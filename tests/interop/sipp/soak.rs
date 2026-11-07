//! Optional wall-clock sessions, concurrent calls and teardown accounting.
//! No test in this module is selected by the ordinary interop runner suites.
use super::{Sipp, SippLimits};
use crate::interop::{
    bounded,
    faults::{Action, Direction, Rule},
    log_dir, sdp, until, Failure, Required, Stack, TestResult,
};
use rsipstack::{
    dialog::{
        invitation::InviteOption,
        invite_dialog::InviteDialog,
        session_timer::{RefreshMethod, SessionTimerConfig},
    },
    sip::{HeadersExt, Method, SipMessage},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

fn parameter(name: &str, default: usize, min: usize, max: usize) -> TestResult<usize> {
    let value = match std::env::var(name) {
        Ok(value) => value.parse::<usize>().required()?,
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => return Err(Failure(error.to_string())),
    };
    check!(
        (min..=max).contains(&value),
        "{name} must be in {min}..={max}"
    );
    Ok(value)
}
async fn rss_kib() -> TestResult<usize> {
    let output = bounded(
        "RSS sample",
        tokio::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output(),
    )
    .await?
    .required()?;
    check!(
        output.status.success(),
        "ps failed while sampling test-process RSS"
    );
    String::from_utf8(output.stdout)
        .required()?
        .trim()
        .parse()
        .required()
}
fn tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn refreshed(
    stack: &Stack,
    dialogs: &[InviteDialog],
    method: &Method,
    cycles: usize,
) -> TestResult<bool> {
    let mut successes: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut acknowledgments: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for packet in stack
        .wire
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
    {
        match &packet.message {
            SipMessage::Response(r)
                if !packet.sent
                    && r.status_code.code() == 200
                    && r.cseq_header().required()?.method().required()? == *method =>
            {
                successes
                    .entry(r.call_id_header().required()?.value().to_owned())
                    .or_default()
                    .insert(r.cseq_header().required()?.seq().required()?);
            }
            SipMessage::Request(r) if packet.sent && r.method == Method::Ack => {
                acknowledgments
                    .entry(r.call_id_header().required()?.value().to_owned())
                    .or_default()
                    .insert(r.cseq_header().required()?.seq().required()?);
            }
            _ => {}
        }
    }
    for dialog in dialogs {
        check!(
            dialog.state().is_confirmed(),
            "call ended before required refresh cycles: {}",
            dialog.id()
        );
        let status = dialog.session_timer_status().required()?;
        check!(
            status.worker_running && status.expirations == 0,
            "timer worker stopped early: {status:?}"
        );
        let required = cycles + usize::from(*method == Method::Invite);
        let id = dialog.id().call_id;
        if status.refreshes < cycles || successes.get(&id).map_or(0, BTreeSet::len) < required {
            return Ok(false);
        }
        if *method == Method::Invite && acknowledgments.get(&id).map_or(0, BTreeSet::len) < required
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn scenario(name: &str, reinvite: bool) -> TestResult {
    let calls = parameter("RSIPSTACK_SOAK_CALLS", 8, 2, 256)?;
    let rounds = parameter("RSIPSTACK_SOAK_ROUNDS", 3, 2, 1000)?;
    let cycles = parameter("RSIPSTACK_SOAK_REFRESHES", 3, 2, 100)?;
    let rss_limit = parameter("RSIPSTACK_SOAK_RSS_GROWTH_MIB", 64, 1, 8192)? * 1024;
    let dir = log_dir(name)?;
    let mut report = File::create(dir.join("soak.csv")).required()?;
    writeln!(report, "round,calls,refreshes_per_call,elapsed_ms,rss_kib,rss_growth_kib,tasks,dialogs,transactions,cached_transactions").required()?;
    std::fs::write(dir.join("config.txt"), format!("calls={calls}\nrounds={rounds}\nrefreshes={cycles}\ninterval=90\nrss_limit_kib={rss_limit}\nfault=drop_one_refresh_200_per_round\n")).required()?;
    let method = if reinvite {
        Method::Invite
    } else {
        Method::Update
    };
    // Initialize subprocess notification machinery before the task baseline.
    rss_kib().await?;
    let baseline_tasks = tasks();
    let mut warm_rss = None;
    let run_start = Instant::now();
    for round in 1..=rounds {
        let batch = dir.join(format!("round-{round:04}"));
        std::fs::create_dir_all(&batch).required()?;
        let stack = Stack::with_faults(
            &batch,
            vec![Rule::new(
                "refresh_response",
                Direction::Receive,
                method.clone(),
                Some(200),
                if reinvite { calls + 1 } else { 1 },
                Action::Drop,
            )],
        )
        .await?;
        stack
            .layer
            .set_session_timer(Some(SessionTimerConfig {
                expires: 90,
                refresh_method: if reinvite {
                    RefreshMethod::Reinvite
                } else {
                    RefreshMethod::Update
                },
                ..Default::default()
            }))
            .required()?;
        let deadline = Duration::from_secs(cycles as u64 * 50 + 30);
        let mut peer = Sipp::start_with_limits(
            if reinvite {
                "soak_invite"
            } else {
                "soak_update"
            },
            "udp",
            &batch,
            &stack.uri,
            &[],
            SippLimits {
                calls,
                timeout_secs: deadline.as_secs() + 30,
                receive_timeout_ms: 100_000,
            },
        )
        .await?;
        let mut dialogs = Vec::with_capacity(calls);
        let mut invites = JoinSet::new();
        for _ in 0..calls {
            let (dialog, invite) = stack
                .layer
                .do_invite_async(
                    InviteOption {
                        caller: stack.uri.clone(),
                        contact: stack.uri.clone(),
                        callee: peer.uri.clone(),
                        offer: Some(sdp()),
                        ..Default::default()
                    },
                    stack.sender.clone(),
                )
                .required()?;
            dialogs.push(dialog);
            invites.spawn(async move { invite.await });
        }
        bounded("parallel call establishment", async {
            while let Some(result) = invites.join_next().await {
                let (_, response) = result.required()?.required()?.required()?;
                check_eq!(response.required()?.status_code.code(), 200);
            }
            Ok::<_, Failure>(())
        })
        .await??;
        println!("round {round}/{rounds}: {calls} active dialogs, waiting for {cycles} real 45-second refresh cycles");
        let started = Instant::now();
        let mut progress = Instant::now();
        loop {
            stack.errors.check()?;
            check!(
                peer.child.try_wait().required()?.is_none(),
                "{}",
                peer.diagnostic("peer exited during soak")
            );
            if refreshed(&stack, &dialogs, &method, cycles)? {
                break;
            }
            check!(
                started.elapsed() < deadline,
                "refresh cycle deadline exceeded"
            );
            if progress.elapsed() >= Duration::from_secs(30) {
                let minimum = dialogs
                    .iter()
                    .filter_map(|d| d.session_timer_status())
                    .map(|s| s.refreshes)
                    .min()
                    .unwrap_or(0);
                println!("round {round}: minimum refreshes={minimum}/{cycles}, live_tasks={}, rss_kib={}", tasks(), rss_kib().await?);
                progress = Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let faults = stack.faults.as_ref().required()?;
        faults.applied("refresh_response").await?;
        faults.check_retransmissions().await?;
        let mut hangups = JoinSet::new();
        for dialog in &dialogs {
            let dialog = dialog.clone();
            hangups.spawn(async move { dialog.bye().await });
        }
        bounded("parallel hangup", async {
            while let Some(result) = hangups.join_next().await {
                result.required()?.required()?;
            }
            Ok::<_, Failure>(())
        })
        .await??;
        peer.finish().await?;
        until("timer workers and dialog registry released", || {
            (stack.layer.is_empty()
                && dialogs
                    .iter()
                    .all(|d| d.session_timer_status().is_some_and(|s| !s.worker_running)))
            .then_some(())
        })
        .await?;
        // Preserve the real SIP absorption windows instead of hiding retained
        // transactions by aborting their tasks or reducing T1/Timer M.
        let drained = tokio::time::timeout(Duration::from_secs(75), async {
            loop {
                let stats = stack.layer.endpoint.get_stats();
                if stats.running_transactions == 0
                    && stats.finished_transactions == 0
                    && stats.waiting_ack == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        let stats = stack.layer.endpoint.get_stats();
        check!(
            drained.is_ok(),
            "transactions not released: running={}, cached={}, waiting_ack={}",
            stats.running_transactions,
            stats.finished_transactions,
            stats.waiting_ack
        );
        stack.finish(&batch, format!("{calls} calls x {cycles} refreshes; dropped response recovered; registry and transactions drained\n")).await?;
        let weak_layer = Arc::downgrade(&stack.layer);
        let weak_endpoint = Arc::downgrade(&stack.layer.endpoint);
        drop(dialogs);
        drop(stack);
        until("endpoint, layer and runtime tasks released", || {
            (weak_layer.strong_count() == 0
                && weak_endpoint.strong_count() == 0
                && tasks() <= baseline_tasks)
                .then_some(())
        })
        .await?;
        let rss = rss_kib().await?;
        let baseline = *warm_rss.get_or_insert(rss);
        let growth = rss.saturating_sub(baseline);
        writeln!(
            report,
            "{round},{calls},{cycles},{},{rss},{growth},{},0,0,0",
            run_start.elapsed().as_millis(),
            tasks()
        )
        .required()?;
        report.flush().required()?;
        println!(
            "round {round} drained: tasks={}, rss={} KiB, growth={} KiB",
            tasks(),
            rss,
            growth
        );
        check!(growth <= rss_limit, "RSS growth {growth} KiB exceeds configured {rss_limit} KiB after warmup; inspect soak.csv and use a heap profiler to diagnose");
    }
    std::fs::write(
        dir.join("PASS"),
        format!(
            "{rounds} rounds, {calls} concurrent calls, {cycles} refreshes per call; elapsed={}s\n",
            run_start.elapsed().as_secs()
        ),
    )
    .required()
}

#[tokio::test]
#[ignore = "long wall-clock test; use scripts/interop/run-soak.sh update"]
async fn udp_session_soak_update() -> TestResult {
    scenario("udp_session_soak_update", false).await
}
#[tokio::test]
#[ignore = "long wall-clock test; use scripts/interop/run-soak.sh reinvite"]
async fn udp_session_soak_reinvite() -> TestResult {
    scenario("udp_session_soak_reinvite", true).await
}
