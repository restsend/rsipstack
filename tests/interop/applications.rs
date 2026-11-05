//! Three real processes: two independent SIP peers and a standalone rsipstack app.
use super::{bounded, free_addr, log_dir, until_result, Packet, Peer, Required, TestResult};
use rsipstack::sip::{prelude::HeadersExt, Header, Method, Request, Response, SipMessage, Uri};
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
};

#[derive(Clone, Copy)]
pub enum Outcome {
    CallerBye,
    CalleeBye,
    Busy,
    Cancel,
}

pub struct Program {
    child: Child,
    pub uri: Uri,
    dir: PathBuf,
    mode: String,
}

impl Program {
    pub async fn start(mode: &str, transport: &str, target: &Uri, dir: &Path) -> TestResult<Self> {
        std::fs::create_dir_all(dir).required()?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let binary = std::env::var_os(format!("INTEROP_{}_BIN", mode.to_uppercase()))
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join(format!("target/debug/examples/interop_{mode}")));
        check!(
            binary.is_file(),
            "Missing {}; run scripts/interop/run.sh {mode}",
            binary.display()
        );
        let addr = free_addr(transport)?;
        let uri = format!("sip:interop@{addr};transport={transport}")
            .parse()
            .required()?;
        let child = Command::new(binary)
            .args([
                "--listen",
                &addr.to_string(),
                "--transport",
                transport,
                "--target",
                &target.to_string(),
                "--log-dir",
            ])
            .arg(dir)
            .stdin(Stdio::piped())
            .stdout(File::create(dir.join("stdout.log")).required()?)
            .stderr(File::create(dir.join("stderr.log")).required()?)
            .kill_on_drop(true)
            .spawn()
            .required()?;
        let mut app = Self {
            child,
            uri,
            dir: dir.to_owned(),
            mode: mode.to_owned(),
        };
        app.marker("stdout.log", "READY ").await?;
        Ok(app)
    }

    pub async fn marker(&mut self, file: &str, marker: &str) -> TestResult {
        until_result(marker, || {
            let text = match std::fs::read_to_string(self.dir.join(file)) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(error) => return Err(super::Failure(error.to_string())),
            };
            if text.contains(marker) {
                return Ok(Some(()));
            }
            check!(
                self.child.try_wait().required()?.is_none(),
                "Application exited: {}",
                self.diagnostic()
            );
            Ok(None)
        })
        .await
        .map_err(|e| super::Failure(format!("{e}\n{}", self.diagnostic())))
    }

    fn diagnostic(&self) -> String {
        ["stderr.log", "events.log"]
            .iter()
            .map(|name| {
                format!(
                    "{name}:\n{}",
                    std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub async fn finish(mut self) -> TestResult<Vec<Packet>> {
        self.marker("events.log", "ENDED ").await?;
        // A rejected INVITE ends the call before its hop-by-hop ACKs arrive.
        // Keep the process alive until both sides have actually exchanged ACK.
        until_result("application ACKs on both legs", || {
            let packets = read_frames(&self.dir.join("sip.frames"), true)?;
            let received = request(&packets, false, Method::Ack).is_ok();
            let sent = request(&packets, true, Method::Ack).is_ok();
            Ok((received && sent).then_some(()))
        })
        .await?;
        let stdin = self.child.stdin.as_mut().required()?;
        stdin.write_all(b"quit\n").await.required()?;
        stdin.flush().await.required()?;
        let status = bounded("interop application shutdown", self.child.wait())
            .await?
            .required()?;
        check!(
            status.success(),
            "Application failed ({status}): {}",
            self.diagnostic()
        );
        check_eq!(
            std::fs::read_to_string(self.dir.join("summary.txt")).required()?,
            "active_calls=0\ndialogs=0\nbackground_errors=0\n"
        );
        let events = std::fs::read_to_string(self.dir.join("events.log")).required()?;
        check_eq!(
            events.lines().filter(|s| s.starts_with("ENDED ")).count(),
            1
        );
        if self.mode == "b2bua" {
            let bridges: Vec<_> = events
                .lines()
                .filter(|s| s.starts_with("BRIDGE "))
                .collect();
            check_eq!(bridges.len(), 1);
            let ids: Vec<_> = bridges[0].split_whitespace().skip(1).collect();
            check_eq!(ids.len(), 2);
            for id in ids {
                check_eq!(
                    events
                        .lines()
                        .filter(|s| s.starts_with("STATE Terminated(") && s.contains(id))
                        .count(),
                    1,
                    "Each B2BUA leg must terminate exactly once"
                );
            }
        } else {
            check_eq!(events.lines().filter(|s| s.starts_with("CALL ")).count(), 1);
        }
        read_frames(&self.dir.join("sip.frames"), false)
    }
}

fn read_frames(path: &Path, allow_partial: bool) -> TestResult<Vec<Packet>> {
    let bytes = std::fs::read(path).required()?;
    let mut rest = bytes.as_slice();
    let mut packets = Vec::new();
    while !rest.is_empty() {
        let split = rest.iter().position(|b| *b == b'\n');
        if allow_partial && split.is_none() {
            break;
        }
        let split = split.required()?;
        let head = std::str::from_utf8(&rest[..split]).required()?;
        let (direction, length) = head.split_once(' ').required()?;
        check!(matches!(direction, "TX" | "RX"), "Invalid frame direction");
        let length: usize = length.parse().required()?;
        rest = &rest[split + 1..];
        if allow_partial && rest.len() <= length {
            break;
        }
        check!(
            rest.len() > length && rest[length] == b'\n',
            "Truncated SIP frame"
        );
        let raw = std::str::from_utf8(&rest[..length]).required()?;
        packets.push(Packet {
            sent: direction == "TX",
            message: SipMessage::try_from(raw).required()?,
        });
        rest = &rest[length + 1..];
    }
    Ok(packets)
}

fn request(packets: &[Packet], sent: bool, method: Method) -> TestResult<&Request> {
    packets
        .iter()
        .find_map(|p| match &p.message {
            SipMessage::Request(r) if p.sent == sent && r.method == method => Some(r),
            _ => None,
        })
        .required()
}

fn response(packets: &[Packet], sent: bool, method: Method, code: u16) -> TestResult<&Response> {
    for p in packets {
        if let SipMessage::Response(r) = &p.message {
            if p.sent == sent
                && r.status_code.code() == code
                && r.cseq_header().required()?.method().required()? == method
            {
                return Ok(r);
            }
        }
    }
    Err(super::Failure(format!(
        "Missing {} {code} {method}",
        if sent { "TX" } else { "RX" }
    )))
}

fn ack_matches(ack: &Request, invite: &Request, final_response: &Response) -> TestResult {
    check_eq!(
        ack.call_id_header().required()?,
        invite.call_id_header().required()?
    );
    check_eq!(
        ack.cseq_header().required()?.seq().required()?,
        invite.cseq_header().required()?.seq().required()?
    );
    check_eq!(
        ack.from_header().required()?.tag().required()?,
        invite.from_header().required()?.tag().required()?
    );
    check_eq!(
        ack.to_header().required()?.tag().required()?,
        final_response.to_header().required()?.tag().required()?
    );
    Ok(())
}

pub fn verify(
    packets: &[Packet],
    mode: &str,
    code_a: u16,
    code_b: u16,
    established: bool,
    cancelled: bool,
) -> TestResult {
    let a = request(packets, false, Method::Invite)?;
    let b = request(packets, true, Method::Invite)?;
    let final_a = response(packets, true, Method::Invite, code_a)?;
    let final_b = response(packets, false, Method::Invite, code_b)?;
    check_eq!(
        a.body,
        b.body,
        "The offer must cross the application unchanged"
    );
    if mode == "proxy" {
        check_eq!(
            a.call_id_header().required()?,
            b.call_id_header().required()?
        );
        check_eq!(a.from_header().required()?, b.from_header().required()?);
        check_eq!(a.to_header().required()?, b.to_header().required()?);
        check_eq!(a.cseq_header().required()?, b.cseq_header().required()?);
        check_eq!(
            a.contact_header().required()?,
            b.contact_header().required()?
        );
        check_eq!(
            b.headers
                .iter()
                .filter(|h| matches!(h, Header::Via(_)))
                .count(),
            2
        );
        check!(b
            .headers
            .iter()
            .any(|h| matches!(h, Header::RecordRoute(_))));
        check_eq!(
            b.max_forwards_header()
                .required()?
                .value()
                .parse::<u32>()
                .required()?
                + 1,
            a.max_forwards_header()
                .required()?
                .value()
                .parse::<u32>()
                .required()?
        );
        check_eq!(
            final_a.to_header().required()?,
            final_b.to_header().required()?
        );
    } else {
        check!(
            a.call_id_header().required()? != b.call_id_header().required()?,
            "This B2BUA creates independent Call-IDs"
        );
        check!(
            a.from_header().required()?.tag().required()?
                != b.from_header().required()?.tag().required()?
        );
        check_eq!(
            b.headers
                .iter()
                .filter(|h| matches!(h, Header::Via(_)))
                .count(),
            1
        );
        check!(!b
            .headers
            .iter()
            .any(|h| matches!(h, Header::RecordRoute(_))));
        check!(a.contact_header().required()? != b.contact_header().required()?);
    }
    ack_matches(request(packets, false, Method::Ack)?, a, final_a)?;
    ack_matches(request(packets, true, Method::Ack)?, b, final_b)?;
    if established {
        check!(!final_a.body.is_empty());
        check_eq!(
            final_a.body,
            final_b.body,
            "The answer must cross the application unchanged"
        );
        for sent in [false, true] {
            let bye = request(packets, sent, Method::Bye)?;
            let ok = response(packets, !sent, Method::Bye, 200)?;
            check_eq!(
                bye.call_id_header().required()?,
                ok.call_id_header().required()?
            );
            check_eq!(bye.cseq_header().required()?, ok.cseq_header().required()?);
            // PJSIP's URI printer omits transport/port in From/To by default.
            // Correlate the dialog tags, not the rendered header text.
            check_eq!(
                bye.from_header().required()?.tag().required()?,
                ok.from_header().required()?.tag().required()?
            );
            check_eq!(
                bye.to_header().required()?.tag().required()?,
                ok.to_header().required()?.tag().required()?
            );
            let (invite, answer) =
                if bye.call_id_header().required()? == a.call_id_header().required()? {
                    (a, final_a)
                } else {
                    check_eq!(
                        bye.call_id_header().required()?,
                        b.call_id_header().required()?
                    );
                    (b, final_b)
                };
            let from = bye.from_header().required()?.tag().required()?;
            let to = bye.to_header().required()?.tag().required()?;
            let caller = invite.from_header().required()?.tag().required()?;
            let callee = answer.to_header().required()?.tag().required()?;
            check!(
                (from == caller && to == callee) || (from == callee && to == caller),
                "BYE must belong to the established dialog"
            );
        }
    } else if code_b >= 300 {
        check!(!packets
            .iter()
            .any(|p| matches!(&p.message, SipMessage::Request(r) if r.method == Method::Bye)));
    }
    if cancelled {
        for (sent, invite) in [(false, a), (true, b)] {
            let cancel = request(packets, sent, Method::Cancel)?;
            check_eq!(
                cancel.call_id_header().required()?,
                invite.call_id_header().required()?
            );
            check_eq!(
                cancel.cseq_header().required()?.seq().required()?,
                invite.cseq_header().required()?.seq().required()?
            );
            response(packets, !sent, Method::Cancel, 200)?;
        }
    }
    Ok(())
}

pub async fn scenario(mode: &str, name: &str, transport: &str, outcome: Outcome) -> TestResult {
    let dir = log_dir(&format!("{mode}_{name}"))?;
    for peer in ["caller", "callee"] {
        std::fs::create_dir_all(dir.join(peer)).required()?;
    }
    let mut callee = Peer::start(transport, &dir.join("callee")).await?;
    let app = Program::start(mode, transport, &callee.uri, &dir.join("application")).await?;
    let mut caller = Peer::start(transport, &dir.join("caller")).await?;
    caller.command(&format!("m\n{}\n", app.uri)).await?;
    callee.wait_text("state changed to EARLY").await?;
    caller.wait_text("state changed to EARLY").await?;
    let established = matches!(outcome, Outcome::CallerBye | Outcome::CalleeBye);
    match outcome {
        Outcome::CallerBye | Outcome::CalleeBye => {
            callee.command("a\n200\n").await?;
            caller.wait_text("state changed to CONFIRMED").await?;
            callee.wait_text("state changed to CONFIRMED").await?;
            if matches!(outcome, Outcome::CallerBye) {
                caller.command("h\n").await?;
            } else {
                callee.command("h\n").await?;
            }
        }
        Outcome::Busy => callee.command("a\n486\n").await?,
        Outcome::Cancel => caller.command("h\n").await?,
    }
    caller.wait_text("is DISCONNECTED").await?;
    callee.wait_text("is DISCONNECTED").await?;
    match outcome {
        Outcome::CallerBye => caller.wait_text("Response msg 200/BYE").await?,
        Outcome::CalleeBye => callee.wait_text("Response msg 200/BYE").await?,
        // Require receipt of the non-2xx ACK before stopping the application.
        Outcome::Busy | Outcome::Cancel => callee.wait_text("Request msg ACK").await?,
    }
    let packets = app.finish().await?;
    caller.stop().await?;
    callee.stop().await?;
    let code = match outcome {
        Outcome::Busy => 486,
        Outcome::Cancel => 487,
        _ => 200,
    };
    verify(
        &packets,
        mode,
        code,
        code,
        established,
        matches!(outcome, Outcome::Cancel),
    )?;
    std::fs::write(
        dir.join("PASS"),
        format!("{mode}: two independent PJSUA peers, {transport}\n"),
    )
    .required()
}

pub async fn late_200(mode: &str, name: &str, transport: &str) -> TestResult {
    let dir = log_dir(&format!("{mode}_{name}"))?;
    for peer in ["caller", "callee"] {
        std::fs::create_dir_all(dir.join(peer)).required()?;
    }
    let unused: Uri = "sip:unused@127.0.0.1:9".parse().required()?;
    let callee = super::sipp::Sipp::start(
        "application_late_200",
        transport,
        &dir.join("callee"),
        &unused,
    )
    .await?;
    let app = Program::start(mode, transport, &callee.uri, &dir.join("application")).await?;
    let mut caller = Peer::start(transport, &dir.join("caller")).await?;
    caller.command(&format!("m\n{}\n", app.uri)).await?;
    caller.wait_text("state changed to EARLY").await?;
    caller.command("h\n").await?;
    caller.wait_text("is DISCONNECTED").await?;
    // SIPp sends the INVITE 200 only after observing CANCEL and requires ACK/BYE.
    callee.finish().await?;
    if mode == "proxy" {
        caller.wait_text("Response msg 200/BYE").await?;
    }
    let packets = app.finish().await?;
    caller.stop().await?;
    let code_a = if mode == "proxy" { 200 } else { 487 };
    verify(&packets, mode, code_a, 200, false, true)?;
    let b = request(&packets, true, Method::Invite)?;
    let bye = request(&packets, true, Method::Bye)?;
    check_eq!(
        bye.call_id_header().required()?,
        b.call_id_header().required()?
    );
    response(&packets, false, Method::Bye, 200)?;
    if mode == "b2bua" {
        check!(
            !packets.iter().any(|p| !p.sent
                && matches!(&p.message, SipMessage::Request(r) if r.method == Method::Bye)),
            "The cancelled caller leg must end with 487, without BYE"
        );
    } else {
        request(&packets, false, Method::Bye)?;
        response(&packets, true, Method::Bye, 200)?;
    }
    std::fs::write(
        dir.join("PASS"),
        format!("{mode}: CANCEL followed by a late downstream 200, {transport}\n"),
    )
    .required()
}

pub async fn lost_bye_response(mode: &str, name: &str) -> TestResult {
    let dir = log_dir(&format!("{mode}_{name}"))?;
    for peer in ["caller", "callee"] {
        std::fs::create_dir_all(dir.join(peer)).required()?;
    }
    let unused: Uri = "sip:unused@127.0.0.1:9".parse().required()?;
    let callee = super::sipp::Sipp::start(
        "application_lost_bye_response",
        "udp",
        &dir.join("callee"),
        &unused,
    )
    .await?;
    let app = Program::start(mode, "udp", &callee.uri, &dir.join("application")).await?;
    let mut caller = Peer::start("udp", &dir.join("caller")).await?;
    caller.command(&format!("m\n{}\n", app.uri)).await?;
    caller.wait_text("state changed to CONFIRMED").await?;
    caller.command("h\n").await?;
    callee.finish().await?;
    caller.wait_text("Response msg 200/BYE").await?;
    let packets = app.finish().await?;
    caller.stop().await?;
    verify(&packets, mode, 200, 200, true, false)?;
    std::fs::write(
        dir.join("PASS"),
        format!("{mode}: SIPp required the same UDP BYE transaction twice\n"),
    )
    .required()
}
