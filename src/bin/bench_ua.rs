use clap::Parser;
use futures::future::{self, Future};
use rsipstack::dialog::dialog::{
    Dialog, DialogState, DialogStateReceiver, DialogStateSender, TerminatedReason,
};
use rsipstack::dialog::dialog_layer::DialogLayer;
use rsipstack::dialog::invitation::InviteOption;
use rsipstack::dialog::DialogId;
use rsipstack::Result;
use rsipstack::{
    dialog::authenticate::Credential,
    transaction::TransactionReceiver,
    transport::{udp::UdpConnection, TransportLayer},
    EndpointBuilder, Error,
};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "SIP Benchmark User Agent for testing")]
struct Args {
    /// Mode: "server" (receive calls) or "client" (make calls)
    #[arg(short, long, default_value = "server")]
    mode: String,

    /// Local port to bind
    #[arg(short, long, default_value = "5060")]
    port: u16,

    /// Remote SIP server address (required for client mode, e.g., sip:server.com or server.com:5060)
    #[arg(short, long)]
    server: Option<String>,

    /// Number of concurrent calls to maintain (client mode only)
    #[arg(short, long, default_value = "10")]
    calls: u32,

    /// Call answer probability in percentage (server mode only)
    #[arg(short, long, default_value = "100")]
    answer: u8,
}

#[derive(Debug, Clone)]
struct Stats {
    total_calls: Arc<AtomicU64>,
    reject_calls: Arc<AtomicU64>,
    failed_calls: Arc<AtomicU64>,
    active_calls: Arc<Mutex<HashMap<DialogId, Instant>>>,
    calls_per_second: Arc<AtomicU64>,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_calls: Arc::new(AtomicU64::new(0)),
            reject_calls: Arc::new(AtomicU64::new(0)),
            failed_calls: Arc::new(AtomicU64::new(0)),
            active_calls: Arc::new(Mutex::new(HashMap::new())),
            calls_per_second: Arc::new(AtomicU64::new(0)),
        }
    }
}

async fn run_server(
    dialog_layer: Arc<DialogLayer>,
    mut incoming: TransactionReceiver,
    state_sender: DialogStateSender,
    contact: rsip::Uri,
    answer_prob: u8,
    stats: Stats,
) -> Result<()> {
    info!(answer_prob = %answer_prob, "Starting server mode");

    loop {
        while let Some(mut tx) = incoming.recv().await {
            match tx.original.method {
                rsip::Method::Invite => {
                    stats.total_calls.fetch_add(1, Ordering::Relaxed);
                    let should_answer = rand::random_range(0..=99) < answer_prob as u64;
                    if !should_answer {
                        stats.reject_calls.fetch_add(1, Ordering::Relaxed);
                        tx.reply(rsip::StatusCode::BusyHere).await.ok();
                        continue;
                    }
                    let mut dialog = dialog_layer
                        .get_or_create_server_invite(
                            &tx,
                            state_sender.clone(),
                            None,
                            Some(contact.clone()),
                        )
                        .unwrap();

                    tokio::spawn(async move {
                        dialog.handle(&mut tx).await.ok();
                    });
                }
                rsip::Method::Bye => {
                    if let Ok(dialog_id) = DialogId::try_from(&tx) {
                        stats.active_calls.lock().unwrap().remove(&dialog_id);
                        tx.reply(rsip::StatusCode::OK).await.ok();
                        dialog_layer.remove_dialog(&dialog_id);
                    }
                }
                _ => {}
            }
        }
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

async fn run_client(
    dialog_layer: Arc<DialogLayer>,
    contact: rsip::Uri,
    credential: Option<Credential>,
    concurrent_calls: u32,
    state_sender: DialogStateSender,
    stats: Stats,
) -> Result<()> {
    info!(concurrent_calls = %concurrent_calls, "Starting client mode");

    // Use a rate limiter to ensure stable call creation
    let max_calls_per_cycle = 100; // Increased to 20 (was 5)
    let cycle_duration = Duration::from_millis(10); // Reduced to 50ms (was 100ms)

    loop {
        let start_time = Instant::now();

        // Calculate how many calls we need to create to maintain target concurrency
        let calls_to_create;
        {
            let dialogs = stats.active_calls.lock().unwrap();
            calls_to_create =
                concurrent_calls as usize - dialogs.len().min(concurrent_calls as usize);
        }
        let calls_to_create_now = calls_to_create.min(max_calls_per_cycle);

        // Create new calls if needed
        if calls_to_create_now > 0 {
            info!(creating = %calls_to_create_now, concurrent = %concurrent_calls, "Creating new calls to maintain concurrency");

            // Prepare call creation futures
            for _ in 0..calls_to_create_now {
                let dialog_layer = dialog_layer.clone();
                let contact = contact.clone();
                let credential = credential.clone();
                let state_sender = state_sender.clone();
                let stats = stats.clone();

                let invite_loop = async move {
                    let invite_option = InviteOption {
                        callee: contact.clone(),
                        caller: contact.clone(),
                        contact,
                        credential,
                        ..Default::default()
                    };
                    stats.total_calls.fetch_add(1, Ordering::Relaxed);

                    match dialog_layer.do_invite(invite_option, state_sender).await {
                        Ok((dialog, _)) => {
                            // Update total call count

                            // Get dialog ID and add to active calls tracking
                            let dialog_id = dialog.id();
                            stats
                                .active_calls
                                .lock()
                                .unwrap()
                                .insert(dialog_id.clone(), Instant::now());

                            // Return the dialog for call management
                            Some((dialog_id, dialog))
                        }
                        Err(_) => None,
                    }
                };
                tokio::spawn(async move {
                    let dialog = match invite_loop.await {
                        Some((_, dialog)) => dialog,
                        None => return,
                    };
                    let duration = Duration::from_secs(rand::random_range(3..=10));
                    sleep(duration).await;
                    dialog.bye().await.ok();
                });
            }
        }

        // Sleep for the remainder of the cycle to maintain a consistent pace
        let elapsed = start_time.elapsed();
        if elapsed < cycle_duration {
            sleep(cycle_duration - elapsed).await;
        }
    }
}

async fn update_stats(dialog_layer: Arc<DialogLayer>, stats: Stats) {
    let mut last_total = stats.total_calls.load(Ordering::SeqCst);
    let mut last_time = Instant::now();

    loop {
        sleep(Duration::from_secs(1)).await;
        let current_total = stats.total_calls.load(Ordering::Relaxed);
        let current_time = Instant::now();
        let elapsed = current_time.duration_since(last_time).as_secs();

        if elapsed > 0 {
            let cps = (current_total - last_total) / elapsed;
            stats.calls_per_second.store(cps, Ordering::Relaxed);
            last_total = current_total;
            last_time = current_time;
        }

        // Print stats
        println!("\x1B[2J\x1B[1;1H"); // Clear screen and move cursor to top
        println!("=== SIP Benchmark UA Stats ===");

        // Get active calls count from the HashMap
        let active_calls_count = stats.active_calls.lock().unwrap().len();
        println!("Dialogs: {}", dialog_layer.len());
        println!("Active Calls: {}", active_calls_count);
        println!(
            "Rejected Calls: {}",
            stats.reject_calls.load(Ordering::Relaxed)
        );
        println!(
            "Failed Calls: {}",
            stats.failed_calls.load(Ordering::Relaxed)
        );
        println!("Total Calls: {}", stats.total_calls.load(Ordering::Relaxed));
        println!(
            "Calls/Second: {}",
            stats.calls_per_second.load(Ordering::Relaxed)
        );
        println!("============================");
    }
}

async fn process_dialog_state(
    dialog_layer: Arc<DialogLayer>,
    mut state_receiver: DialogStateReceiver,
    stats: Stats,
) -> Result<()> {
    while let Some(state) = state_receiver.recv().await {
        match state {
            DialogState::Calling(id) => match dialog_layer.get_dialog(&id) {
                Some(dialog) => match dialog {
                    Dialog::ServerInvite(dialog) => {
                        dialog.accept(None, None).ok();
                    }
                    _ => {}
                },
                None => {}
            },
            DialogState::Confirmed(id, _) => {
                stats
                    .active_calls
                    .lock()
                    .unwrap()
                    .insert(id, Instant::now());
            }
            DialogState::Terminated(id, status) => {
                match status {
                    TerminatedReason::UacOther(status) => {
                        info!(id = %id, status = %status, "dialog terminated");
                    }
                    TerminatedReason::UasOther(status) => {
                        info!(id = %id, status = %status, "dialog terminated");
                    }
                    _ => {}
                }
                dialog_layer.remove_dialog(&id);
                // Remove from active calls tracking
                stats.active_calls.lock().unwrap().remove(&id);
            }
            _ => {
                debug!(state = %state, "Dialog state update");
            }
        }
    }
    Ok(())
}

fn parse_server_uri(server: &str) -> Result<rsip::Uri> {
    // If the server string doesn't start with "sip:", add it
    let server_str = if !server.starts_with("sip:") {
        format!("sip:{}", server)
    } else {
        server.to_string()
    };

    // Parse the URI
    let uri = rsip::Uri::try_from(server_str.as_str())
        .map_err(|e| Error::Error(format!("Invalid server URI: {}", e)))?;

    // If no port is specified, use default SIP port
    if uri.host_with_port.port.is_none() {
        let mut uri = uri;
        uri.host_with_port.port = Some(5060.into());
        Ok(uri)
    } else {
        Ok(uri)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_file(true)
        .with_line_number(true)
        .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
        .try_init()
        .ok();

    let args = Args::parse();

    // Validate arguments
    if args.mode == "client" && args.server.is_none() {
        return Err(Error::Error(
            "Server address is required in client mode".to_string(),
        ));
    }

    if args.answer > 100 {
        return Err(Error::Error(
            "Probability must be between 0 and 100".to_string(),
        ));
    }

    let token = CancellationToken::new();
    let transport_layer = TransportLayer::new(token.clone());

    // Setup UDP connection
    let addr = format!("0.0.0.0:{}", args.port);
    let connection =
        UdpConnection::create_connection(addr.parse()?, None, Some(token.child_token())).await?;
    transport_layer.add_transport(connection.into());

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(token.clone())
        .with_transport_layer(transport_layer)
        .build();

    let first_addr = endpoint
        .get_addrs()
        .first()
        .ok_or(Error::Error("no address found".to_string()))?
        .clone();

    let contact = rsip::Uri {
        scheme: Some(rsip::Scheme::Sip),
        auth: None,
        host_with_port: first_addr.addr.into(),
        params: vec![],
        headers: vec![],
    };

    let incoming = endpoint.incoming_transactions()?;
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let (state_sender, state_receiver) = dialog_layer.new_dialog_state_channel();
    let stats = Stats::new();

    let mode_handler: BoxFuture<Result<()>> = match args.mode.as_str() {
        "server" => Box::pin(run_server(
            dialog_layer.clone(),
            incoming,
            state_sender.clone(),
            contact,
            args.answer,
            stats.clone(),
        )),
        "client" => {
            let server_uri = parse_server_uri(args.server.as_ref().unwrap())?;
            Box::pin(run_client(
                dialog_layer.clone(),
                server_uri,
                None,
                args.calls,
                state_sender.clone(),
                stats.clone(),
            ))
        }
        _ => Box::pin(future::err(Error::Error(
            "Invalid mode. Use 'server' or 'client'".to_string(),
        ))),
    };

    select! {
        _ = endpoint.serve() => {
            info!("Endpoint finished");
        }
        r = mode_handler => {
            info!(result = ?r, "Mode handler finished");
        }
        r = process_dialog_state(dialog_layer.clone(), state_receiver, stats.clone()) => {
            info!(result = ?r, "Dialog state handler finished");
        }
        _ = update_stats(dialog_layer.clone(),stats) => {
            info!("Stats updater finished");
        }
    }

    Ok(())
}
