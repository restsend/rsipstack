use clap::Parser;
use play_file::{build_rtp_conn, play_audio_file};
use rsip::prelude::HeadersExt;
use rsip::typed::MediaType;
use rsipstack::dialog::dialog::{Dialog, DialogState, DialogStateReceiver, DialogStateSender};
use rsipstack::dialog::dialog_layer::DialogLayer;
use rsipstack::dialog::invitation::InviteOption;
use rsipstack::dialog::server_dialog::ServerInviteDialog;
use rsipstack::transaction::endpoint::EndpointInnerRef;
use rsipstack::Result;
use rsipstack::{
    dialog::{authenticate::Credential, registration::Registration},
    transaction::TransactionReceiver,
    transport::{udp::UdpConnection, TransportLayer},
    EndpointBuilder, Error,
};
use std::net::{IpAddr, SocketAddr};
use std::{env, sync::Arc, time::Duration};
use tokio::time::timeout;
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::play_file::play_echo;
mod play_file;
#[derive(Debug, Clone)]
struct MediaSessionOption {
    pub random_reject: u32,
    pub auto_answer: bool,
    pub cancel_token: CancellationToken,
    pub external_ip: Option<IpAddr>,
    pub rtp_start_port: u16,
    pub echo: bool,
}

/// A SIP client example that sends a REGISTER request to a SIP server.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// SIP port
    #[arg(long, default_value = "25060")]
    port: u16,

    /// SIP port
    #[arg(long, default_value = "32000")]
    rtp_start_port: u16,

    #[arg(long, default_value = "false")]
    echo: bool,

    /// External IP address
    #[arg(long)]
    external_ip: Option<IpAddr>,

    /// SIP server address
    #[arg(long)]
    sip_server: Option<String>,

    /// SIP user
    #[arg(long)]
    user: Option<String>,

    /// SIP password
    #[arg(long)]
    password: Option<String>,

    #[arg(long)]
    call: Option<String>,

    #[arg(long)]
    reject: bool,

    #[arg(long)]
    auto_answer: bool,
    #[arg(long, default_value = "0")]
    random_reject: u32,
}

async fn handle_user_input(
    cancel_token: CancellationToken,
    answer_sender: tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    loop {
        select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(input)) => {
                        let input = input.trim().to_lowercase();
                        if input == "q" {
                            info!("User requested to hang up");
                            cancel_token.cancel();
                            info!("Cancelled all dialogs");
                            break;
                        } else if input == "a" || input == "r" {
                            answer_sender.send(input.to_string()).expect("send answer");
                        }
                    },
                    Ok(None) => {
                        // EOF reached
                        break;
                    },
                    Err(e) => {
                        info!(error = ?e, "Error reading input");
                        break;
                    }
                }
            },
            _ = cancel_token.cancelled() => {
                info!("User input handler cancelled");
                break;
            }
        }
    }
    Ok(())
}
pub fn get_first_non_loopback_interface() -> Result<IpAddr> {
    for i in get_if_addrs::get_if_addrs()? {
        if !i.is_loopback() {
            match i.addr {
                get_if_addrs::IfAddr::V4(ref addr) => return Ok(std::net::IpAddr::V4(addr.ip)),
                _ => continue,
            }
        }
    }
    Err(Error::Error("No IPV4 interface found".to_string()))
}
// A sip client example, that sends a REGISTER request to a sip server.
#[tokio::main]
async fn main() -> rsipstack::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
        .try_init()
        .ok();

    if let Err(e) = dotenv::dotenv() {
        info!(error = %e, "Failed to load .env file");
    }

    let args = Args::parse();

    info!("Starting SIP client");

    let mut sip_server = args
        .sip_server
        .unwrap_or(env::var("SIP_SERVER").unwrap_or_default());

    if !sip_server.starts_with("sip:") && !sip_server.starts_with("sips:") {
        sip_server = format!("sip:{}", sip_server);
    }

    let sip_server = rsip::Uri::try_from(sip_server).ok();
    let sip_username = args
        .user
        .unwrap_or(env::var("SIP_USERNAME").unwrap_or_default());
    let sip_password = args
        .password
        .unwrap_or(env::var("SIP_PASSWORD").unwrap_or_default());

    let token = CancellationToken::new();
    let opt = MediaSessionOption {
        cancel_token: token.clone(),
        external_ip: args.external_ip.clone(),
        rtp_start_port: args.rtp_start_port,
        echo: args.echo,
        auto_answer: args.auto_answer,
        random_reject: args.random_reject,
    };

    let transport_layer = TransportLayer::new(token.clone());

    let external_ip = args
        .external_ip
        .or_else(|| env::var("EXTERNAL_IP").ok().and_then(|s| s.parse().ok()));

    let external = external_ip.map(|ip| SocketAddr::new(ip, args.port));

    let addr = get_first_non_loopback_interface().expect("get first non loopback interface");
    let connection = UdpConnection::create_connection(
        format!("{}:{}", addr, args.port).parse()?,
        external.clone(),
        Some(token.child_token()),
    )
    .await?;

    transport_layer.add_transport(connection.into());

    let endpoint = EndpointBuilder::new()
        .with_cancel_token(token.clone())
        .with_transport_layer(transport_layer)
        .build();

    let credential = Credential {
        username: sip_username.clone(),
        password: sip_password,
        realm: None,
    };

    let incoming = endpoint.incoming_transactions()?;
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));

    let (state_sender, state_receiver) = dialog_layer.new_dialog_state_channel();

    let first_addr = endpoint
        .get_addrs()
        .first()
        .ok_or(crate::Error::Error("no address found".to_string()))?
        .clone();

    let contact = rsip::Uri {
        scheme: Some(rsip::Scheme::Sip),
        auth: Some(rsip::Auth {
            user: sip_username,
            password: None,
        }),
        host_with_port: first_addr.addr.into(),
        params: vec![],
        headers: vec![],
    };

    select! {
        _ = endpoint.serve() => {
            info!("user agent finished");
        }
        r = process_registration(endpoint.inner.clone(), sip_server, credential.clone(), token.clone()) => {
            info!(result = ?r, "register loop finished");
        }
        r = process_incoming_request(dialog_layer.clone(), incoming, state_sender.clone(), contact.clone(), args.reject) => {
            info!(result = ?r, "serve loop finished");
        }
        r = process_dialog(dialog_layer.clone(), state_receiver, opt.clone()) => {
            info!(result = ?r, "dialog loop finished");
        }
        r = async {
            if let Some(callee) = args.call.clone() {
                let invite_option = InviteOption {
                    callee: callee.try_into().expect("callee"),
                    caller: contact.clone(),
                    contact: contact.clone(),
                    credential: Some(credential.clone()),
                    ..Default::default()
                };

                match make_call(dialog_layer, invite_option, opt, state_sender).await {
                    Ok(_) => info!("Call finished"),
                    Err(e) => info!(error = ?e, "Failed to make call"),
                }
            }
            select! {
                _ = token.cancelled() => {
                    info!("token cancelled")
                }
            }
        } => {
            info!(result = ?r, "dialog loop finished");
        }
    }
    Ok(())
}

async fn process_registration(
    endpoint: EndpointInnerRef,
    sip_server: Option<rsip::Uri>,
    credential: Credential,
    cancel_token: CancellationToken,
) -> Result<()> {
    let sip_server = match sip_server {
        Some(uri) => uri,
        None => {
            cancel_token.cancelled().await;
            return Ok(());
        }
    };

    let mut registration = Registration::new(endpoint, Some(credential));
    loop {
        let resp = registration.register(sip_server.clone(), None).await?;
        debug!("received response: {}", resp.to_string());
        if resp.status_code != rsip::StatusCode::OK {
            return Err(rsipstack::Error::Error("Failed to register".to_string()));
        }
        sleep(Duration::from_secs(registration.expires().max(50) as u64)).await;
    }
}

async fn process_incoming_request(
    dialog_layer: Arc<DialogLayer>,
    mut incoming: TransactionReceiver,
    state_sender: DialogStateSender,
    contact: rsip::Uri,
    reject: bool,
) -> Result<()> {
    while let Some(mut tx) = incoming.recv().await {
        info!("Received transaction: {:?}", tx.key);

        match tx.original.to_header()?.tag()?.as_ref() {
            Some(_) => match dialog_layer.match_dialog(&tx) {
                Some(mut d) => {
                    tokio::spawn(async move {
                        d.handle(&mut tx).await?;
                        Ok::<_, Error>(())
                    });
                    continue;
                }
                None => {
                    info!("dialog not found: {}", tx.original);
                    tx.reply(rsip::StatusCode::CallTransactionDoesNotExist)
                        .await?;
                    continue;
                }
            },
            None => {}
        }
        // out dialog, new server dialog
        match tx.original.method {
            rsip::Method::Invite | rsip::Method::Ack => {
                if reject && tx.original.method == rsip::Method::Invite {
                    info!("Rejecting incoming call: {}", tx.original);
                    tx.reply(rsip::StatusCode::BusyHere).await?;
                    continue;
                }
                let mut dialog = match dialog_layer.get_or_create_server_invite(
                    &tx,
                    state_sender.clone(),
                    None,
                    Some(contact.clone()),
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        // 481 Dialog/Transaction Does Not Exist
                        info!("Failed to obtain dialog: {:?}", e);
                        tx.reply(rsip::StatusCode::CallTransactionDoesNotExist)
                            .await?;
                        continue;
                    }
                };
                tokio::spawn(async move {
                    dialog.handle(&mut tx).await?;
                    Ok::<_, Error>(())
                });
            }
            _ => {
                info!("Received request: {:?}", tx.original.method);
                tx.reply(rsip::StatusCode::OK).await?;
            }
        }
    }
    Ok::<_, Error>(())
}

async fn process_dialog(
    dialog_layer: Arc<DialogLayer>,
    state_receiver: DialogStateReceiver,
    opt: MediaSessionOption,
) -> Result<()> {
    let mut state_receiver = state_receiver;
    while let Some(state) = state_receiver.recv().await {
        match state {
            DialogState::Calling(id) => {
                info!("Calling dialog {}", id);
                let dialog = match dialog_layer.get_dialog(&id) {
                    Some(d) => d,
                    None => {
                        info!("Dialog not found {}", id);
                        continue;
                    }
                };
                match dialog {
                    Dialog::ServerInvite(d) => {
                        // play example pcmu of handling incoming call
                        //
                        // [A] Ai answer, [R] Reject, [E] Play example pcmu
                        let opt_clone = opt.clone();
                        tokio::spawn(async move { process_invite(&opt_clone, d).await.ok() });
                    }
                    Dialog::ClientInvite(_) => {
                        info!("Client invite dialog {}", id);
                    }
                    Dialog::ServerSubscription(_) => {
                        info!("Server subscription dialog {}", id);
                    }
                    Dialog::ClientSubscription(_) => {
                        info!("Client subscription dialog {}", id);
                    }
                    Dialog::ServerPublication(_) => {
                        info!("Server publication dialog {}", id);
                    }
                    Dialog::ClientPublication(_) => {
                        info!("Client publication dialog {}", id);
                    }
                }
            }
            DialogState::Early(id, resp) => {
                info!("Early dialog {} {}", id, resp);
            }
            DialogState::Terminated(id, reason) => {
                info!("Dialog terminated {} {:?}", id, reason);
                dialog_layer.remove_dialog(&id);
            }
            _ => {
                info!("Received dialog state: {}", state);
            }
        }
    }
    Ok(())
}

async fn make_call(
    dialog_layer: Arc<DialogLayer>,
    invite_option: InviteOption,
    media_option: MediaSessionOption,
    state_sender: DialogStateSender,
) -> Result<()> {
    let ssrc = rand::random::<u32>();
    let codec_type = 0;
    let (rtp_conn, offer) = build_rtp_conn(&media_option, ssrc, codec_type).await?;
    let mut invite_option = invite_option;
    invite_option.offer = Some(offer.into());

    let (dialog, resp) = dialog_layer.do_invite(invite_option, state_sender).await?;
    let rtp_token = dialog.cancel_token().child_token();
    let resp = resp.ok_or(Error::Error("No response".to_string()))?;

    if resp.status_code != rsip::StatusCode::OK {
        info!("Failed to make call: {:?}", resp);
        return Err(Error::Error("Failed to make call".to_string()));
    }

    let body = String::from_utf8_lossy(resp.body()).to_string();
    info!("Received response: {}", resp);

    let answer = match sdp_rs::SessionDescription::try_from(body.as_str()) {
        Ok(s) => s,
        Err(e) => {
            info!("Failed to parse answer SDP: {:?} {}", e, body);
            return Err(Error::Error("Failed to parse SDP".to_string()));
        }
    };

    let peer_addr = match answer.connection {
        Some(c) => c.connection_address.base,
        None => {
            info!("No connection address in answer SDP");
            return Err(Error::Error(
                "No connection address in answer SDP".to_string(),
            ));
        }
    };

    let peer_port = answer
        .media_descriptions
        .first()
        .map(|m| m.media.port)
        .ok_or(Error::Error("No audio port in answer SDP".to_string()))?;

    let peer_addr = format!("{}:{}", peer_addr, peer_port);
    let payload_type = answer
        .media_descriptions
        .first()
        .and_then(|m| m.media.fmt.parse::<u8>().ok())
        .unwrap_or(0);
    info!("Peer address: {} payload_type:{}", peer_addr, payload_type);
    play_audio_file(
        rtp_conn,
        rtp_token,
        ssrc,
        "example",
        0,
        1,
        peer_addr,
        payload_type,
    )
    .await
    .expect("play example file");
    dialog.bye().await.expect("send BYE");
    Ok(())
}

async fn process_invite(opt: &MediaSessionOption, dialog: ServerInviteDialog) -> Result<()> {
    let ssrc = rand::random::<u32>();

    let body = String::from_utf8_lossy(dialog.initial_request().body()).to_string();
    let offer = match sdp_rs::SessionDescription::try_from(body.as_str()) {
        Ok(s) => s,
        Err(e) => {
            info!("Failed to parse offer SDP: {:?} {}", e, body);
            return Err(Error::Error("Failed to parse SDP".to_string()));
        }
    };

    let peer_addr = match offer.connection {
        Some(c) => c.connection_address.base,
        None => {
            info!("No connection address in offer SDP");
            return Err(Error::Error(
                "No connection address in offer SDP".to_string(),
            ));
        }
    };

    let peer_port = offer
        .media_descriptions
        .first()
        .map(|m| m.media.port)
        .ok_or(Error::Error("No audio port in offer SDP".to_string()))?;
    let payload_type = offer
        .media_descriptions
        .first()
        .and_then(|m| m.media.fmt.parse::<u8>().ok())
        .unwrap_or(0);

    let (conn, answer) = build_rtp_conn(opt, ssrc, payload_type).await?;

    let (answer_sender, mut answer_receiver) = tokio::sync::mpsc::unbounded_channel();
    if opt.random_reject > 0 {
        if rand::random::<u32>() % opt.random_reject == 0 {
            info!("Randomly rejecting the call");
            dialog.reject(Some(rsip::StatusCode::BusyHere), Some("Busy here".into()));
            return Ok(());
        }
    }
    let mut ts = 0;
    let mut seq = 1;
    let peer_addr = format!("{}:{}", peer_addr, peer_port);
    if opt.auto_answer {
        let headers = vec![rsip::typed::ContentType(MediaType::Sdp(vec![])).into()];
        dialog.ringing(Some(headers), Some(answer.clone().into()))?;
        let ringback_token = CancellationToken::new();
        timeout(
            Duration::from_secs(rand::random::<u64>() % 3u64 + 1),
            play_audio_file(
                conn.clone(),
                ringback_token.clone(),
                ssrc,
                "ringback",
                ts,
                seq,
                peer_addr.clone(),
                payload_type,
            ),
        )
        .await
        .ok();

        //answer_sender.send("a".to_string()).expect("send answer");
        info!(
            "Accepted call with answer SDP peer address: {} port: {} payload_type: {}",
            peer_addr, peer_port, payload_type
        );
    } else {
        let headers = vec![rsip::typed::ContentType(MediaType::Sdp(vec![])).into()];
        dialog.ringing(Some(headers), Some(answer.clone().into()))?;
    }

    let rtp_token = dialog.cancel_token().child_token();
    let echo = opt.echo;
    let answered = opt.auto_answer;

    tokio::spawn(async move {
        let input_token = CancellationToken::new();
        select! {
            _ = handle_user_input(input_token, answer_sender) => {
                info!("user input handler finished");
            }
            _ = async {
                let mut rejected = false;

                println!("\x1b[32mPress 'a' to answer, 'r' to reject, or 'q' to quit.\x1b[0m");
                if !answered {
                    let ringback_token = rtp_token.child_token();
                    let (pos,_) = tokio::join!(
                            play_audio_file(
                            conn.clone(),
                            ringback_token.clone(),
                            ssrc,
                            "ringback",
                            ts,
                            seq,
                            peer_addr.clone(),
                            payload_type
                        ),
                        async {
                            let r = answer_receiver.recv().await.unwrap_or_default();
                            ringback_token.cancel();

                            if r == "a" {
                                info!("User answered the call");
                            } else if r == "r" {
                                info!("User rejected the call");
                                dialog.reject(Some(rsip::StatusCode::BusyHere), Some("Busy here".into()));
                                rejected = true;
                                return;
                            } else {
                                info!("Unknown command: {}", r);
                                return;
                            }
                        }
                    );
                    match pos {
                        Ok((t, s)) => {
                            ts = t;
                            seq = s;
                        }
                        Err(e) => {
                            info!("Failed to play ringback: {:?}", e);
                        }
                    }
                }
                if rejected {
                    return;
                }
                let headers = vec![rsip::typed::ContentType(MediaType::Sdp(vec![])).into()];
                match dialog.accept(Some(headers), Some(answer.clone().into())) {
                    Ok(_) => info!("Accepted call with answer SDP peer address: {} port: {} payload_type: {}", peer_addr, peer_port, payload_type),
                    Err(e) => {
                        error!("Failed to accept call: {:?}", e);
                        return;
                    }
                }
                if echo {
                    play_echo(conn, rtp_token).await.expect("play echo");
                } else {
                    play_audio_file(conn, rtp_token, ssrc, "example", ts, seq, peer_addr, payload_type)
                        .await
                        .expect("play example file");
                }
            } => {
                info!("answer receiver finished");
            }
        }
        dialog.bye().await.expect("send BYE");
    });
    Ok(())
}
