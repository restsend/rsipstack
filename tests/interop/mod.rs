//! Process and endpoint fixtures for the opt-in PJSIP and SIPp suites.
mod pjsip;
mod sipp;
use rsipstack::{
    dialog::{
        dialog::{Dialog, DialogState, DialogStateSender},
        dialog_layer::DialogLayer,
        invite_dialog::InviteDialog,
    },
    sip::{prelude::HeadersExt, Method, Request, Response, SipMessage, StatusCode, Uri},
    transaction::endpoint::{MessageInspector, TransportEventInspector},
    transport::{
        tcp_listener::TcpListenerConnection, udp::UdpConnection, SipAddr, TransportEvent,
        TransportLayer,
    },
    EndpointBuilder,
};
use std::{
    fs::File,
    io::Write,
    net::{SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(15);

pub async fn until<T>(description: &str, mut check: impl FnMut() -> Option<T>) -> T {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Some(value) = check() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {description}; inspect the scenario logs"))
}

pub async fn bounded<T>(description: &str, future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future)
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {description}; inspect the scenario logs"))
}

// Both peers bind only loopback. PJSUA and rsipstack's TCP listener accept
// port numbers, not pre-bound sockets; a collision fails visibly at startup.
pub fn free_addr(transport: &str) -> SocketAddr {
    if transport == "tcp" {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    } else {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }
}

pub fn log_dir(name: &str) -> PathBuf {
    let root = std::env::var_os("RSIPSTACK_INTEROP_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/interop/results")
                .join(format!("direct-{}", std::process::id()))
        });
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let pass = dir.join("PASS");
    if pass.exists() {
        std::fs::remove_file(pass).unwrap();
    }
    println!("scenario {name}: {}", dir.display());
    dir
}

pub struct Peer {
    child: Child,
    output: watch::Receiver<String>,
    reader: JoinHandle<()>,
    pub uri: Uri,
}

impl Peer {
    pub async fn start(transport: &str, dir: &Path) -> Self {
        let binary = std::env::var_os("PJSUA_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/interop/pjsua")
            });
        assert!(
            binary.is_file(),
            "PJSUA not found: {}. Run bash scripts/interop/build-pjsua.sh or set PJSUA_BIN",
            binary.display()
        );
        let addr = free_addr(transport);
        let uri: Uri = format!("sip:pjsip@{addr};transport={transport}")
            .parse()
            .unwrap();
        let mut child = Command::new(&binary)
            .args([
                "--null-audio",
                "--no-color",
                "--stdout-no-buf",
                "--no-vad",
                "--use-timer=0",
                "--max-calls=1",
                "--auto-answer=180",
                "--bound-addr=127.0.0.1",
                "--ip-addr=127.0.0.1",
                "--log-level=5",
                "--app-log-level=5",
                "--rtp-port=0",
            ])
            .arg(if transport == "udp" {
                "--no-tcp"
            } else {
                "--no-udp"
            })
            .arg(format!("--local-port={}", addr.port()))
            .arg(format!("--id={uri}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(dir.join("pjsua.stderr.log")).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("cannot start {}: {e}", binary.display()));
        let mut stdout = child.stdout.take().unwrap();
        let mut log = File::create(dir.join("pjsua.log")).unwrap();
        let (sender, output) = watch::channel(String::new());
        let reader = tokio::spawn(async move {
            let mut buf = [0; 8192];
            loop {
                let n = stdout.read(&mut buf).await.expect("read PJSUA output");
                if n == 0 {
                    break;
                }
                log.write_all(&buf[..n]).unwrap();
                log.flush().unwrap();
                sender.send_modify(|text| text.push_str(&String::from_utf8_lossy(&buf[..n])));
            }
        });
        let mut peer = Self {
            child,
            output,
            reader,
            uri,
        };
        peer.wait_text(">>> ").await;
        peer
    }

    pub async fn wait_text(&mut self, text: &str) {
        bounded(
            &format!("PJSUA output {text:?}"),
            self.output.wait_for(|s| s.contains(text)),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("PJSUA exited before {text:?}; see pjsua.log and pjsua.stderr.log")
        });
    }

    pub async fn command(&mut self, command: &str) {
        let stdin = self.child.stdin.as_mut().unwrap();
        bounded("PJSUA command", async {
            stdin.write_all(command.as_bytes()).await.unwrap();
            stdin.flush().await.unwrap();
        })
        .await;
    }

    pub async fn stop(mut self) {
        self.command("q\n").await;
        let status = bounded("PJSUA shutdown", self.child.wait()).await.unwrap();
        self.reader.await.unwrap();
        assert!(status.success(), "PJSUA exited with {status}");
    }
}

#[derive(Clone)]
pub struct Packet {
    pub sent: bool,
    pub message: SipMessage,
}

#[derive(Clone)]
pub struct Wire(Arc<Mutex<Vec<Packet>>>);

struct Inspector {
    wire: Wire,
    log: Mutex<File>,
    start: Instant,
}

impl Inspector {
    fn record(&self, sent: bool, message: SipMessage) -> SipMessage {
        writeln!(
            self.log.lock().unwrap(),
            "{:?} {}\n{}\n",
            self.start.elapsed(),
            if sent { "TX" } else { "RX" },
            message
        )
        .unwrap();
        self.wire.0.lock().unwrap().push(Packet {
            sent,
            message: message.clone(),
        });
        message
    }
}

struct Received(Arc<Inspector>);
struct Sent(Arc<Inspector>);

// ACKs absorbed by the finished-transaction cache do not reach after_received.
#[async_trait::async_trait]
impl TransportEventInspector for Received {
    async fn handle(&self, event: TransportEvent) -> Option<TransportEvent> {
        if let TransportEvent::Incoming(message, _, _) = &event {
            self.0.record(false, message.clone());
        }
        Some(event)
    }
}

impl MessageInspector for Sent {
    fn before_send(&self, msg: SipMessage, _: Option<&SipAddr>) -> SipMessage {
        self.0.record(true, msg)
    }
    fn after_received(&self, msg: SipMessage, _: Option<&SipAddr>) -> SipMessage {
        msg
    }
}

impl Wire {
    pub async fn request(&self, sent: bool, method: Method) -> Request {
        until(
            &format!("{} {method}", if sent { "TX" } else { "RX" }),
            || {
                self.0
                    .lock()
                    .unwrap()
                    .iter()
                    .find_map(|p| match &p.message {
                        SipMessage::Request(r) if p.sent == sent && r.method == method => {
                            Some(r.clone())
                        }
                        _ => None,
                    })
            },
        )
        .await
    }

    pub async fn response(&self, sent: bool, method: Method, code: u16) -> Response {
        until(&format!("response {code} to {method}"), || {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find_map(|p| match &p.message {
                    SipMessage::Response(r)
                        if p.sent == sent
                            && r.status_code.code() == code
                            && r.cseq_header().unwrap().method().unwrap() == method =>
                    {
                        Some(r.clone())
                    }
                    _ => None,
                })
        })
        .await
    }

    pub fn requests(&self, method: Method) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|p| matches!(&p.message, SipMessage::Request(r) if r.method == method))
            .count()
    }
}

pub struct Stack {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    pub layer: Arc<DialogLayer>,
    pub sender: DialogStateSender,
    pub states: Arc<Mutex<Vec<DialogState>>>,
    pub incoming: mpsc::UnboundedReceiver<InviteDialog>,
    pub uri: Uri,
    pub wire: Wire,
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Stack {
    pub async fn start(transport: &str, dir: &Path) -> Self {
        let cancel = CancellationToken::new();
        let layer = TransportLayer::new(cancel.child_token());
        let addr = if transport == "udp" {
            let udp = UdpConnection::create_connection(
                "127.0.0.1:0".parse().unwrap(),
                None,
                Some(cancel.child_token()),
            )
            .await
            .unwrap();
            let addr = udp.get_addr().get_socketaddr().unwrap();
            layer.add_transport(udp.into());
            addr
        } else {
            let addr = free_addr(transport);
            layer.add_transport(TcpListenerConnection::new(addr, None).await.unwrap().into());
            addr
        };
        let uri: Uri = format!("sip:rsipstack@{addr};transport={transport}")
            .parse()
            .unwrap();
        let wire = Wire(Arc::new(Mutex::new(Vec::new())));
        let inspector = Arc::new(Inspector {
            wire: wire.clone(),
            log: Mutex::new(File::create(dir.join("sip.log")).unwrap()),
            start: Instant::now(),
        });
        let endpoint = EndpointBuilder::new()
            .with_user_agent("rsipstack-interop")
            .with_transport_layer(layer)
            .with_cancel_token(cancel.child_token())
            .with_inspector(Box::new(Sent(inspector.clone())))
            .with_transport_inspector(Box::new(Received(inspector)))
            .build();
        let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
        let mut transactions = endpoint.incoming_transactions().unwrap();
        let mut tasks = vec![tokio::spawn(async move {
            endpoint.inner.serve().await.expect("endpoint serve");
        })];
        if transport == "tcp" {
            bounded("rsipstack TCP listener", async {
                loop {
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
        }
        let (sender, mut receiver) = layer.new_dialog_state_channel();
        let states = Arc::new(Mutex::new(Vec::new()));
        let saved = states.clone();
        let dialogs = layer.clone();
        let mut log = File::create(dir.join("states.log")).unwrap();
        tasks.push(tokio::spawn(async move {
            while let Some(state) = receiver.recv().await {
                writeln!(log, "{state:?}").unwrap();
                if let DialogState::Terminated(id, _) = &state {
                    // Registry removal is the application's documented duty.
                    dialogs.remove_dialog(id);
                }
                saved.lock().unwrap().push(state);
            }
        }));
        let (incoming_tx, incoming) = mpsc::unbounded_channel();
        let dialogs = layer.clone();
        let state_sender = sender.clone();
        let contact = uri.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(mut tx) = transactions.recv().await {
                let dialog = if let Some(d) = dialogs.match_dialog(&tx) {
                    Some(d)
                } else if tx.original.method == Method::Invite
                    && tx.original.to_header().unwrap().tag().unwrap().is_none()
                {
                    let d = dialogs
                        .get_or_create_server_invite(
                            &tx,
                            state_sender.clone(),
                            None,
                            Some(contact.clone()),
                        )
                        .unwrap();
                    incoming_tx.send(d.clone()).unwrap();
                    Some(Dialog::Invite(d))
                } else {
                    None
                };
                if let Some(mut dialog) = dialog {
                    tokio::spawn(async move {
                        dialog.handle(&mut tx).await.expect("dialog handler");
                    });
                } else {
                    tx.reply(StatusCode::CallTransactionDoesNotExist)
                        .await
                        .unwrap();
                }
            }
        }));
        Self {
            cancel,
            tasks,
            layer,
            sender,
            states,
            incoming,
            uri,
            wire,
        }
    }

    pub async fn state(&self, description: &str, predicate: impl Fn(&DialogState) -> bool) {
        until(description, || {
            self.states
                .lock()
                .unwrap()
                .iter()
                .any(&predicate)
                .then_some(())
        })
        .await;
    }
}

/// Fixed PCMU offer/answer; the peer negotiates it normally. These tests check
/// SIP signalling, not RTP quality. The inactive stream needs no audio hardware.
pub fn sdp() -> Vec<u8> {
    b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=interop\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 9 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=inactive\r\n".to_vec()
}
