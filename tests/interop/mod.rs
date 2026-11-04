//! Process and endpoint fixtures for the opt-in PJSIP and SIPp suites.
#[macro_use]
mod failure;
pub use failure::{Failure, Required, TestResult};
mod faults;
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

pub async fn until<T>(description: &str, mut check: impl FnMut() -> Option<T>) -> TestResult<T> {
    until_result(description, || Ok(check())).await
}

pub async fn until_result<T>(
    description: &str,
    mut check: impl FnMut() -> TestResult<Option<T>>,
) -> TestResult<T> {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Some(value) = check()? {
                return Ok(value);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| {
        Failure(format!(
            "Timeout waiting for {description}; inspect the scenario logs"
        ))
    })?
}

pub async fn bounded<T>(
    description: &str,
    future: impl std::future::Future<Output = T>,
) -> TestResult<T> {
    tokio::time::timeout(WAIT, future).await.map_err(|_| {
        Failure(format!(
            "Timeout waiting for {description}; inspect the scenario logs"
        ))
    })
}

// Both peers bind only loopback. PJSUA and rsipstack's TCP listener accept
// port numbers, not pre-bound sockets; a collision fails visibly at startup.
pub fn free_addr(transport: &str) -> TestResult<SocketAddr> {
    if transport == "tcp" {
        TcpListener::bind("127.0.0.1:0")
            .required()?
            .local_addr()
            .required()
    } else {
        UdpSocket::bind("127.0.0.1:0")
            .required()?
            .local_addr()
            .required()
    }
}

pub fn log_dir(name: &str) -> TestResult<PathBuf> {
    let root = std::env::var_os("RSIPSTACK_INTEROP_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/interop/results")
                .join(format!("direct-{}", std::process::id()))
        });
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).required()?;
    let pass = dir.join("PASS");
    if pass.exists() {
        std::fs::remove_file(pass).required()?;
    }
    println!("scenario {name}: {}", dir.display());
    Ok(dir)
}

pub struct Peer {
    child: Child,
    output: watch::Receiver<String>,
    reader: JoinHandle<TestResult>,
    pub uri: Uri,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Peer {
    pub async fn start(transport: &str, dir: &Path) -> TestResult<Self> {
        let binary = std::env::var_os("PJSUA_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/interop/pjsua")
            });
        check!(
            binary.is_file(),
            "PJSUA not found: {}. Run bash scripts/interop/build-pjsua.sh or set PJSUA_BIN",
            binary.display()
        );
        let addr = free_addr(transport)?;
        let uri: Uri = format!("sip:pjsip@{addr};transport={transport}")
            .parse()
            .required()?;
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
            .stderr(File::create(dir.join("pjsua.stderr.log")).required()?)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Failure(format!("Cannot start {}: {e}", binary.display())))?;
        let mut stdout = child.stdout.take().required()?;
        let mut log = File::create(dir.join("pjsua.log")).required()?;
        let (sender, output) = watch::channel(String::new());
        let reader = tokio::spawn(async move {
            let mut buf = [0; 8192];
            loop {
                let n = stdout.read(&mut buf).await.required()?;
                if n == 0 {
                    break;
                }
                log.write_all(&buf[..n]).required()?;
                log.flush().required()?;
                sender.send_modify(|text| text.push_str(&String::from_utf8_lossy(&buf[..n])));
            }
            Ok(())
        });
        let mut peer = Self {
            child,
            output,
            reader,
            uri,
        };
        peer.wait_text(">>> ").await?;
        Ok(peer)
    }

    pub async fn wait_text(&mut self, text: &str) -> TestResult {
        self.wait_text_after(text, 0).await
    }

    pub fn output_len(&self) -> usize {
        self.output.borrow().len()
    }

    pub async fn wait_text_after(&mut self, text: &str, offset: usize) -> TestResult {
        bounded(
            &format!("PJSUA output {text:?}"),
            self.output
                .wait_for(|s| s.get(offset..).is_some_and(|tail| tail.contains(text))),
        )
        .await?
        .map_err(|_| {
            Failure(format!(
                "PJSUA exited before {text:?}; see pjsua.log and pjsua.stderr.log"
            ))
        })?;
        Ok(())
    }

    pub async fn command(&mut self, command: &str) -> TestResult {
        let stdin = self.child.stdin.as_mut().required()?;
        bounded("PJSUA command", async {
            stdin.write_all(command.as_bytes()).await.required()?;
            stdin.flush().await.required()
        })
        .await?
    }

    pub async fn stop(mut self) -> TestResult {
        self.command("q\n").await?;
        let status = bounded("PJSUA shutdown", self.child.wait())
            .await?
            .required()?;
        (&mut self.reader).await.required()?.required()?;
        check!(status.success(), "PJSUA exited with {status}");
        Ok(())
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
    errors: Diagnostics,
}

impl Inspector {
    fn record(&self, sent: bool, message: SipMessage) -> SipMessage {
        let result = writeln!(
            self.log.lock().unwrap_or_else(|p| p.into_inner()),
            "{:?} {}\n{}\n",
            self.start.elapsed(),
            if sent { "TX" } else { "RX" },
            message
        );
        if let Err(error) = result {
            self.errors
                .record(format!("SIP trace write failed: {error}"));
        }
        self.wire
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(Packet {
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
    pub fn checkpoint(&self) -> usize {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub async fn request(&self, sent: bool, method: Method) -> TestResult<Request> {
        self.request_after(sent, method, 0).await
    }

    pub async fn request_after(
        &self,
        sent: bool,
        method: Method,
        offset: usize,
    ) -> TestResult<Request> {
        until(
            &format!("{} {method}", if sent { "TX" } else { "RX" }),
            || {
                self.0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter()
                    .skip(offset)
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

    pub async fn response(&self, sent: bool, method: Method, code: u16) -> TestResult<Response> {
        until_result(&format!("response {code} to {method}"), || {
            for packet in self.0.lock().unwrap_or_else(|p| p.into_inner()).iter() {
                if let SipMessage::Response(response) = &packet.message {
                    if packet.sent == sent
                        && response.status_code.code() == code
                        && response.cseq_header().required()?.method().required()? == method
                    {
                        return Ok(Some(response.clone()));
                    }
                }
            }
            Ok(None)
        })
        .await
    }

    pub fn requests(&self, method: Method) -> usize {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|p| matches!(&p.message, SipMessage::Request(r) if r.method == method))
            .count()
    }
}

/// Background failures remain test failures even when the peer finishes normally.
#[derive(Clone)]
struct Diagnostics {
    failures: Arc<Mutex<Vec<String>>>,
    log: Arc<Mutex<File>>,
}

impl Diagnostics {
    fn new(dir: &Path) -> TestResult<Self> {
        Ok(Self {
            failures: Arc::new(Mutex::new(Vec::new())),
            log: Arc::new(Mutex::new(
                File::create(dir.join("background-errors.log")).required()?,
            )),
        })
    }

    fn record(&self, message: String) {
        let mut failures = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(error) = writeln!(
            self.log.lock().unwrap_or_else(|p| p.into_inner()),
            "{message}"
        ) {
            failures.push(format!("Background error log write failed: {error}"));
        }
        failures.push(message);
    }

    fn spawn(
        &self,
        context: impl Into<String>,
        future: impl std::future::Future<Output = TestResult> + Send + 'static,
    ) -> JoinHandle<()> {
        let diagnostics = self.clone();
        let context = context.into();
        tokio::spawn(async move {
            if let Err(error) = future.await {
                diagnostics.record(format!("{context}: {error}"));
            }
        })
    }

    fn check(&self) -> TestResult {
        let failures = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        check!(
            failures.is_empty(),
            "Background errors:\n{}",
            failures.join("\n")
        );
        Ok(())
    }
}

pub struct Stack {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    handlers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    errors: Diagnostics,
    pub layer: Arc<DialogLayer>,
    pub sender: DialogStateSender,
    pub states: Arc<Mutex<Vec<DialogState>>>,
    pub incoming: mpsc::UnboundedReceiver<InviteDialog>,
    pub uri: Uri,
    pub wire: Wire,
    pub faults: Option<faults::Control>,
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in self.tasks.iter().chain(
            self.handlers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter(),
        ) {
            task.abort();
        }
    }
}

impl Stack {
    pub async fn start(transport: &str, dir: &Path) -> TestResult<Self> {
        Self::start_inner(transport, dir, None).await
    }

    pub async fn with_faults(dir: &Path, rules: Vec<faults::Rule>) -> TestResult<Self> {
        Self::start_inner("udp", dir, Some(rules)).await
    }

    async fn start_inner(
        transport: &str,
        dir: &Path,
        rules: Option<Vec<faults::Rule>>,
    ) -> TestResult<Self> {
        let cancel = CancellationToken::new();
        let layer = TransportLayer::new(cancel.child_token());
        let errors = Diagnostics::new(dir)?;
        let mut tasks = Vec::new();
        let mut faults = None;
        let addr = if let Some(rules) = rules {
            let (socket, control, task) = faults::socket(dir, rules, errors.clone()).await?;
            tasks.push(task);
            faults = Some(control);
            let udp = UdpConnection::from_socket(socket, None, Some(cancel.child_token()))
                .await
                .required()?;
            let addr = udp.get_addr().get_socketaddr().required()?;
            layer.add_transport(udp.into());
            addr
        } else if transport == "udp" {
            let udp = UdpConnection::create_connection(
                "127.0.0.1:0".parse().required()?,
                None,
                Some(cancel.child_token()),
            )
            .await
            .required()?;
            let addr = udp.get_addr().get_socketaddr().required()?;
            layer.add_transport(udp.into());
            addr
        } else {
            let addr = free_addr(transport)?;
            layer.add_transport(
                TcpListenerConnection::new(addr, None)
                    .await
                    .required()?
                    .into(),
            );
            addr
        };
        let uri: Uri = format!("sip:rsipstack@{addr};transport={transport}")
            .parse()
            .required()?;
        let wire = Wire(Arc::new(Mutex::new(Vec::new())));
        let inspector = Arc::new(Inspector {
            errors: errors.clone(),
            wire: wire.clone(),
            log: Mutex::new(File::create(dir.join("sip.log")).required()?),
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
        let mut transactions = endpoint.incoming_transactions().required()?;
        tasks.push(errors.spawn("endpoint serve", async move {
            endpoint.inner.serve().await.required()
        }));
        // Construct the owner before awaiting startup so an early return
        // cancels every task and releases the listening socket.
        let handlers = Arc::new(Mutex::new(Vec::new()));
        let (sender, mut receiver) = layer.new_dialog_state_channel();
        let (incoming_tx, incoming) = mpsc::unbounded_channel();
        let states = Arc::new(Mutex::new(Vec::new()));
        let mut stack = Self {
            cancel,
            tasks,
            handlers: handlers.clone(),
            errors: errors.clone(),
            layer: layer.clone(),
            sender: sender.clone(),
            states: states.clone(),
            incoming,
            uri: uri.clone(),
            wire,
            faults,
        };
        if transport == "tcp" {
            bounded("rsipstack TCP listener", async {
                loop {
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
        }
        let saved = states.clone();
        let dialogs = layer.clone();
        let mut log = File::create(dir.join("states.log")).required()?;
        stack
            .tasks
            .push(errors.spawn("dialog state recorder", async move {
                while let Some(state) = receiver.recv().await {
                    writeln!(log, "{state:?}").required()?;
                    if let DialogState::Terminated(id, _) = &state {
                        // Registry removal is the application's documented duty.
                        dialogs.remove_dialog(id);
                    }
                    saved.lock().unwrap_or_else(|p| p.into_inner()).push(state);
                }
                Ok(())
            }));
        let dialogs = layer.clone();
        let state_sender = sender.clone();
        let contact = uri.clone();
        let handler_errors = errors.clone();
        stack
            .tasks
            .push(errors.spawn("transaction router", async move {
                while let Some(mut tx) = transactions.recv().await {
                    let dialog = if let Some(d) = dialogs.match_dialog(&tx) {
                        Some(d)
                    } else if tx.original.method == Method::Invite
                        && tx
                            .original
                            .to_header()
                            .required()?
                            .tag()
                            .required()?
                            .is_none()
                    {
                        let d = dialogs
                            .get_or_create_server_invite(
                                &tx,
                                state_sender.clone(),
                                None,
                                Some(contact.clone()),
                            )
                            .required()?;
                        incoming_tx.send(d.clone()).required()?;
                        Some(Dialog::Invite(d))
                    } else {
                        None
                    };
                    if let Some(mut dialog) = dialog {
                        let context = format!(
                            "dialog handler: {} {}",
                            tx.original.method,
                            tx.original.call_id_header().required()?
                        );
                        let task = handler_errors.spawn(context, async move {
                            dialog.handle(&mut tx).await.required()
                        });
                        handlers
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push(task);
                    } else {
                        tx.reply(StatusCode::CallTransactionDoesNotExist)
                            .await
                            .required()?;
                    }
                }
                Ok(())
            }));
        Ok(stack)
    }

    pub async fn finish(&self, dir: &Path, summary: String) -> TestResult {
        loop {
            let task = self
                .handlers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pop();
            let Some(mut task) = task else {
                break;
            };
            let result = bounded("dialog handler shutdown", &mut task).await;
            if result.is_err() {
                task.abort();
            }
            result?.required()?;
        }
        self.errors.check()?;
        for task in &self.tasks {
            check!(
                !task.is_finished(),
                "Background service ended before fixture shutdown; inspect background-errors.log"
            );
        }
        if let Some(faults) = &self.faults {
            faults.check()?;
        }
        std::fs::write(dir.join("PASS"), summary).required()
    }

    pub async fn state(
        &self,
        description: &str,
        predicate: impl Fn(&DialogState) -> bool,
    ) -> TestResult {
        until(description, || {
            self.states
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .any(&predicate)
                .then_some(())
        })
        .await
    }
}

/// Fixed PCMU offer/answer; the peer negotiates it normally. These tests check
/// SIP signalling, not RTP quality. The inactive stream needs no audio hardware.
pub fn sdp() -> Vec<u8> {
    b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=interop\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 9 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=inactive\r\n".to_vec()
}

#[tokio::test]
async fn background_failure_is_reported_without_unwinding() -> TestResult {
    let dir = tempfile::tempdir().required()?;
    let errors = Diagnostics::new(dir.path())?;
    let task = errors.spawn("dialog handler", async {
        Err(Failure("injected Broken pipe".into()))
    });
    // A normal join with a recorded error must never become a passing check.
    task.await.required()?;
    let error = errors.check().err().required()?;
    check!(error.0.contains("dialog handler: injected Broken pipe"));
    let log = std::fs::read_to_string(dir.path().join("background-errors.log")).required()?;
    check!(log.contains("dialog handler: injected Broken pipe"));
    Ok(())
}
