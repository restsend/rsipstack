//! Shared process lifecycle for the deliberately small interop applications.
use rsipstack::{
    sip::{SipMessage, Uri},
    transaction::endpoint::{Endpoint, EndpointOption, MessageInspector, TransportEventInspector},
    transport::{
        tcp_listener::TcpListenerConnection, udp::UdpConnection, SipAddr, TransportEvent,
        TransportLayer,
    },
    EndpointBuilder,
};
use std::{
    collections::HashSet,
    error::Error,
    fs::File,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub type AppResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub struct Config {
    pub listen: SocketAddr,
    pub transport: String,
    pub target: Uri,
    pub logs: PathBuf,
}

impl Config {
    pub fn parse() -> AppResult<Self> {
        let mut args = std::env::args().skip(1);
        let (mut listen, mut transport, mut target, mut logs) = (None, None, None, None);
        while let Some(key) = args.next() {
            if key == "--help" {
                println!("--listen 127.0.0.1:PORT --transport udp|tcp --target sip:user@127.0.0.1:PORT;transport=udp --log-dir PATH\nSend quit on stdin to check cleanup and stop. Loopback only; one configured next hop.");
                std::process::exit(0);
            }
            let value = args
                .next()
                .ok_or_else(|| format!("Missing value for {key}"))?;
            match key.as_str() {
                "--listen" => listen = Some(value.parse::<SocketAddr>()?),
                "--transport" => transport = Some(value),
                "--target" => target = Some(value.parse::<Uri>()?),
                "--log-dir" => logs = Some(PathBuf::from(value)),
                _ => return Err(format!("Unknown argument {key}").into()),
            }
        }
        let config = Self {
            listen: listen.ok_or("Missing --listen")?,
            transport: transport.ok_or("Missing --transport")?,
            target: target.ok_or("Missing --target")?,
            logs: logs.ok_or("Missing --log-dir")?,
        };
        let target = SipAddr::try_from(&config.target)?.get_socketaddr()?;
        if !config.listen.ip().is_loopback() || !target.ip().is_loopback() {
            return Err("Interop applications only accept loopback addresses".into());
        }
        if !matches!(config.transport.as_str(), "udp" | "tcp") {
            return Err("--transport must be udp or tcp".into());
        }
        Ok(config)
    }
}

#[derive(Clone)]
pub struct Tasks {
    handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    errors: Arc<Mutex<Vec<String>>>,
    events: Arc<Mutex<File>>,
}

impl Tasks {
    pub fn event(&self, text: impl AsRef<str>) {
        if let Err(error) = writeln!(
            self.events.lock().unwrap_or_else(|p| p.into_inner()),
            "{}",
            text.as_ref()
        ) {
            self.errors
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(error.to_string());
        }
    }

    pub fn spawn(
        &self,
        context: &'static str,
        future: impl std::future::Future<Output = AppResult> + Send + 'static,
    ) {
        let tasks = self.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = future.await {
                let error = format!("{context}: {error}");
                tasks.event(format!("ERROR {error}"));
                tasks
                    .errors
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(error);
            }
        });
        self.handles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(task);
    }

    async fn stop(&self) {
        // Explicit shutdown cancels timer-retention tasks too. Join all of them
        // so a genuine library panic still fails the application.
        loop {
            let handles =
                std::mem::take(&mut *self.handles.lock().unwrap_or_else(|p| p.into_inner()));
            if handles.is_empty() {
                break;
            }
            for task in &handles {
                task.abort();
            }
            for task in handles {
                if let Err(error) = task.await {
                    if !error.is_cancelled() {
                        self.errors
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push(error.to_string());
                    }
                }
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct Calls(Arc<Mutex<HashSet<String>>>);

impl Calls {
    pub fn add(&self, id: String) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).insert(id);
    }
    pub fn remove(&self, id: &str) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).remove(id);
    }
    pub fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[derive(Clone)]
struct Trace {
    file: Arc<Mutex<File>>,
    tasks: Tasks,
}

impl Trace {
    fn record(&self, direction: &str, message: &SipMessage) {
        let raw = message.to_string();
        let mut file = self.file.lock().unwrap_or_else(|p| p.into_inner());
        // Length framing preserves SDP and messages containing blank lines.
        if let Err(error) =
            write!(file, "{direction} {}\n{raw}\n", raw.len()).and_then(|_| file.flush())
        {
            self.tasks
                .errors
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(error.to_string());
        }
    }
}

impl MessageInspector for Trace {
    fn before_send(&self, message: SipMessage, _: Option<&SipAddr>) -> SipMessage {
        self.record("TX", &message);
        message
    }
    fn after_received(&self, message: SipMessage, _: Option<&SipAddr>) -> SipMessage {
        message
    }
}

#[async_trait::async_trait]
impl TransportEventInspector for Trace {
    async fn handle(&self, event: TransportEvent) -> Option<TransportEvent> {
        if let TransportEvent::Incoming(message, _, _) = &event {
            self.record("RX", message);
        }
        Some(event)
    }
}

pub struct App {
    pub config: Config,
    pub endpoint: Endpoint,
    pub tasks: Tasks,
    pub calls: Calls,
    pub uri: Uri,
    cancel: CancellationToken,
}

impl App {
    pub async fn start(proxy: bool) -> AppResult<Self> {
        let config = Config::parse()?;
        std::fs::create_dir_all(&config.logs)?;
        let tasks = Tasks {
            handles: Arc::default(),
            errors: Arc::default(),
            events: Arc::new(Mutex::new(File::create(config.logs.join("events.log"))?)),
        };
        let trace = Trace {
            file: Arc::new(Mutex::new(File::create(config.logs.join("sip.frames"))?)),
            tasks: tasks.clone(),
        };
        let cancel = CancellationToken::new();
        let transport = TransportLayer::new(cancel.clone());
        if config.transport == "udp" {
            transport.add_transport(
                UdpConnection::create_connection(config.listen, None, Some(cancel.child_token()))
                    .await?
                    .into(),
            );
        } else {
            transport.add_transport(
                TcpListenerConnection::new(config.listen, None)
                    .await?
                    .into(),
            );
        }
        let endpoint = EndpointBuilder::new()
            .with_user_agent("rsipstack-interop-app")
            .with_cancel_token(cancel.child_token())
            .with_transport_layer(transport)
            .with_option(EndpointOption {
                auto_ack_2xx: !proxy,
                ..Default::default()
            })
            .with_inspector(Box::new(trace.clone()))
            .with_transport_inspector(Box::new(trace))
            .build();
        let uri = format!(
            "sip:interop@{};transport={}",
            config.listen, config.transport
        )
        .parse()?;
        Ok(Self {
            config,
            endpoint,
            tasks,
            calls: Calls::default(),
            uri,
            cancel,
        })
    }

    pub async fn run(self, dialogs: impl Fn() -> usize) -> AppResult {
        let endpoint = self.endpoint.inner.clone();
        self.tasks.spawn("endpoint", async move {
            endpoint.serve().await?;
            Ok(())
        });
        if self.config.transport == "tcp" {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if tokio::net::TcpStream::connect(self.config.listen)
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await?;
        }
        println!("READY {}", self.uri);
        std::io::stdout().flush()?;
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        match lines.next_line().await? {
            Some(line) if line == "quit" => {}
            None => return Err("Control stdin closed before quit".into()),
            Some(line) => return Err(format!("Unknown control command {line}").into()),
        }
        let active_calls = self.calls.len();
        let active_dialogs = dialogs();
        self.cancel.cancel();
        self.tasks.stop().await;
        let errors = self
            .tasks
            .errors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        std::fs::write(
            self.config.logs.join("summary.txt"),
            format!(
                "active_calls={active_calls}\ndialogs={active_dialogs}\nbackground_errors={}\n",
                errors.len()
            ),
        )?;
        if active_calls != 0 || active_dialogs != 0 || !errors.is_empty() {
            return Err(format!("Unclean shutdown: calls={active_calls}, dialogs={active_dialogs}, errors={errors:?}").into());
        }
        Ok(())
    }
}
