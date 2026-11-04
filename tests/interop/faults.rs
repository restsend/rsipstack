//! Deterministic faults at the real UDP socket boundary. No SIP header rewriting.
use super::{bounded, until, Diagnostics, Failure, Required, TestResult};
use rsipstack::{
    platform::net::UdpSocket as PlatformSocket,
    sip::{prelude::HeadersExt, Method, SipMessage},
};
use std::{
    fs::File,
    io::Write,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, Mutex as AsyncMutex},
    task::JoinHandle,
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Send,
    Receive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Drop,
    /// A network delay: the local send completes before the datagram is delivered.
    Delay(u64),
    /// Hold a datagram until the driver releases this rule; other traffic continues.
    Hold,
    /// Hold a send AND its completion, to exercise application/transport races.
    BlockSend,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub direction: Direction,
    pub method: Method,
    pub status: Option<u16>,
    pub occurrence: usize,
    pub action: Action,
}

impl Rule {
    pub fn new(
        id: &str,
        direction: Direction,
        method: Method,
        status: Option<u16>,
        occurrence: usize,
        action: Action,
    ) -> Self {
        Self {
            id: id.into(),
            direction,
            method,
            status,
            occurrence,
            action,
        }
    }
}

#[derive(Clone)]
pub struct Trace {
    pub packet_id: usize,
    pub phase: &'static str,
    pub direction: Direction,
    pub message: Option<SipMessage>,
    pub rule: Option<String>,
}

struct Journal {
    events: File,
    packets: File,
    traces: Vec<Trace>,
    applied: Vec<bool>,
    pending: usize,
    start: Instant,
}

#[derive(Clone)]
pub struct Control {
    commands: mpsc::UnboundedSender<Command>,
    journal: Arc<Mutex<Journal>>,
    rules: Arc<Vec<Rule>>,
    errors: Diagnostics,
}

impl Control {
    pub fn traces(&self) -> Vec<Trace> {
        self.journal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .traces
            .clone()
    }

    pub async fn applied(&self, id: &str) -> TestResult {
        check!(
            self.rules.iter().any(|r| r.id == id),
            "Unknown fault rule {id}"
        );
        until(&format!("fault rule {id}"), || {
            self.traces()
                .iter()
                .any(|t| {
                    t.rule.as_deref() == Some(id)
                        && matches!(t.phase, "drop" | "hold" | "delay" | "block_send")
                })
                .then_some(())
        })
        .await
    }

    pub async fn release(&self, id: &str) -> TestResult {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Release(id.into(), reply))
            .required()?;
        bounded("fault gate release", result).await?.required()?
    }

    pub async fn check_retransmissions(&self) -> TestResult {
        let traces = self.traces();
        for dropped in traces.iter().filter(|t| t.phase == "drop") {
            let original = dropped.message.as_ref().required()?;
            let (method, headers) = match original {
                SipMessage::Request(r) => (r.method, &r.headers),
                SipMessage::Response(r) => {
                    (r.cseq_header().required()?.method().required()?, &r.headers)
                }
            };
            let retry = until("retransmission after injected packet loss", || {
                self.traces().into_iter().find(|t| {
                    t.packet_id > dropped.packet_id
                        && t.direction == dropped.direction
                        && t.phase == "delivered"
                        && t.message
                            .as_ref()
                            .is_some_and(|message| match (original, message) {
                                (SipMessage::Request(a), SipMessage::Request(b)) => {
                                    a.method == b.method
                                        && a.cseq_header().ok() == b.cseq_header().ok()
                                        && a.call_id_header().ok() == b.call_id_header().ok()
                                }
                                (SipMessage::Response(a), SipMessage::Response(b)) => {
                                    a.status_code == b.status_code
                                        && a.cseq_header().ok() == b.cseq_header().ok()
                                        && a.call_id_header().ok() == b.call_id_header().ok()
                                }
                                _ => false,
                            })
                })
            })
            .await?;
            let retry_headers = match retry.message.as_ref().required()? {
                SipMessage::Request(r) => &r.headers,
                SipMessage::Response(r) => &r.headers,
            };
            // ACKs to repeated 2xx may use a fresh Via branch. Other retries
            // must remain the same transaction, including Via and dialog tags.
            for name in ["From", "To", "CSeq", "Call-ID", "Via"] {
                if name == "Via" && method == Method::Ack {
                    continue;
                }
                let values = |h: &rsipstack::sip::Headers| {
                    h.iter()
                        .filter(|v| v.name().eq_ignore_ascii_case(name))
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                };
                check_eq!(
                    values(headers),
                    values(retry_headers),
                    "Retry changed {name}"
                );
            }
        }
        Ok(())
    }

    pub fn check(&self) -> TestResult {
        self.errors.check()?;
        let journal = self.journal.lock().unwrap_or_else(|p| p.into_inner());
        for (rule, applied) in self.rules.iter().zip(&journal.applied) {
            check!(
                *applied,
                "Fault rule {} never fired; the scenario did not exercise the requested fault",
                rule.id
            );
        }
        check_eq!(journal.pending, 0, "Fault datagrams remain pending");
        Ok(())
    }
}

struct Datagram {
    id: usize,
    bytes: Vec<u8>,
    addr: SocketAddr,
    direction: Direction,
    message: Option<SipMessage>,
}

struct Pending {
    packet: Datagram,
    rule: usize,
    deadline: Option<Instant>,
    completion: Option<oneshot::Sender<rsipstack::Result<usize>>>,
}

enum Command {
    Send(
        Vec<u8>,
        SocketAddr,
        oneshot::Sender<rsipstack::Result<usize>>,
    ),
    Release(String, oneshot::Sender<TestResult>),
}

pub struct FaultSocket {
    addr: SocketAddr,
    commands: mpsc::UnboundedSender<Command>,
    received: AsyncMutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
}

fn stopped() -> rsipstack::Error {
    rsipstack::Error::Error("Fault socket stopped; inspect background-errors.log".into())
}

#[async_trait::async_trait]
impl PlatformSocket for FaultSocket {
    fn local_addr(&self) -> rsipstack::Result<SocketAddr> {
        Ok(self.addr)
    }

    async fn send_to(&self, bytes: &[u8], addr: SocketAddr) -> rsipstack::Result<usize> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Send(bytes.to_vec(), addr, reply))
            .map_err(|_| stopped())?;
        result.await.map_err(|_| stopped())?
    }

    async fn recv_from(&self, buf: &mut [u8]) -> rsipstack::Result<(usize, SocketAddr)> {
        let (bytes, addr) = self
            .received
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(stopped)?;
        if bytes.len() > buf.len() {
            return Err(rsipstack::Error::Error(
                "Fault socket receive buffer too small".into(),
            ));
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), addr))
    }
}

/// Plans can be replayed against one selected test through RSIPSTACK_FAULT_PLAN.
fn plan(dir: &Path, defaults: Vec<Rule>) -> TestResult<Vec<Rule>> {
    let rules = if let Some(path) = std::env::var_os("RSIPSTACK_FAULT_PLAN") {
        decode_plan(&std::fs::read_to_string(path).required()?)?
    } else {
        defaults
    };
    validate(&rules)?;
    let mut text = String::from(
        "# id\tdirection\tmethod\tstatus-or-request\toccurrence\taction\tmilliseconds\n",
    );
    for r in &rules {
        let (action, ms) = match r.action {
            Action::Drop => ("drop", 0),
            Action::Delay(ms) => ("delay", ms),
            Action::Hold => ("hold", 0),
            Action::BlockSend => ("block_send", 0),
        };
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{action}\t{ms}\n",
            r.id,
            if r.direction == Direction::Send {
                "send"
            } else {
                "receive"
            },
            r.method,
            r.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "request".into()),
            r.occurrence
        ));
    }
    std::fs::write(dir.join("fault-plan.tsv"), text).required()?;
    Ok(rules)
}

fn decode_plan(text: &str) -> TestResult<Vec<Rule>> {
    let mut rules = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<_> = line.split('\t').collect();
        check_eq!(fields.len(), 7, "Invalid fault-plan row");
        let direction = match fields[1] {
            "send" => Direction::Send,
            "receive" => Direction::Receive,
            _ => return Err(Failure("Invalid fault direction".into())),
        };
        let ms: u64 = fields[6].parse().required()?;
        let action = match fields[5] {
            "drop" if ms == 0 => Action::Drop,
            "hold" if ms == 0 => Action::Hold,
            "block_send" if ms == 0 => Action::BlockSend,
            "delay" => Action::Delay(ms),
            _ => return Err(Failure("Invalid fault action or delay".into())),
        };
        rules.push(Rule::new(
            fields[0],
            direction,
            fields[2].parse().required()?,
            if fields[3] == "request" {
                None
            } else {
                Some(fields[3].parse().required()?)
            },
            fields[4].parse().required()?,
            action,
        ));
    }
    validate(&rules)?;
    Ok(rules)
}

fn validate(rules: &[Rule]) -> TestResult {
    check!(rules.len() <= 64, "At most 64 fault rules are allowed");
    for (i, r) in rules.iter().enumerate() {
        check!(
            !r.id.is_empty() && r.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "Invalid fault rule id"
        );
        check!(r.occurrence > 0, "Fault occurrence starts at 1");
        check!(
            r.status.is_none_or(|s| (100..=699).contains(&s)),
            "Invalid SIP status in fault plan"
        );
        check!(
            r.action != Action::BlockSend || r.direction == Direction::Send,
            "block_send requires the send direction"
        );
        if let Action::Delay(ms) = r.action {
            check!((1..=10_000).contains(&ms), "Delay must be 1..10000 ms");
        }
        for other in &rules[..i] {
            check!(r.id != other.id, "Duplicate fault id {}", r.id);
            check!(
                !(r.direction == other.direction
                    && r.method == other.method
                    && r.status == other.status
                    && r.occurrence == other.occurrence),
                "Overlapping fault rules {} and {}",
                r.id,
                other.id
            );
        }
    }
    Ok(())
}

struct Pump {
    socket: UdpSocket,
    control: Control,
    received: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    counters: Vec<usize>,
    pending: Vec<Pending>,
    next_id: usize,
}

impl Pump {
    fn record(&self, packet: &Datagram, phase: &'static str, rule: Option<usize>) -> TestResult {
        let mut journal = self
            .control
            .journal
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let elapsed = journal.start.elapsed().as_micros();
        let rule = rule.map(|i| self.control.rules[i].id.clone());
        writeln!(
            journal.events,
            "{elapsed}\t{}\t{:?}\t{phase}\t{}\t{}\t{}",
            packet.id,
            packet.direction,
            rule.as_deref().unwrap_or("-"),
            packet.addr,
            packet.bytes.len()
        )
        .required()?;
        if phase == "observed" {
            writeln!(
                journal.packets,
                "packet={} {:?} peer={}\n{}\n",
                packet.id,
                packet.direction,
                packet.addr,
                String::from_utf8_lossy(&packet.bytes)
            )
            .required()?;
        }
        journal.traces.push(Trace {
            packet_id: packet.id,
            phase,
            direction: packet.direction,
            message: packet.message.clone(),
            rule,
        });
        Ok(())
    }

    async fn forward(
        &self,
        packet: Datagram,
        rule: Option<usize>,
        completion: Option<oneshot::Sender<rsipstack::Result<usize>>>,
    ) -> TestResult {
        if completion.as_ref().is_some_and(|c| c.is_closed()) {
            self.record(&packet, "send_cancelled", rule)?;
            return Ok(());
        }
        if packet.direction == Direction::Send {
            let len = self
                .socket
                .send_to(&packet.bytes, packet.addr)
                .await
                .required()?;
            check_eq!(len, packet.bytes.len(), "Partial UDP send");
        } else {
            self.received
                .send((packet.bytes.clone(), packet.addr))
                .required()?;
        }
        self.record(&packet, "delivered", rule)?;
        if let Some(reply) = completion {
            let _ = reply.send(Ok(packet.bytes.len()));
        }
        Ok(())
    }

    async fn packet(
        &mut self,
        bytes: Vec<u8>,
        addr: SocketAddr,
        direction: Direction,
        completion: Option<oneshot::Sender<rsipstack::Result<usize>>>,
    ) -> TestResult {
        self.next_id += 1;
        let message = SipMessage::try_from(bytes.as_slice()).ok();
        let packet = Datagram {
            id: self.next_id,
            bytes,
            addr,
            direction,
            message,
        };
        self.record(&packet, "observed", None)?;
        let identity = match &packet.message {
            Some(SipMessage::Request(r)) => Some((r.method, None)),
            Some(SipMessage::Response(r)) => Some((
                r.cseq_header().required()?.method().required()?,
                Some(r.status_code.code()),
            )),
            None => None, // Non-SIP datagrams (e.g. CRLF keepalives) pass unchanged.
        };
        let mut matched = None;
        for (i, r) in self.control.rules.iter().enumerate() {
            if direction == r.direction && identity == Some((r.method, r.status)) {
                self.counters[i] += 1;
                if self.counters[i] == r.occurrence {
                    matched = Some(i);
                }
            }
        }
        let Some(rule) = matched else {
            return self.forward(packet, None, completion).await;
        };
        self.control
            .journal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .applied[rule] = true;
        let action = self.control.rules[rule].action.clone();
        if action == Action::Drop {
            self.record(&packet, "drop", Some(rule))?;
            if let Some(reply) = completion {
                let _ = reply.send(Ok(packet.bytes.len()));
            }
            return Ok(());
        }
        let phase = match action {
            Action::Delay(_) => "delay",
            Action::BlockSend => "block_send",
            _ => "hold",
        };
        self.record(&packet, phase, Some(rule))?;
        let completion = if action == Action::BlockSend {
            completion
        } else {
            if let Some(reply) = completion {
                let _ = reply.send(Ok(packet.bytes.len()));
            }
            None
        };
        let deadline = if let Action::Delay(ms) = action {
            Some(Instant::now() + Duration::from_millis(ms))
        } else {
            None
        };
        self.pending.push(Pending {
            packet,
            rule,
            deadline,
            completion,
        });
        self.control
            .journal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending = self.pending.len();
        Ok(())
    }

    async fn release(&mut self, index: usize) -> TestResult {
        let pending = self.pending.remove(index);
        self.record(&pending.packet, "released", Some(pending.rule))?;
        self.forward(pending.packet, Some(pending.rule), pending.completion)
            .await?;
        self.control
            .journal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending = self.pending.len();
        Ok(())
    }

    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) -> TestResult {
        let mut buf = [0; 65535];
        loop {
            let deadline = self.pending.iter().filter_map(|p| p.deadline).min();
            tokio::select! {
                packet = self.socket.recv_from(&mut buf) => {
                    let (len, addr) = packet.required()?;
                    self.packet(buf[..len].to_vec(), addr, Direction::Receive, None).await?;
                }
                command = commands.recv() => {
                    match command.required()? {
                        Command::Send(bytes, addr, reply) => self.packet(bytes, addr, Direction::Send, Some(reply)).await?,
                        Command::Release(id, reply) => {
                            if let Some(i) = self.pending.iter().position(|p| self.control.rules[p.rule].id == id && p.deadline.is_none()) {
                                self.release(i).await?;
                                let _ = reply.send(Ok(()));
                            } else { let _ = reply.send(Err(Failure(format!("No held packet for rule {id}")))); }
                        }
                    }
                }
                () = async { if let Some(t) = deadline { tokio::time::sleep_until(t).await; } else { std::future::pending::<()>().await; } } => {
                    while let Some(i) = self.pending.iter().position(|p| p.deadline.is_some_and(|t| t <= Instant::now())) { self.release(i).await?; }
                }
            }
        }
    }
}

pub async fn socket(
    dir: &Path,
    defaults: Vec<Rule>,
    errors: Diagnostics,
) -> TestResult<(Arc<FaultSocket>, Control, JoinHandle<()>)> {
    let rules = Arc::new(plan(dir, defaults)?);
    let socket = UdpSocket::bind("127.0.0.1:0").await.required()?;
    let addr = socket.local_addr().required()?;
    let (commands, receiver) = mpsc::unbounded_channel();
    let (received, incoming) = mpsc::unbounded_channel();
    let journal = Arc::new(Mutex::new(Journal {
        events: File::create(dir.join("fault-events.tsv")).required()?,
        packets: File::create(dir.join("fault-packets.log")).required()?,
        traces: Vec::new(),
        applied: vec![false; rules.len()],
        pending: 0,
        start: Instant::now(),
    }));
    let control = Control {
        commands: commands.clone(),
        journal,
        rules: rules.clone(),
        errors: errors.clone(),
    };
    let pump = Pump {
        socket,
        control: control.clone(),
        received,
        counters: vec![0; rules.len()],
        pending: Vec::new(),
        next_id: 0,
    };
    let task = errors.spawn("UDP fault pump", pump.run(receiver));
    Ok((
        Arc::new(FaultSocket {
            addr,
            commands,
            received: AsyncMutex::new(incoming),
        }),
        control,
        task,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str) -> Vec<u8> {
        format!("{method} sip:peer@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test\r\nFrom: <sip:a@localhost>;tag=a\r\nTo: <sip:b@localhost>;tag=b\r\nCall-ID: fault-fixture-test\r\nCSeq: 1 {method}\r\nContent-Length: 0\r\n\r\n").into_bytes()
    }

    async fn outbound_gate(action: Action) -> TestResult {
        let dir = tempfile::tempdir().required()?;
        let (socket, control, task) = socket(
            dir.path(),
            vec![Rule::new(
                "ack",
                Direction::Send,
                Method::Ack,
                None,
                1,
                action.clone(),
            )],
            Diagnostics::new(dir.path())?,
        )
        .await?;
        let peer = UdpSocket::bind("127.0.0.1:0").await.required()?;
        let addr = peer.local_addr().required()?;
        let sender = socket.clone();
        let mut ack = tokio::spawn(async move { sender.send_to(&request("ACK"), addr).await });
        control.applied("ack").await?;
        if action == Action::BlockSend {
            check!(!ack.is_finished(), "BlockSend returned before release");
        } else {
            bounded("Hold must complete the local send", &mut ack)
                .await?
                .required()?
                .required()?;
        }
        bounded(
            "Unrelated send while ACK is held",
            socket.send_to(&request("BYE"), addr),
        )
        .await?
        .required()?;
        let mut buf = [0; 2048];
        let (len, _) = bounded("BYE bypassing held ACK", peer.recv_from(&mut buf))
            .await?
            .required()?;
        check_eq!(&buf[..len], request("BYE"));
        control.release("ack").await?;
        let (len, _) = bounded("released ACK", peer.recv_from(&mut buf))
            .await?
            .required()?;
        check_eq!(&buf[..len], request("ACK"));
        if action == Action::BlockSend {
            bounded("released send completion", ack)
                .await?
                .required()?
                .required()?;
        }
        control.check()?;
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn network_hold_does_not_block_send_or_other_traffic() -> TestResult {
        outbound_gate(Action::Hold).await
    }

    #[tokio::test]
    async fn blocked_send_keeps_other_traffic_flowing() -> TestResult {
        outbound_gate(Action::BlockSend).await
    }

    #[tokio::test]
    async fn incoming_hold_reorders_actual_datagrams() -> TestResult {
        let dir = tempfile::tempdir().required()?;
        let (socket, control, task) = socket(
            dir.path(),
            vec![Rule::new(
                "ack",
                Direction::Receive,
                Method::Ack,
                None,
                1,
                Action::Hold,
            )],
            Diagnostics::new(dir.path())?,
        )
        .await?;
        let peer = UdpSocket::bind("127.0.0.1:0").await.required()?;
        peer.send_to(&request("ACK"), socket.addr)
            .await
            .required()?;
        control.applied("ack").await?;
        peer.send_to(&request("BYE"), socket.addr)
            .await
            .required()?;
        let mut buf = [0; 2048];
        let (len, _) = bounded("incoming BYE bypassing ACK", socket.recv_from(&mut buf))
            .await?
            .required()?;
        check_eq!(&buf[..len], request("BYE"));
        control.release("ack").await?;
        let (len, _) = bounded("released incoming ACK", socket.recv_from(&mut buf))
            .await?
            .required()?;
        check_eq!(&buf[..len], request("ACK"));
        control.check()?;
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn delay_does_not_deliver_before_its_deadline() -> TestResult {
        let dir = tempfile::tempdir().required()?;
        let (socket, control, task) = socket(
            dir.path(),
            vec![Rule::new(
                "ack",
                Direction::Send,
                Method::Ack,
                None,
                1,
                Action::Delay(50),
            )],
            Diagnostics::new(dir.path())?,
        )
        .await?;
        let peer = UdpSocket::bind("127.0.0.1:0").await.required()?;
        let start = Instant::now();
        bounded(
            "queued send",
            socket.send_to(&request("ACK"), peer.local_addr().required()?),
        )
        .await?
        .required()?;
        let mut buf = [0; 2048];
        let (len, _) = bounded("delayed ACK", peer.recv_from(&mut buf))
            .await?
            .required()?;
        check_eq!(&buf[..len], request("ACK"));
        check!(start.elapsed() >= Duration::from_millis(50));
        control.check()?;
        // The emitted plan must be accepted unchanged for later replay.
        let saved =
            decode_plan(&std::fs::read_to_string(dir.path().join("fault-plan.tsv")).required()?)?;
        check_eq!(format!("{saved:?}"), format!("{:?}", control.rules));
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn unapplied_fault_cannot_pass() -> TestResult {
        let dir = tempfile::tempdir().required()?;
        let (_, control, task) = socket(
            dir.path(),
            vec![Rule::new(
                "missing",
                Direction::Send,
                Method::Ack,
                None,
                1,
                Action::Drop,
            )],
            Diagnostics::new(dir.path())?,
        )
        .await?;
        check!(control.check().is_err());
        check!(control.release("missing").await.is_err());
        task.abort();
        Ok(())
    }

    #[test]
    fn invalid_and_ambiguous_plans_are_rejected() -> TestResult {
        for text in [
            "broken",
            "a\tsend\tACK\trequest\t0\tdrop\t0",
            "a\treceive\tACK\trequest\t1\tblock_send\t0",
            "a\tsend\tACK\trequest\t1\tdelay\t10001",
            "a\tsend\tACK\trequest\t1\tdrop\t0\nb\tsend\tACK\trequest\t1\thold\t0",
        ] {
            check!(decode_plan(text).is_err(), "Invalid plan accepted: {text}");
        }
        Ok(())
    }
}
