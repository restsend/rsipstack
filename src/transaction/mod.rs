use crate::transport::{SipAddr, SipConnection};
use key::TransactionKey;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use transaction::Transaction;

pub mod endpoint;
pub mod key;
pub mod message;
mod timer;
pub mod transaction;
pub use endpoint::Endpoint;
pub use endpoint::EndpointBuilder;
#[cfg(test)]
mod tests;

pub const TO_TAG_LEN: usize = 8;
pub const BRANCH_LEN: usize = 12;
pub const CNONCE_LEN: usize = 8;
pub const CALL_ID_LEN: usize = 22;
pub struct IncomingRequest {
    pub request: crate::sip::Request,
    pub connection: SipConnection,
    pub from: SipAddr,
}

pub type TransactionReceiver = UnboundedReceiver<Transaction>;
pub type TransactionSender = UnboundedSender<Transaction>;

/// SIP Transaction State
///
/// `TransactionState` represents the various states a SIP transaction can be in
/// during its lifecycle. These states implement the transaction state machines
/// defined in RFC 3261 for both client and server transactions, with the RFC 6026
/// `Accepted` state for INVITE 2xx response handling.
///
/// # States
///
/// * `Nothing` - Initial state for client transactions created
/// * `Calling` - Initial state for client transactions when request is sent or received
/// * `Trying` - Request has been sent/received, waiting for response/processing
/// * `Proceeding` - Provisional response received/sent (1xx except 100 Trying)
/// * `Accepted` - INVITE transaction received/sent a 2xx final response (RFC 6026 §7.1/§7.2);
///   server transaction waits for ACKs and absorbs 2xx retransmissions from the TU until
///   Timer L fires; client transaction absorbs 2xx retransmissions from the server until
///   Timer M fires.
/// * `Completed` - Final non-2xx response received/sent (RFC 3261 §17), waiting for ACK (server INVITE)
///   or response retransmissions (client). For INVITE 2xx, see `Accepted` (RFC 6026 supersedes RFC 3261 §17.2.1 paragraph 4 / §17.1.1.2).
/// * `Confirmed` - ACK received/sent for INVITE non-2xx (3xx-6xx) transactions
/// * `Terminated` - Transaction has completed and is being cleaned up
///
/// # State Transitions
///
/// ## Client Non-INVITE Transaction (RFC 3261 §17.1.2)
/// ```text
/// Nothing → Calling → Trying → Proceeding → Completed → Terminated
/// ```
///
/// ## Client INVITE Transaction (RFC 3261 §17.1.1 + RFC 6026 §7.2)
/// ```text
/// Nothing → Calling → Trying → Proceeding ──2xx──→ Accepted ──Timer M──→ Terminated
///                                       │
///                                       └──3xx-6xx──→ Completed → Confirmed → Terminated
/// ```
///
/// ## Server INVITE Transaction (RFC 3261 §17.2.1 + RFC 6026 §7.1)
/// ```text
/// Calling → Trying → Proceeding ──2xx──→ Accepted ──Timer L──→ Terminated
///                              │
///                              └──3xx-6xx──→ Completed ──ACK──→ Confirmed → Terminated
/// ```
///
/// ## Server Non-INVITE Transaction (RFC 3261 §17.2.2)
/// ```text
/// Calling → Trying → Proceeding → Completed → Terminated
/// ```
///
/// # Examples
///
/// ```rust
/// use rsipstack::transaction::TransactionState;
///
/// let state = TransactionState::Proceeding;
/// match state {
///     TransactionState::Nothing => println!("Transaction starting"),
///     TransactionState::Calling => println!("Request sent"),
///     TransactionState::Trying => println!("Request sent/received"),
///     TransactionState::Proceeding => println!("Provisional response"),
///     TransactionState::Accepted => println!("2xx accepted; waiting for Timer L/M"),
///     TransactionState::Completed => println!("Final non-2xx response"),
///     TransactionState::Confirmed => println!("ACK received/sent"),
///     TransactionState::Terminated => println!("Transaction complete"),
///     // `#[non_exhaustive]`: downstream code MUST keep a wildcard arm to
///     // remain forward-compatible with future state additions.
///     _ => println!("future RFC-extension state"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TransactionState {
    Nothing,
    Calling,
    Trying,
    Proceeding,
    /// RFC 6026 §7.1 (server) / §7.2 (client): an INVITE transaction has sent or received
    /// a 2xx final response. The server absorbs 2xx retransmissions from the TU and waits
    /// for ACK until Timer L (= 64*T1) fires; the client absorbs server-retransmitted 2xx
    /// responses until Timer M (= 64*T1) fires. Replaces the RFC 3261 §17.1.1.2 / §17.2.1
    /// behaviour that incorrectly routed 2xx through the `Completed` state.
    Accepted,
    Completed,
    Confirmed,
    Terminated,
}

impl std::fmt::Display for TransactionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionState::Nothing => write!(f, "Nothing"),
            TransactionState::Calling => write!(f, "Calling"),
            TransactionState::Trying => write!(f, "Trying"),
            TransactionState::Proceeding => write!(f, "Proceeding"),
            TransactionState::Accepted => write!(f, "Accepted"),
            TransactionState::Completed => write!(f, "Completed"),
            TransactionState::Confirmed => write!(f, "Confirmed"),
            TransactionState::Terminated => write!(f, "Terminated"),
        }
    }
}
/// SIP Transaction Type
///
/// `TransactionType` distinguishes between the four types of SIP transactions
/// as defined in RFC 3261. Each type has different behavior for retransmissions,
/// timers, and state transitions.
///
/// # Types
///
/// * `ClientInvite` - Client-side INVITE transaction (UAC INVITE)
/// * `ClientNonInvite` - Client-side non-INVITE transaction (UAC non-INVITE)
/// * `ServerInvite` - Server-side INVITE transaction (UAS INVITE)
/// * `ServerNonInvite` - Server-side non-INVITE transaction (UAS non-INVITE)
///
/// # Characteristics
///
/// ## Client INVITE
/// * Longer timeouts due to human interaction
/// * ACK handling for 2xx responses
/// * CANCEL support for early termination
///
/// ## Client Non-INVITE
/// * Shorter timeouts for automated responses
/// * No ACK required
/// * Simpler state machine
///
/// ## Server INVITE
/// * Must handle ACK for final responses
/// * Supports provisional responses
/// * Complex retransmission rules
///
/// ## Server Non-INVITE
/// * Simple request/response pattern
/// * No ACK handling
/// * Faster completion
///
/// # Examples
///
/// ```rust
/// use rsipstack::transaction::TransactionType;
/// use rsipstack::sip::Method;
///
/// fn get_transaction_type(method: &Method, is_client: bool) -> TransactionType {
///     match (method, is_client) {
///         (Method::Invite, true) => TransactionType::ClientInvite,
///         (Method::Invite, false) => TransactionType::ServerInvite,
///         (_, true) => TransactionType::ClientNonInvite,
///         (_, false) => TransactionType::ServerNonInvite,
///     }
/// }
/// ```
#[derive(Debug, PartialEq)]
pub enum TransactionType {
    ClientInvite,
    ClientNonInvite,
    ServerInvite,
    ServerNonInvite,
}
impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionType::ClientInvite => write!(f, "ClientInvite"),
            TransactionType::ClientNonInvite => write!(f, "ClientNonInvite"),
            TransactionType::ServerInvite => write!(f, "ServerInvite"),
            TransactionType::ServerNonInvite => write!(f, "ServerNonInvite"),
        }
    }
}
/// SIP Transaction Timers
///
/// `TransactionTimer` represents the various timers used in SIP transactions
/// as defined in RFC 3261 and RFC 6026. These timers ensure reliable message
/// delivery and proper transaction cleanup.
///
/// # Timer Types
///
/// * `TimerA` - Retransmission timer for client transactions (unreliable transport)
/// * `TimerB` - Transaction timeout timer for client transactions
/// * `TimerC` - Proceeding timeout for client INVITE
/// * `TimerD` - Wait timer for response retransmissions (client)
/// * `TimerK` - Wait timer for ACK (server INVITE non-2xx) / cleanup (client non-INVITE)
/// * `TimerG` - Retransmission timer for INVITE server transactions (non-2xx only per RFC 6026 §7.1)
/// * `TimerL` - RFC 6026 §7.1 server INVITE Accepted-state timer (64*T1)
/// * `TimerM` - RFC 6026 §7.2 client INVITE Accepted-state timer (64*T1)
/// * `TimerCleanup` - Internal cleanup timer for transaction removal
///
/// # Timer Values (RFC 3261 + RFC 6026)
///
/// * T1 = 500ms (RTT estimate)
/// * T2 = 4s (maximum retransmit interval)
/// * T4 = 5s (maximum duration a message will remain in the network)
///
/// ## Timer Calculations
/// * Timer A: starts at T1, doubles each retransmission up to T2
/// * Timer B: 64*T1 (32 seconds)
/// * Timer D: 32 seconds for unreliable, 0 for reliable transports
/// * Timer E: starts at T1, doubles up to T2
/// * Timer F: 64*T1 (32 seconds)
/// * Timer G: starts at T1, doubles up to T2 (non-2xx final response retransmits only)
/// * Timer K: T4 for unreliable, 0 for reliable transports
/// * **Timer L: 64*T1 (32 seconds) — RFC 6026 §7.1**
/// * **Timer M: 64*T1 (32 seconds) — RFC 6026 §7.2**
///
/// # Examples
///
/// ```rust
/// use rsipstack::transaction::{TransactionTimer, key::{TransactionKey, TransactionRole}};
/// use std::time::Duration;
///
/// # fn example() -> rsipstack::Result<()> {
/// // Create a mock request to generate a transaction key
/// let request = rsipstack::sip::Request {
///     method: rsipstack::sip::Method::Register,
///     uri: rsipstack::sip::Uri::try_from("sip:example.com")?,
///     headers: vec![
///         rsipstack::sip::Header::Via("SIP/2.0/UDP example.com:5060;branch=z9hG4bKnashds".into()),
///         rsipstack::sip::Header::CSeq("1 REGISTER".into()),
///         rsipstack::sip::Header::From("Alice <sip:alice@example.com>;tag=1928301774".into()),
///         rsipstack::sip::Header::CallId("a84b4c76e66710@pc33.atlanta.com".into()),
///     ].into(),
///     version: rsipstack::sip::Version::V2,
///     body: Default::default(),
/// };
/// let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
///
/// let timer = TransactionTimer::TimerA(key.clone(), Duration::from_millis(500));
/// match timer {
///     TransactionTimer::TimerA(key, duration) => {
///         println!("Timer A fired for transaction {}", key);
///     },
///     TransactionTimer::TimerB(key) => {
///         println!("Transaction {} timed out", key);
///     },
///     // `#[non_exhaustive]`: downstream code MUST keep a wildcard arm to
///     // remain forward-compatible with future timer additions (e.g. RFC
///     // extensions like Timer L / Timer M / future RFC variants).
///     _ => {}
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Usage
///
/// Timers are automatically managed by the transaction layer:
/// * Started when entering appropriate states
/// * Cancelled when leaving states or receiving responses
/// * Fire events that drive state machine transitions
/// * Handle retransmissions and timeouts
#[non_exhaustive]
pub enum TransactionTimer {
    TimerA(TransactionKey, Duration),
    TimerB(TransactionKey),
    TimerC(TransactionKey),
    TimerD(TransactionKey),
    TimerK(TransactionKey),
    TimerG(TransactionKey, Duration),
    /// RFC 6026 §7.1: server INVITE Accepted-state timer. Fires once at 64*T1
    /// after a 2xx final response is sent, then transitions the transaction to
    /// Terminated. Absorbs ACKs for the 2xx and late 2xx retransmissions from
    /// the TU. Replaces the RFC 3261 §17.2.1 Timer K (T4) usage for 2xx
    /// responses, which was too short to handle proxy-chain ACK fan-in.
    TimerL(TransactionKey),
    /// RFC 6026 §7.2: client INVITE Accepted-state timer. Fires once at 64*T1
    /// after a 2xx final response is received, then transitions the
    /// transaction to Terminated. Absorbs server-retransmitted 2xx responses
    /// (the TU is responsible for the ACK).
    TimerM(TransactionKey),
    TimerCleanup(TransactionKey),
}

impl TransactionTimer {
    pub fn key(&self) -> &TransactionKey {
        match self {
            TransactionTimer::TimerA(key, _) => key,
            TransactionTimer::TimerB(key) => key,
            TransactionTimer::TimerC(key) => key,
            TransactionTimer::TimerD(key) => key,
            TransactionTimer::TimerG(key, _) => key,
            TransactionTimer::TimerK(key) => key,
            TransactionTimer::TimerL(key) => key,
            TransactionTimer::TimerM(key) => key,
            TransactionTimer::TimerCleanup(key) => key,
        }
    }
}

impl std::fmt::Display for TransactionTimer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionTimer::TimerA(key, duration) => {
                write!(f, "TimerA: {} {}", key, duration.as_millis())
            }
            TransactionTimer::TimerB(key) => write!(f, "TimerB: {}", key),
            TransactionTimer::TimerC(key) => write!(f, "TimerC: {}", key),
            TransactionTimer::TimerD(key) => write!(f, "TimerD: {}", key),
            TransactionTimer::TimerG(key, duration) => {
                write!(f, "TimerG: {} {}", key, duration.as_millis())
            }
            TransactionTimer::TimerK(key) => write!(f, "TimerK: {}", key),
            TransactionTimer::TimerL(key) => write!(f, "TimerL: {}", key),
            TransactionTimer::TimerM(key) => write!(f, "TimerM: {}", key),
            TransactionTimer::TimerCleanup(key) => write!(f, "TimerCleanup: {}", key),
        }
    }
}

pub fn make_via_branch() -> crate::sip::Param {
    crate::sip::Param::Branch(format!("z9hG4bK{}", random_text(BRANCH_LEN)).into())
}

pub fn make_call_id(domain: Option<&str>) -> crate::sip::headers::CallId {
    format!(
        "{}@{}",
        random_text(CALL_ID_LEN),
        domain.unwrap_or("restsend.com")
    )
    .into()
}

pub fn make_tag() -> crate::sip::param::Tag {
    random_text(TO_TAG_LEN).into()
}

#[cfg(not(target_family = "wasm"))]
pub fn random_text(count: usize) -> String {
    use rand::RngExt;
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(count)
        .map(char::from)
        .collect::<String>()
}

#[cfg(target_family = "wasm")]
pub fn random_text(count: usize) -> String {
    (0..count)
        .map(|_| {
            let r = js_sys::Math::random();
            let c = (r * 16.0) as u8;
            if c < 10 {
                (c + 48) as char
            } else {
                (c + 87) as char
            }
        })
        .collect()
}
