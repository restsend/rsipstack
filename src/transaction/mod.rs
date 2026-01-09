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
    pub request: rsip::Request,
    pub connection: SipConnection,
    pub from: SipAddr,
}

pub type TransactionReceiver = UnboundedReceiver<Transaction>;
pub type TransactionSender = UnboundedSender<Transaction>;

/// SIP Transaction State
///
/// `TransactionState` represents the various states a SIP transaction can be in
/// during its lifecycle. These states implement the transaction state machines
/// defined in RFC 3261 for both client and server transactions.
///
/// # States
///
/// * `Nothing` - Initial state for client transactions created
/// * `Calling` - Initial state for client transactions when request is sent or received
/// * `Trying` - Request has been sent/received, waiting for response/processing
/// * `Proceeding` - Provisional response received/sent (1xx except 100 Trying)
/// * `Completed` - Final response received/sent, waiting for ACK (INVITE) or cleanup
/// * `Confirmed` - ACK received/sent for INVITE transactions
/// * `Terminated` - Transaction has completed and is being cleaned up
///
/// # State Transitions
///
/// ## Client Non-INVITE Transaction
/// ```text
/// Nothing → Calling → Trying → Proceeding → Completed → Terminated
/// ```
///
/// ## Client INVITE Transaction  
/// ```text
/// Nothing → Calling → Trying → Proceeding → Completed → Terminated
///                                      ↓
///                                   Confirmed → Terminated
/// ```
///
/// ## Server Transactions
/// ```text
/// Calling → Trying → Proceeding → Completed → Terminated
///                           ↓
///                         Confirmed → Terminated (INVITE only)
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
///     TransactionState::Completed => println!("Final response"),
///     TransactionState::Confirmed => println!("ACK received/sent"),
///     TransactionState::Terminated => println!("Transaction complete"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionState {
    Nothing,
    Calling,
    Trying,
    Proceeding,
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
/// use rsip::Method;
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
/// as defined in RFC 3261. These timers ensure reliable message delivery
/// and proper transaction cleanup.
///
/// # Timer Types
///
/// * `TimerA` - Retransmission timer for client transactions (unreliable transport)
/// * `TimerB` - Transaction timeout timer for client transactions
/// * `TimerD` - Wait timer for response retransmissions (client)
/// * `TimerE` - Retransmission timer for non-INVITE server transactions
/// * `TimerF` - Transaction timeout timer for non-INVITE server transactions
/// * `TimerK` - Wait timer for ACK (server INVITE transactions)
/// * `TimerG` - Retransmission timer for INVITE server transactions
/// * `TimerCleanup` - Internal cleanup timer for transaction removal
///
/// # Timer Values (RFC 3261)
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
/// * Timer G: starts at T1, doubles up to T2
/// * Timer K: T4 for unreliable, 0 for reliable transports
///
/// # Examples
///
/// ```rust
/// use rsipstack::transaction::{TransactionTimer, key::{TransactionKey, TransactionRole}};
/// use std::time::Duration;
///
/// # fn example() -> rsipstack::Result<()> {
/// // Create a mock request to generate a transaction key
/// let request = rsip::Request {
///     method: rsip::Method::Register,
///     uri: rsip::Uri::try_from("sip:example.com")?,
///     headers: vec![
///         rsip::Header::Via("SIP/2.0/UDP example.com:5060;branch=z9hG4bKnashds".into()),
///         rsip::Header::CSeq("1 REGISTER".into()),
///         rsip::Header::From("Alice <sip:alice@example.com>;tag=1928301774".into()),
///         rsip::Header::CallId("a84b4c76e66710@pc33.atlanta.com".into()),
///     ].into(),
///     version: rsip::Version::V2,
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
pub enum TransactionTimer {
    TimerA(TransactionKey, Duration),
    TimerB(TransactionKey),
    TimerC(TransactionKey),
    TimerD(TransactionKey),
    TimerK(TransactionKey),
    TimerG(TransactionKey, Duration),
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
            TransactionTimer::TimerCleanup(key) => write!(f, "TimerCleanup: {}", key),
        }
    }
}

pub fn make_via_branch() -> rsip::Param {
    rsip::Param::Branch(format!("z9hG4bK{}", random_text(BRANCH_LEN)).into())
}

// Global Call-ID generator function pointer (similar to Go's approach)
static MAKE_CALL_ID_GENERATOR: std::sync::RwLock<fn(Option<&str>) -> rsip::headers::CallId> =
    std::sync::RwLock::new(default_make_call_id);

/// Default Call-ID generator implementation
///
/// Generates Call-ID in the format: `<random-22-chars>@<domain>`
fn default_make_call_id(domain: Option<&str>) -> rsip::headers::CallId {
    format!(
        "{}@{}",
        random_text(CALL_ID_LEN),
        domain.unwrap_or("restsend.com")
    )
    .into()
}

/// Set a custom Call-ID generator function
///
/// This allows external projects to override the default Call-ID generation
/// logic globally. The custom generator will be used by all endpoints and
/// registrations.
///
/// # Parameters
///
/// * `generator` - Function that takes an optional domain and returns a Call-ID
///
/// # Examples
///
/// ```rust
/// use rsipstack::transaction::set_make_call_id_generator;
///
/// // Use custom UUID-based Call-ID
/// set_make_call_id_generator(|domain| {
///     format!(
///         "{}@{}",
///         uuid::Uuid::new_v4(),
///         domain.unwrap_or("example.com")
///     )
///     .into()
/// });
/// ```
pub fn set_make_call_id_generator(generator: fn(Option<&str>) -> rsip::headers::CallId) {
    *MAKE_CALL_ID_GENERATOR.write().unwrap() = generator;
}

/// Generate a Call-ID header value
///
/// Uses the configured generator (set via `set_make_call_id_generator`),
/// or the default implementation if no custom generator is set.
///
/// # Parameters
///
/// * `domain` - Optional domain suffix for the Call-ID
///
/// # Returns
///
/// A Call-ID header value
///
/// # Examples
///
/// ```rust
/// use rsipstack::transaction::make_call_id;
///
/// let call_id = make_call_id(Some("example.com"));
/// ```
pub fn make_call_id(domain: Option<&str>) -> rsip::headers::CallId {
    let generator = MAKE_CALL_ID_GENERATOR.read().unwrap();
    generator(domain)
}

pub fn make_tag() -> rsip::param::Tag {
    random_text(TO_TAG_LEN).into()
}

#[cfg(not(target_family = "wasm"))]
pub fn random_text(count: usize) -> String {
    use rand::Rng;
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
