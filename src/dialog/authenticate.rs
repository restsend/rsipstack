use super::DialogId;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transaction::{make_via_branch, random_text, CNONCE_LEN};
use crate::Result;
use rsip::headers::auth::{AuthQop, Qop};
use rsip::prelude::{HasHeaders, HeadersExt, ToTypedHeader};
use rsip::services::DigestGenerator;
use rsip::typed::{Authorization, ProxyAuthorization};
use rsip::{Header, Param, Response};

/// SIP Authentication Credentials
///
/// `Credential` contains the authentication information needed for SIP
/// digest authentication. This is used when a SIP server challenges
/// a request with a 401 Unauthorized or 407 Proxy Authentication Required
/// response.
///
/// # Fields
///
/// * `username` - The username for authentication
/// * `password` - The password for authentication
/// * `realm` - Optional authentication realm (extracted from challenge)
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust,no_run
/// # use rsipstack::dialog::authenticate::Credential;
/// # fn example() -> rsipstack::Result<()> {
/// let credential = Credential {
///     username: "alice".to_string(),
///     password: "secret123".to_string(),
///     realm: Some("example.com".to_string()),
/// };
/// # Ok(())
/// # }
/// ```
///
/// ## Usage with Registration
///
/// ```rust,no_run
/// # use rsipstack::dialog::authenticate::Credential;
/// # fn example() -> rsipstack::Result<()> {
/// let credential = Credential {
///     username: "alice".to_string(),
///     password: "secret123".to_string(),
///     realm: None, // Will be extracted from server challenge
/// };
///
/// // Use credential with registration
/// // let registration = Registration::new(endpoint.inner.clone(), Some(credential));
/// # Ok(())
/// # }
/// ```
///
/// ## Usage with INVITE
///
/// ```rust,no_run
/// # use rsipstack::dialog::authenticate::Credential;
/// # use rsipstack::dialog::invitation::InviteOption;
/// # fn example() -> rsipstack::Result<()> {
/// # let sdp_bytes = vec![];
/// # let credential = Credential {
/// #     username: "alice".to_string(),
/// #     password: "secret123".to_string(),
/// #     realm: Some("example.com".to_string()),
/// # };
/// let invite_option = InviteOption {
///     caller: rsip::Uri::try_from("sip:alice@example.com")?,
///     callee: rsip::Uri::try_from("sip:bob@example.com")?,
///     content_type: Some("application/sdp".to_string()),
///     offer: Some(sdp_bytes),
///     contact: rsip::Uri::try_from("sip:alice@192.168.1.100:5060")?,
///     credential: Some(credential),
///     ..Default::default()
/// };
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Credential {
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
}

/// Handle client-side authentication challenge
///
/// This function processes a 401 Unauthorized or 407 Proxy Authentication Required
/// response and creates a new transaction with proper authentication headers.
/// It implements SIP digest authentication according to RFC 3261 and RFC 2617.
///
/// # Parameters
///
/// * `new_seq` - New CSeq number for the authenticated request
/// * `tx` - Original transaction that received the authentication challenge
/// * `resp` - Authentication challenge response (401 or 407)
/// * `cred` - User credentials for authentication
///
/// # Returns
///
/// * `Ok(Transaction)` - New transaction with authentication headers
/// * `Err(Error)` - Failed to process authentication challenge
///
/// # Examples
///
/// ## Automatic Authentication Handling
///
/// ```rust,no_run
/// # use rsipstack::dialog::authenticate::{handle_client_authenticate, Credential};
/// # use rsipstack::transaction::transaction::Transaction;
/// # use rsip::Response;
/// # async fn example() -> rsipstack::Result<()> {
/// # let new_seq = 1u32;
/// # let original_tx: Transaction = todo!();
/// # let auth_challenge_response: Response = todo!();
/// # let credential = Credential {
/// #     username: "alice".to_string(),
/// #     password: "secret123".to_string(),
/// #     realm: Some("example.com".to_string()),
/// # };
/// // This is typically called automatically by dialog methods
/// let new_tx = handle_client_authenticate(
///     new_seq,
///     original_tx,
///     auth_challenge_response,
///     &credential
/// ).await?;
///
/// // Send the authenticated request
/// new_tx.send().await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Manual Authentication Flow
///
/// ```rust,no_run
/// # use rsipstack::dialog::authenticate::{handle_client_authenticate, Credential};
/// # use rsipstack::transaction::transaction::Transaction;
/// # use rsip::{SipMessage, StatusCode, Response};
/// # async fn example() -> rsipstack::Result<()> {
/// # let mut tx: Transaction = todo!();
/// # let credential = Credential {
/// #     username: "alice".to_string(),
/// #     password: "secret123".to_string(),
/// #     realm: Some("example.com".to_string()),
/// # };
/// # let new_seq = 2u32;
/// // Send initial request
/// tx.send().await?;
///
/// while let Some(message) = tx.receive().await {
///     match message {
///         SipMessage::Response(resp) => {
///             match resp.status_code {
///                 StatusCode::Unauthorized | StatusCode::ProxyAuthenticationRequired => {
///                     // Handle authentication challenge
///                     let auth_tx = handle_client_authenticate(
///                         new_seq, tx, resp, &credential
///                     ).await?;
///
///                     // Send authenticated request
///                     auth_tx.send().await?;
///                     tx = auth_tx;
///                 },
///                 StatusCode::OK => {
///                     println!("Request successful");
///                     break;
///                 },
///                 _ => {
///                     println!("Request failed: {}", resp.status_code);
///                     break;
///                 }
///             }
///         },
///         _ => {}
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// This function handles SIP authentication challenges and creates authenticated requests.
pub async fn handle_client_authenticate(
    new_seq: u32,
    tx: Transaction,
    resp: Response,
    cred: &Credential,
) -> Result<Transaction> {
    let header = match resp.www_authenticate_header() {
        Some(h) => Header::WwwAuthenticate(h.clone()),
        None => {
            let code = resp.status_code.clone();
            let proxy_header = rsip::header_opt!(resp.headers().iter(), Header::ProxyAuthenticate);
            let proxy_header = proxy_header.ok_or(crate::Error::DialogError(
                "missing proxy/www authenticate".to_string(),
                DialogId::try_from(&tx.original)?,
                code,
            ))?;
            Header::ProxyAuthenticate(proxy_header.clone())
        }
    };

    let mut new_req = tx.original.clone();
    new_req.cseq_header_mut()?.mut_seq(new_seq)?;

    let challenge = match &header {
        Header::WwwAuthenticate(h) => h.typed()?,
        Header::ProxyAuthenticate(h) => h.typed()?.0,
        _ => unreachable!(),
    };

    let cnonce = random_text(CNONCE_LEN);
    let auth_qop = match challenge.qop {
        Some(Qop::Auth) => Some(AuthQop::Auth { cnonce, nc: 1 }),
        Some(Qop::AuthInt) => Some(AuthQop::AuthInt { cnonce, nc: 1 }),
        _ => None,
    };

    // Use MD5 as default algorithm if none specified (RFC 2617 compatibility)
    let algorithm = challenge
        .algorithm
        .unwrap_or(rsip::headers::auth::Algorithm::Md5);

    let response = DigestGenerator {
        username: cred.username.as_str(),
        password: cred.password.as_str(),
        algorithm,
        nonce: challenge.nonce.as_str(),
        method: &tx.original.method,
        qop: auth_qop.as_ref(),
        uri: &tx.original.uri,
        realm: challenge.realm.as_str(),
    }
    .compute();

    let auth = Authorization {
        scheme: challenge.scheme,
        username: cred.username.clone(),
        realm: challenge.realm,
        nonce: challenge.nonce,
        uri: tx.original.uri.clone(),
        response,
        algorithm: Some(algorithm),
        opaque: challenge.opaque,
        qop: auth_qop,
    };

    let mut via_header = tx.original.via_header()?.clone().typed()?;
    let params = &mut via_header.params;
    params.retain(|p| !matches!(p, rsip::Param::Branch(_)));
    params.push(make_via_branch());
    params.push(Param::Other("rport".into(), None));
    new_req.headers_mut().unique_push(via_header.into());

    new_req.headers_mut().retain(|h| {
        !matches!(
            h,
            Header::ProxyAuthenticate(_)
                | Header::Authorization(_)
                | Header::WwwAuthenticate(_)
                | Header::ProxyAuthorization(_)
        )
    });

    match header {
        Header::WwwAuthenticate(_) => {
            new_req.headers_mut().unique_push(auth.into());
        }
        Header::ProxyAuthenticate(_) => {
            new_req
                .headers_mut()
                .unique_push(ProxyAuthorization(auth).into());
        }
        _ => unreachable!(),
    }
    let key = TransactionKey::from_request(&new_req, TransactionRole::Client)?;
    let mut new_tx = Transaction::new_client(
        key,
        new_req,
        tx.endpoint_inner.clone(),
        tx.connection.clone(),
    );
    new_tx.destination = tx.destination.clone();
    Ok(new_tx)
}
