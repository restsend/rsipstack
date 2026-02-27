use super::DialogId;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transaction::{make_via_branch, random_text, CNONCE_LEN};
use crate::Result;
use rsip::headers::auth::{Algorithm, AuthQop, Qop};
use rsip::prelude::{HasHeaders, HeadersExt, ToTypedHeader};
use rsip::services::DigestGenerator;
use rsip::typed::{Authorization, ProxyAuthorization};
use rsip::{Header, Method, Param, Response};

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
///     &original_tx,
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
///                         new_seq, &tx, resp, &credential
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
    tx: &Transaction,
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
                DialogId::try_from(tx)?,
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

/// Compute the digest hash value using the specified algorithm.
///
/// This is a standalone hash function that supports MD5, SHA-256, and SHA-512
/// algorithms as specified in RFC 2617 and RFC 7616.
fn hash_value(algorithm: Algorithm, value: &str) -> String {
    use md5::Md5;
    use sha2::{Digest, Sha256, Sha512};

    match algorithm {
        Algorithm::Md5 | Algorithm::Md5Sess => {
            let mut hasher = Md5::new();
            hasher.update(value.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        Algorithm::Sha256 | Algorithm::Sha256Sess => {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        Algorithm::Sha512 | Algorithm::Sha512Sess => {
            let mut hasher = Sha512::new();
            hasher.update(value.as_bytes());
            format!("{:x}", hasher.finalize())
        }
    }
}

/// Compute the digest response using raw URI string.
///
/// This function computes the SIP digest authentication response using the
/// **raw URI string** rather than a parsed and re-serialized `Uri`. This is
/// critical because some SIP devices (e.g., Unify OpenScape phones) use
/// lowercase transport parameters like `transport=tls` in their digest URI,
/// while rsip's `Uri::Display` always normalizes to uppercase (`transport=TLS`).
/// Using the parsed URI would produce a different hash and cause authentication
/// to fail.
///
/// # Parameters
///
/// * `username` - The authentication username
/// * `password` - The authentication password
/// * `realm` - The authentication realm
/// * `nonce` - The server-provided nonce
/// * `method` - The SIP method (REGISTER, INVITE, etc.)
/// * `uri_raw` - The **raw** URI string exactly as provided by the client
/// * `algorithm` - The hash algorithm to use
/// * `qop` - Optional quality of protection
///
/// # Returns
///
/// The computed digest response string.
///
/// # Examples
///
/// ```rust,no_run
/// # use rsipstack::dialog::authenticate::compute_digest;
/// # use rsip::headers::auth::Algorithm;
/// let response = compute_digest(
///     "alice",
///     "secret123",
///     "example.com",
///     "dcd98b7102dd2f0e8b11d0f600bfb0c093",
///     &rsip::Method::Register,
///     "sip:example.com:5061;transport=tls",
///     Algorithm::Md5,
///     None,
/// );
/// ```
pub fn compute_digest(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    method: &Method,
    uri_raw: &str,
    algorithm: Algorithm,
    qop: Option<&AuthQop>,
) -> String {
    let ha1 = hash_value(algorithm, &format!("{}:{}:{}", username, realm, password));
    let ha2 = match qop {
        None | Some(AuthQop::Auth { .. }) => {
            hash_value(algorithm, &format!("{}:{}", method, uri_raw))
        }
        _ => hash_value(
            algorithm,
            &format!("{}:{}:d41d8cd98f00b204e9800998ecf8427e", method, uri_raw),
        ),
    };

    let value = match qop {
        Some(AuthQop::Auth { cnonce, nc }) => {
            format!("{}:{}:{:08}:{}:{}:{}", ha1, nonce, nc, cnonce, "auth", ha2)
        }
        Some(AuthQop::AuthInt { cnonce, nc }) => {
            format!(
                "{}:{}:{:08}:{}:{}:{}",
                ha1, nonce, nc, cnonce, "auth-int", ha2
            )
        }
        None => format!("{}:{}:{}", ha1, nonce, ha2),
    };

    hash_value(algorithm, &value)
}

/// Extract the raw `uri` value from a SIP Authorization/Proxy-Authorization header.
///
/// Uses rsip's `AuthTokenizer` to parse the header, which preserves the original
/// case of parameter values. This is necessary because `rsip::Uri::Display`
/// normalizes transport parameters to uppercase (e.g., `transport=tls` → `transport=TLS`),
/// which breaks digest authentication verification when the client used a different case.
///
/// # Parameters
///
/// * `header_value` - The raw header value string (e.g., `Digest username="alice", ...`)
///
/// # Returns
///
/// The raw URI string if found, or `None`.
///
/// # Examples
///
/// ```rust
/// # use rsipstack::dialog::authenticate::extract_digest_uri_raw;
/// let header = r#"Digest username="111",realm="pbx.e36",nonce="abc",uri="sip:pbx.e36:5061;transport=tls",response="xxx",algorithm=MD5"#;
/// let uri = extract_digest_uri_raw(header);
/// assert_eq!(uri, Some("sip:pbx.e36:5061;transport=tls".to_string()));
/// ```
pub fn extract_digest_uri_raw(header_value: &str) -> Option<String> {
    use rsip::headers::typed::tokenizers::AuthTokenizer;
    use rsip::headers::typed::Tokenize;

    let tokenizer = AuthTokenizer::tokenize(header_value).ok()?;
    tokenizer
        .params
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("uri"))
        .map(|(_, value)| value.to_string())
}

/// Verify a SIP digest authentication response.
///
/// This function verifies the digest response from a SIP Authorization or
/// Proxy-Authorization header using the **raw URI string** to avoid case
/// normalization issues. Some SIP devices use lowercase transport parameters
/// (e.g., `transport=tls`) while rsip normalizes them to uppercase (`TLS`),
/// which would cause digest verification to fail if the parsed URI were used.
///
/// # Parameters
///
/// * `auth` - The parsed `Authorization` header (used for username, realm, nonce, etc.)
/// * `password` - The expected password for the user
/// * `method` - The SIP method from the request
/// * `raw_header_value` - The raw Authorization header value string, used to extract the URI
///
/// # Returns
///
/// `true` if the digest response matches, `false` otherwise.
///
/// # Examples
///
/// ```rust,no_run
/// # use rsipstack::dialog::authenticate::verify_digest;
/// # use rsip::typed::Authorization;
/// # use rsip::prelude::ToTypedHeader;
/// # fn example() -> rsipstack::Result<()> {
/// # let auth_header_value = "";
/// # let auth: Authorization = todo!();
/// let is_valid = verify_digest(
///     &auth,
///     "secret123",
///     &rsip::Method::Register,
///     auth_header_value,
/// );
///
/// if is_valid {
///     println!("Authentication successful");
/// } else {
///     println!("Authentication failed");
/// }
/// # Ok(())
/// # }
/// ```
pub fn verify_digest(
    auth: &Authorization,
    password: &str,
    method: &Method,
    raw_header_value: &str,
) -> bool {
    let algorithm = auth.algorithm.unwrap_or(Algorithm::Md5);

    // Extract the raw URI from the header to preserve original case
    // This is critical because DigestGenerator uses Uri::Display which
    // normalizes transport params to uppercase (e.g., transport=tls -> transport=TLS)
    let uri_str = match extract_digest_uri_raw(raw_header_value) {
        Some(uri) => uri,
        None => {
            // Fallback to the parsed URI (which may have case normalization issues)
            auth.uri.to_string()
        }
    };

    let expected = compute_digest(
        &auth.username,
        password,
        &auth.realm,
        &auth.nonce,
        method,
        &uri_str,
        algorithm,
        auth.qop.as_ref(),
    );

    expected == auth.response
}
