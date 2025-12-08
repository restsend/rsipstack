use super::{
    authenticate::{handle_client_authenticate, Credential},
    DialogId,
};
use crate::{
    rsip_ext::RsipResponseExt,
    transaction::{
        endpoint::EndpointInnerRef,
        key::{TransactionKey, TransactionRole},
        make_call_id, make_tag,
        transaction::Transaction,
    },
    transport::SipAddr,
    Result,
};
use rsip::{
    prelude::{HeadersExt, ToTypedHeader},
    Response, SipMessage, StatusCode,
};
use tracing::{debug, info};

/// SIP Registration Client
///
/// `Registration` provides functionality for SIP user agent registration
/// with a SIP registrar server. Registration is the process by which a
/// SIP user agent informs a registrar server of its current location
/// and availability for receiving calls.
///
/// # Key Features
///
/// * **User Registration** - Registers user agent with SIP registrar
/// * **Authentication Support** - Handles digest authentication challenges
/// * **Contact Management** - Manages contact URI and expiration
/// * **DNS Resolution** - Resolves registrar server addresses
/// * **Automatic Retry** - Handles authentication challenges automatically
///
/// # Registration Process
///
/// 1. **DNS Resolution** - Resolves registrar server address
/// 2. **REGISTER Request** - Sends initial REGISTER request
/// 3. **Authentication** - Handles 401/407 challenges if needed
/// 4. **Confirmation** - Receives 200 OK with registration details
/// 5. **Refresh** - Periodically refreshes registration before expiration
///
/// # Examples
///
/// ## Basic Registration
///
/// ```rust,no_run
/// # use rsipstack::dialog::registration::Registration;
/// # use rsipstack::dialog::authenticate::Credential;
/// # use rsipstack::transaction::endpoint::Endpoint;
/// # async fn example() -> rsipstack::Result<()> {
/// # let endpoint: Endpoint = todo!();
/// let credential = Credential {
///     username: "alice".to_string(),
///     password: "secret123".to_string(),
///     realm: Some("example.com".to_string()),
/// };
///
/// let mut registration = Registration::new(endpoint.inner.clone(), Some(credential));
/// let server = rsip::Uri::try_from("sip:sip.example.com").unwrap();
/// let response = registration.register(server.clone(), None).await?;
///
/// if response.status_code == rsip::StatusCode::OK {
///     println!("Registration successful");
///     println!("Expires in: {} seconds", registration.expires());
/// }
/// # Ok(())
/// }
/// ```
///
/// ## Registration Loop
///
/// ```rust,no_run
/// # use rsipstack::dialog::registration::Registration;
/// # use rsipstack::dialog::authenticate::Credential;
/// # use rsipstack::transaction::endpoint::Endpoint;
/// # use std::time::Duration;
/// # async fn example() -> rsipstack::Result<()> {
/// # let endpoint: Endpoint = todo!();
/// # let credential: Credential = todo!();
/// # let server = rsip::Uri::try_from("sip:sip.example.com").unwrap();
/// let mut registration = Registration::new(endpoint.inner.clone(), Some(credential));
///
/// loop {
///     match registration.register(server.clone(), None).await {
///         Ok(response) if response.status_code == rsip::StatusCode::OK => {
///             let expires = registration.expires();
///             println!("Registered for {} seconds", expires);
///
///             // Re-register before expiration (with some margin)
///             tokio::time::sleep(Duration::from_secs((expires * 3 / 4) as u64)).await;
///         },
///         Ok(response) => {
///             eprintln!("Registration failed: {}", response.status_code);
///             tokio::time::sleep(Duration::from_secs(30)).await;
///         },
///         Err(e) => {
///             eprintln!("Registration error: {}", e);
///             tokio::time::sleep(Duration::from_secs(30)).await;
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// Registration is not thread-safe and should be used from a single task.
/// The sequence number and state are managed internally and concurrent
/// access could lead to protocol violations.
pub struct Registration {
    pub last_seq: u32,
    pub endpoint: EndpointInnerRef,
    pub credential: Option<Credential>,
    pub contact: Option<rsip::typed::Contact>,
    pub allow: rsip::headers::Allow,
    /// Public address detected by the server (IP and port)
    pub public_address: Option<rsip::HostWithPort>,
    pub call_id: rsip::headers::CallId,
}

impl Registration {
    /// Create a new registration client
    ///
    /// Creates a new Registration instance for registering with a SIP server.
    /// The registration will use the provided endpoint for network communication
    /// and credentials for authentication if required.
    ///
    /// # Parameters
    ///
    /// * `endpoint` - Reference to the SIP endpoint for network operations
    /// * `credential` - Optional authentication credentials
    ///
    /// # Returns
    ///
    /// A new Registration instance ready to perform registration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::registration::Registration;
    /// # use rsipstack::dialog::authenticate::Credential;
    /// # use rsipstack::transaction::endpoint::Endpoint;
    /// # fn example() {
    /// # let endpoint: Endpoint = todo!();
    /// // Registration without authentication
    /// let registration = Registration::new(endpoint.inner.clone(), None);
    ///
    /// // Registration with authentication
    /// let credential = Credential {
    ///     username: "alice".to_string(),
    ///     password: "secret123".to_string(),
    ///     realm: Some("example.com".to_string()),
    /// };
    /// let registration = Registration::new(endpoint.inner.clone(), Some(credential));
    /// # }
    /// ```
    pub fn new(endpoint: EndpointInnerRef, credential: Option<Credential>) -> Self {
        let call_id = make_call_id(endpoint.option.callid_suffix.as_deref());
        Self {
            last_seq: 0,
            endpoint,
            credential,
            contact: None,
            allow: Default::default(),
            public_address: None,
            call_id,
        }
    }

    /// Get the discovered public address
    ///
    /// Returns the public IP address and port discovered during the registration
    /// process. The SIP server indicates the client's public address through
    /// the 'received' and 'rport' parameters in Via headers.
    ///
    /// This is essential for NAT traversal, as it allows the client to use
    /// the correct public address in Contact headers and SDP for subsequent
    /// dialogs and media sessions.
    ///
    /// # Returns
    ///
    /// * `Some((ip, port))` - The discovered public IP address and port
    /// * `None` - No public address has been discovered yet
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::registration::Registration;
    /// # async fn example() {
    /// # let registration: Registration = todo!();
    /// if let Some(public_address) = registration.discovered_public_address() {
    ///     println!("Public address: {}", public_address);
    ///     // Use this address for Contact headers in dialogs
    /// } else {
    ///     println!("No public address discovered yet");
    /// }
    /// # }
    /// ```
    pub fn discovered_public_address(&self) -> Option<rsip::HostWithPort> {
        self.public_address.clone()
    }

    /// Get the registration expiration time
    ///
    /// Returns the expiration time in seconds for the current registration.
    /// This value is extracted from the Contact header's expires parameter
    /// in the last successful registration response.
    ///
    /// # Returns
    ///
    /// Expiration time in seconds (default: 50 if not set)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::registration::Registration;
    /// # use std::time::Duration;
    /// # async fn example() {
    /// # let registration: Registration = todo!();
    /// let expires = registration.expires();
    /// println!("Registration expires in {} seconds", expires);
    ///
    /// // Schedule re-registration before expiration
    /// let refresh_time = expires * 3 / 4; // 75% of expiration time
    /// tokio::time::sleep(Duration::from_secs(refresh_time as u64)).await;
    /// # }
    /// ```
    pub fn expires(&self) -> u32 {
        self.contact
            .as_ref()
            .and_then(|c| c.expires())
            .map(|e| e.seconds().unwrap_or(50))
            .unwrap_or(50)
    }

    /// Perform SIP registration with the server
    ///
    /// Sends a REGISTER request to the specified SIP server to register
    /// the user agent's current location. This method handles the complete
    /// registration process including DNS resolution, authentication
    /// challenges, and response processing.
    ///
    /// # Parameters
    ///
    /// * `server` - SIP server hostname or IP address (e.g., "sip.example.com")
    ///
    /// # Returns
    ///
    /// * `Ok(Response)` - Final response from the registration server
    /// * `Err(Error)` - Registration failed due to network or protocol error
    ///
    /// # Registration Flow
    ///
    /// 1. **DNS Resolution** - Resolves server address and transport
    /// 2. **Request Creation** - Creates REGISTER request with proper headers
    /// 3. **Initial Send** - Sends the registration request
    /// 4. **Authentication** - Handles 401/407 challenges if credentials provided
    /// 5. **Response Processing** - Returns final response (200 OK or error)
    ///
    /// # Response Codes
    ///
    /// * `200 OK` - Registration successful
    /// * `401 Unauthorized` - Authentication required (handled automatically)
    /// * `403 Forbidden` - Registration not allowed
    /// * `404 Not Found` - User not found
    /// * `423 Interval Too Brief` - Requested expiration too short
    ///
    /// # Examples
    ///
    /// ## Successful Registration
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::registration::Registration;
    /// # use rsip::prelude::HeadersExt;
    /// # async fn example() -> rsipstack::Result<()> {
    /// # let mut registration: Registration = todo!();
    /// let server = rsip::Uri::try_from("sip:sip.example.com").unwrap();
    /// let response = registration.register(server, None).await?;
    ///
    /// match response.status_code {
    ///     rsip::StatusCode::OK => {
    ///         println!("Registration successful");
    ///         // Extract registration details from response
    ///         if let Ok(_contact) = response.contact_header() {
    ///             println!("Registration confirmed");
    ///         }
    ///     },
    ///     rsip::StatusCode::Forbidden => {
    ///         println!("Registration forbidden");
    ///     },
    ///     _ => {
    ///         println!("Registration failed: {}", response.status_code);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Handling
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::registration::Registration;
    /// # use rsipstack::Error;
    /// # async fn example() {
    /// # let mut registration: Registration = todo!();
    /// # let server = rsip::Uri::try_from("sip:sip.example.com").unwrap();
    /// match registration.register(server, None).await {
    ///     Ok(response) => {
    ///         // Handle response based on status code
    ///     },
    ///     Err(Error::DnsResolutionError(msg)) => {
    ///         eprintln!("DNS resolution failed: {}", msg);
    ///     },
    ///     Err(Error::TransportLayerError(msg, addr)) => {
    ///         eprintln!("Network error to {}: {}", addr, msg);
    ///     },
    ///     Err(e) => {
    ///         eprintln!("Registration error: {}", e);
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// # Authentication
    ///
    /// If credentials are provided during Registration creation, this method
    /// will automatically handle authentication challenges:
    ///
    /// 1. Send initial REGISTER request
    /// 2. Receive 401/407 challenge with authentication parameters
    /// 3. Calculate authentication response using provided credentials
    /// 4. Resend REGISTER with Authorization header
    /// 5. Receive final response
    ///
    /// # Contact Header
    ///
    /// The method will automatically update the Contact header with the public
    /// address discovered during the registration process. This is essential
    /// for proper NAT traversal in SIP communications.
    ///
    /// If you want to use a specific Contact header, you can set it manually
    /// before calling this method.
    ///
    pub async fn register(&mut self, server: rsip::Uri, expires: Option<u32>) -> Result<Response> {
        self.last_seq += 1;

        let mut to = rsip::typed::To {
            display_name: None,
            uri: server.clone(),
            params: vec![],
        };

        if let Some(cred) = &self.credential {
            to.uri.auth = Some(rsip::auth::Auth {
                user: cred.username.clone(),
                password: None,
            });
        }

        let from = rsip::typed::From {
            display_name: None,
            uri: to.uri.clone(),
            params: vec![],
        }
        .with_tag(make_tag());

        let via = self.endpoint.get_via(None, None)?;

        // Contact address selection priority:
        // 1. Contact header from REGISTER response (highest priority)
        //    - Most accurate as it reflects server's view of client address
        // 2. Public address discovered during registration
        //    - Address detected from Via received parameter
        // 3. Local non-loopback address (lowest priority)
        //    - Only used for initial registration attempt
        //    - Will be replaced by server-discovered address after first response
        let contact = self.contact.clone().unwrap_or_else(|| {
            let contact_host_with_port = self
                .public_address
                .clone()
                .unwrap_or_else(|| via.uri.host_with_port.clone());
            rsip::typed::Contact {
                display_name: None,
                uri: rsip::Uri {
                    auth: to.uri.auth.clone(),
                    scheme: Some(rsip::Scheme::Sip),
                    host_with_port: contact_host_with_port,
                    params: vec![],
                    headers: vec![],
                },
                params: vec![],
            }
        });
        let mut request = self.endpoint.make_request(
            rsip::Method::Register,
            server,
            via,
            from,
            to,
            self.last_seq,
            None,
        );

        // Thanks to https://github.com/restsend/rsipstack/issues/32
        request.headers.unique_push(self.call_id.clone().into());
        request.headers.unique_push(contact.into());
        request.headers.unique_push(self.allow.clone().into());
        if let Some(expires) = expires {
            request
                .headers
                .unique_push(rsip::headers::Expires::from(expires).into());
        }

        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, request, self.endpoint.clone(), None);

        tx.send().await?;
        let mut auth_sent = false;

        while let Some(msg) = tx.receive().await {
            match msg {
                SipMessage::Response(resp) => match resp.status_code {
                    StatusCode::Trying => {
                        continue;
                    }
                    StatusCode::ProxyAuthenticationRequired | StatusCode::Unauthorized => {
                        let received = resp.via_received();
                        if self.public_address != received {
                            info!(
                                "Updated public address from 401 response, will use in authenticated request: {:?} -> {:?}",
                                self.public_address, received
                            );
                            self.public_address = received;
                            self.contact = None;
                        }

                        if auth_sent {
                            debug!("received {} response after auth sent", resp.status_code);
                            return Ok(resp);
                        }

                        if let Some(cred) = &self.credential {
                            self.last_seq += 1;

                            // Handle authentication with the existing transaction
                            // The contact will be updated in the next registration cycle if needed
                            tx = handle_client_authenticate(self.last_seq, tx, resp, cred).await?;

                            tx.send().await?;
                            auth_sent = true;
                            continue;
                        } else {
                            debug!("received {} response without credential", resp.status_code);
                            return Ok(resp);
                        }
                    }
                    StatusCode::OK => {
                        // Check if server indicated our public IP in Via header
                        let received = resp.via_received();
                        // Update contact header from response

                        match resp.contact_header() {
                            Ok(contact) => {
                                self.contact = contact.typed().ok();
                            }
                            Err(_) => {}
                        };
                        if self.public_address != received {
                            info!(
                                "Discovered public IP, will use for future registrations and calls: {:?} -> {:?}",
                                self.public_address, received
                            );
                            self.public_address = received;
                        }
                        info!(
                            "registration do_request done: {:?} {:?}",
                            resp.status_code,
                            self.contact.as_ref().map(|c| c.uri.to_string())
                        );
                        return Ok(resp);
                    }
                    _ => {
                        info!("registration do_request done: {:?}", resp.status_code);
                        return Ok(resp);
                    }
                },
                _ => break,
            }
        }
        return Err(crate::Error::DialogError(
            "registration transaction is already terminated".to_string(),
            DialogId::try_from(&tx.original)?,
            StatusCode::BadRequest,
        ));
    }

    /// Create a NAT-aware Contact header with public address
    ///
    /// Creates a Contact header suitable for use in SIP dialogs that takes into
    /// account the public address discovered during registration. This is essential
    /// for proper NAT traversal in SIP communications.
    ///
    /// # Parameters
    ///
    /// * `username` - SIP username for the Contact URI
    /// * `public_address` - Optional public address to use (IP and port)
    /// * `local_address` - Fallback local address if no public address available
    ///
    /// # Returns
    ///
    /// A Contact header with appropriate address for NAT traversal
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::dialog::registration::Registration;
    /// # use std::net::{IpAddr, Ipv4Addr};
    /// # use rsipstack::transport::SipAddr;
    /// # fn example() {
    /// # let local_addr: SipAddr = todo!();
    /// let contact = Registration::create_nat_aware_contact(
    ///     "alice",
    ///     Some(rsip::HostWithPort {
    ///         host: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)).into(),
    ///         port: Some(5060.into()),
    ///     }),
    ///     &local_addr,
    /// );
    /// # }
    /// ```
    pub fn create_nat_aware_contact(
        username: &str,
        public_address: Option<rsip::HostWithPort>,
        local_address: &SipAddr,
    ) -> rsip::typed::Contact {
        let contact_host_with_port = public_address.unwrap_or_else(|| local_address.clone().into());
        let params = vec![];

        // Don't add 'ob' parameter as it may confuse some SIP proxies
        // and prevent proper ACK routing
        // if public_address.is_some() {
        //     params.push(Param::Other("ob".into(), None));
        // }

        rsip::typed::Contact {
            display_name: None,
            uri: rsip::Uri {
                scheme: Some(rsip::Scheme::Sip),
                auth: Some(rsip::Auth {
                    user: username.to_string(),
                    password: None,
                }),
                host_with_port: contact_host_with_port,
                params,
                headers: vec![],
            },
            params: vec![],
        }
    }
}
