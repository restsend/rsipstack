use super::{
    authenticate::{handle_client_authenticate, Credential},
    DialogId,
};
use crate::{
    transaction::{
        endpoint::EndpointInnerRef,
        key::{TransactionKey, TransactionRole},
        make_tag,
        transaction::Transaction,
    },
    transport::SipAddr,
    Error, Result,
};
use get_if_addrs::get_if_addrs;
use rsip::{HostWithPort, Param, Response, SipMessage, StatusCode};
use rsip::headers::ToTypedHeader;
use rsip_dns::trust_dns_resolver::TokioAsyncResolver;
use rsip_dns::ResolvableExt;
use std::net::IpAddr;
use tracing::info;

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
/// let response = registration.register(&"sip.example.com".to_string()).await?;
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
/// # let server = "sip.example.com".to_string();
/// let mut registration = Registration::new(endpoint.inner.clone(), Some(credential));
///
/// loop {
///     match registration.register(&server).await {
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
    pub public_address: Option<(std::net::IpAddr, u16)>,
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
        Self {
            last_seq: 0,
            endpoint,
            credential,
            contact: None,
            allow: Default::default(),
            public_address: None,
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
    /// if let Some((public_ip, public_port)) = registration.discovered_public_address() {
    ///     println!("Public address: {}:{}", public_ip, public_port);
    ///     // Use this address for Contact headers in dialogs
    /// } else {
    ///     println!("No public address discovered yet");
    /// }
    /// # }
    /// ```
    pub fn discovered_public_address(&self) -> Option<(std::net::IpAddr, u16)> {
        self.public_address
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

    /// Get the first non-loopback network interface
    ///
    /// Discovers the first available non-loopback IPv4 network interface
    /// on the system. This is used to determine the local IP address
    /// for the Contact header in registration requests.
    ///
    /// # Returns
    ///
    /// * `Ok(IpAddr)` - First non-loopback IPv4 address found
    /// * `Err(Error)` - No suitable interface found
    fn get_first_non_loopback_interface() -> Result<IpAddr> {
        get_if_addrs()?
            .iter()
            .find(|i| !i.is_loopback())
            .map(|i| match i.addr {
                get_if_addrs::IfAddr::V4(ref addr) => Ok(std::net::IpAddr::V4(addr.ip)),
                _ => Err(Error::Error("No IPv4 address found".to_string())),
            })
            .unwrap_or(Err(Error::Error("No interface found".to_string())))
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
    /// let response = registration.register(&"sip.example.com".to_string()).await?;
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
    /// # let server = "sip.example.com".to_string();
    /// match registration.register(&server).await {
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
    /// # Network Discovery
    ///
    /// The method automatically:
    /// * Discovers local network interface for Contact header
    /// * Resolves server address using DNS SRV/A records
    /// * Determines appropriate transport protocol (UDP/TCP/TLS)
    /// * Sets up proper Via headers for response routing
    pub async fn register(&mut self, server: &String) -> Result<Response> {
        self.last_seq += 1;

        let recipient = rsip::Uri::try_from(format!("sip:{}", server))?;

        let mut to = rsip::typed::To {
            display_name: None,
            uri: recipient.clone(),
            params: vec![],
        };

        if let Some(cred) = &self.credential {
            to.uri.auth = Some(rsip::auth::Auth {
                user: cred.username.clone(),
                password: None,
            });
        }

        let form = rsip::typed::From {
            display_name: None,
            uri: to.uri.clone(),
            params: vec![],
        }
        .with_tag(make_tag());

        let first_addr = {
            let mut addr =
                SipAddr::from(HostWithPort::from(Self::get_first_non_loopback_interface()?));
            let context = rsip_dns::Context::initialize_from(
                recipient.clone(),
                rsip_dns::AsyncTrustDnsClient::new(
                    TokioAsyncResolver::tokio(Default::default(), Default::default()).unwrap(),
                ),
                rsip_dns::SupportedTransports::any(),
            )?;

            let mut lookup = rsip_dns::Lookup::from(context);
            match lookup.resolve_next().await {
                Some(target) => {
                    addr.r#type = Some(target.transport);
                    addr
                }
                None => {
                    Err(crate::Error::DnsResolutionError(format!(
                        "DNS resolution error: {}",
                        recipient
                    )))
                }?,
            }
        };
        let contact = self
            .contact
            .clone()
            .unwrap_or_else(|| {
                // Use public address if available, otherwise use local address
                let contact_host_with_port = if let Some((public_ip, public_port)) = self.public_address {
                    info!("Using public address for initial Contact: {}:{}", public_ip, public_port);
                    HostWithPort {
                        host: public_ip.into(),
                        port: Some(public_port.into()),
                    }
                } else {
                    info!("Using local address for initial Contact: {}", first_addr.addr);
                    first_addr.clone().into()
                };
                
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
        let via = self.endpoint.get_via(Some(first_addr.clone()), None)?;
        let mut request = self.endpoint.make_request(
            rsip::Method::Register,
            recipient,
            via,
            form,
            to,
            self.last_seq,
        );

        request.headers.unique_push(contact.into());
        request.headers.unique_push(self.allow.clone().into());

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
                        // First check if server indicated our public IP in Via header
                        // Get all Via headers and check each one
                        let via_headers = resp.headers.iter()
                            .filter_map(|h| match h {
                                rsip::Header::Via(v) => Some(v),
                                _ => None
                            })
                            .collect::<Vec<_>>();
                        
                        info!("Found {} Via headers in 401 response", via_headers.len());
                        
                        for (idx, via) in via_headers.iter().enumerate() {
                            info!("Checking Via header #{} for public IP in 401 response: {}", idx, via);
                            if let Ok(typed_via) = via.typed() {
                                let mut received_ip: Option<std::net::IpAddr> = None;
                                let mut rport: Option<u16> = None;
                                
                                // Parse all Via parameters
                                for param in &typed_via.params {
                                    match param {
                                        Param::Received(received) => {
                                            if let Ok(ip) = received.value().parse() {
                                                received_ip = Some(ip);
                                                info!("Found received parameter: {}", ip);
                                            }
                                        }
                                        Param::Other(key, Some(value)) if key.value() == "rport" => {
                                            if let Ok(port) = value.value().parse::<u16>() {
                                                rport = Some(port);
                                                info!("Found rport parameter: {}", port);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                
                                // If we found both received IP and rport, update our public address
                                if let (Some(public_ip), Some(public_port)) = (received_ip, rport) {
                                    info!("Server detected our public address as {}:{}", public_ip, public_port);
                                    
                                    // Store the public address
                                    let new_public_addr = Some((public_ip, public_port));
                                    
                                    // Only update if this is new information
                                    if self.public_address != new_public_addr {
                                        self.public_address = new_public_addr;
                                        
                                        // IMPORTANT: Clear the stored contact so it gets regenerated with public IP
                                        self.contact = None;
                                        info!("Updated public address from 401 response, will use in authenticated request");
                                    }
                                }
                            }
                        }
                        
                        if auth_sent {
                            info!("received {} response after auth sent", resp.status_code);
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
                            info!("received {} response without credential", resp.status_code);
                            return Ok(resp);
                        }
                    }
                    StatusCode::OK => {
                        // Check if server indicated our public IP in Via header
                        let mut need_reregistration = false;
                        // Get all Via headers and check each one
                        let via_headers = resp.headers.iter()
                            .filter_map(|h| match h {
                                rsip::Header::Via(v) => Some(v),
                                _ => None
                            })
                            .collect::<Vec<_>>();
                        
                        info!("Found {} Via headers in 200 OK response", via_headers.len());
                        
                        for (idx, via) in via_headers.iter().enumerate() {
                            info!("Checking Via header #{} for public IP: {}", idx, via);
                            if let Ok(typed_via) = via.typed() {
                                let mut received_ip: Option<std::net::IpAddr> = None;
                                let mut rport: Option<u16> = None;
                                
                                // Parse all Via parameters
                                for param in &typed_via.params {
                                    match param {
                                        Param::Received(received) => {
                                            if let Ok(ip) = received.value().parse() {
                                                received_ip = Some(ip);
                                                info!("Found received parameter: {}", ip);
                                            }
                                        }
                                        Param::Other(key, Some(value)) if key.value() == "rport" => {
                                            if let Ok(port) = value.value().parse::<u16>() {
                                                rport = Some(port);
                                                info!("Found rport parameter: {}", port);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                
                                // If we found both received IP and rport, update our public address
                                if let (Some(public_ip), Some(public_port)) = (received_ip, rport) {
                                    info!("Server detected our public address as {}:{}", public_ip, public_port);
                                    
                                    // Store the public address
                                    let new_public_addr = Some((public_ip, public_port));
                                    
                                    // Only update and re-register if this is new information
                                    if self.public_address != new_public_addr {
                                        self.public_address = new_public_addr;
                                        
                                        // Clear the stored contact so it gets regenerated with public IP
                                        self.contact = None;
                                        
                                        // We need to re-register immediately with the public IP
                                        need_reregistration = true;
                                        info!("Will re-register with public address");
                                    }
                                }
                            }
                        }
                        
                        // If we detected public IP on first registration, return success
                        // The client will use the discovered public address for future requests
                        if need_reregistration {
                            info!("Discovered public IP, will use for future registrations and calls");
                            // Don't re-register immediately - let the client handle this
                            // and use the discovered public address for INVITE requests
                        }
                        
                        info!("registration do_request done: {:?}", resp.status_code);
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
    ///     Some((IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 5060)),
    ///     &local_addr,
    /// );
    /// # }
    /// ```
    pub fn create_nat_aware_contact(
        username: &str,
        public_address: Option<(std::net::IpAddr, u16)>,
        local_address: &SipAddr,
    ) -> rsip::typed::Contact {
        let contact_host_with_port = if let Some((public_ip, public_port)) = public_address {
            HostWithPort {
                host: public_ip.into(),
                port: Some(public_port.into()),
            }
        } else {
            local_address.clone().into()
        };

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
