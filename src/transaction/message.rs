use super::{endpoint::EndpointInner, make_call_id};
use crate::sip::{
    prelude::{HeadersExt, ToTypedHeader},
    typed::Route as TypedRoute,
    uri::ParamsExt,
    Error, Header, Request, Response, StatusCode, UriWithParams,
};
use crate::sip::{CallId, Method};
use crate::sip_header;
use crate::{transaction::make_via_branch, Result};

impl EndpointInner {
    /// Create a SIP request message
    ///
    /// Constructs a properly formatted SIP request with all required headers
    /// according to RFC 3261. This method is used internally by the endpoint
    /// to create outgoing SIP requests for various purposes.
    ///
    /// # Parameters
    ///
    /// * `method` - SIP method (INVITE, REGISTER, BYE, etc.)
    /// * `req_uri` - Request-URI indicating the target of the request
    /// * `via` - Via header for response routing
    /// * `from` - From header identifying the request originator
    /// * `to` - To header identifying the request target
    /// * `seq` - CSeq sequence number for the request
    ///
    /// # Returns
    ///
    /// A complete SIP request with all mandatory headers
    ///
    /// # Generated Headers
    ///
    /// The method automatically includes these mandatory headers:
    /// * **Via** - Response routing information
    /// * **Call-ID** - Unique identifier for the call/session
    /// * **From** - Request originator with tag parameter
    /// * **To** - Request target (tag added by recipient)
    /// * **CSeq** - Command sequence with method and number
    /// * **Max-Forwards** - Hop count limit (set to 70)
    /// * **User-Agent** - Endpoint identification
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rsipstack::transaction::endpoint::EndpointInner;
    /// # async fn example(endpoint: &EndpointInner) -> rsipstack::Result<()> {
    /// // Create an INVITE request
    /// let via = endpoint.get_via(None, None)?;
    /// let from = rsipstack::sip::typed::From {
    ///     display_name: None,
    ///     uri: rsipstack::sip::Uri::try_from("sip:alice@example.com")?,
    ///     params: vec![rsipstack::sip::Param::Tag("alice-tag".into())],
    /// };
    /// let to = rsipstack::sip::typed::To {
    ///     display_name: None,
    ///     uri: rsipstack::sip::Uri::try_from("sip:bob@example.com")?,
    ///     params: vec![],
    /// };
    ///
    /// let request = endpoint.make_request(
    ///     rsipstack::sip::Method::Invite,
    ///     rsipstack::sip::Uri::try_from("sip:bob@example.com")?,
    ///     via,
    ///     from,
    ///     to,
    ///     1,
    ///     None,
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Usage Context
    ///
    /// This method is typically used by:
    /// * Dialog layer for creating in-dialog requests
    /// * Registration module for REGISTER requests
    /// * Transaction layer for creating client transactions
    /// * Application layer for custom request types
    ///
    /// # Header Ordering
    ///
    /// Headers are added in the order specified by RFC 3261 recommendations:
    /// 1. Via (topmost first)
    /// 2. Call-ID
    /// 3. From
    /// 4. To
    /// 5. CSeq
    /// 6. Max-Forwards
    /// 7. User-Agent
    ///
    /// Additional headers can be added after creation using the headers API.
    pub fn make_request(
        &self,
        method: Method,
        req_uri: crate::sip::Uri,
        via: crate::sip::typed::Via,
        from: crate::sip::typed::From,
        to: crate::sip::typed::To,
        seq: u32,
        call_id: Option<CallId>,
    ) -> Request {
        let call_id = call_id.unwrap_or_else(|| make_call_id(self.option.callid_suffix.as_deref()));
        let headers = vec![
            Header::Via(via.into()),
            Header::CallId(call_id),
            Header::From(from.into()),
            Header::To(to.into()),
            Header::CSeq(crate::sip::typed::CSeq { seq, method }.into()),
            Header::MaxForwards(70.into()),
            Header::UserAgent(self.user_agent.clone().into()),
        ];
        Request {
            method,
            uri: req_uri,
            headers: headers.into(),
            body: vec![],
            version: crate::sip::Version::V2,
        }
    }

    /// Create a SIP response message
    ///
    /// Constructs a properly formatted SIP response based on the received
    /// request. This method copies appropriate headers from the request
    /// and adds the response-specific information according to RFC 3261.
    ///
    /// # Parameters
    ///
    /// * `req` - Original request being responded to
    /// * `status_code` - SIP response status code (1xx-6xx)
    /// * `body` - Optional response body content
    ///
    /// # Returns
    ///
    /// A complete SIP response ready to be sent
    ///
    /// # Header Processing
    ///
    /// The method processes headers as follows:
    /// * **Copied from request**: Via, Call-ID, From, To, CSeq, Max-Forwards
    /// * **Added by endpoint**: User-Agent
    /// * **Filtered out**: All other headers from the request
    ///
    /// Additional response-specific headers should be added after creation.
    ///
    /// # Examples
    ///
    /// ## Success Response
    ///
    /// ```rust,no_run
    /// # use rsipstack::transaction::endpoint::EndpointInner;
    /// # fn example(endpoint: &EndpointInner, request: &rsipstack::sip::Request, sdp_answer: String) {
    /// let response = endpoint.make_response(
    ///     &request,
    ///     rsipstack::sip::StatusCode::OK,
    ///     Some(sdp_answer.into_bytes())
    /// );
    /// # }
    /// ```
    ///
    /// ## Error Response
    ///
    /// ```rust,no_run
    /// # use rsipstack::transaction::endpoint::EndpointInner;
    /// # fn example(endpoint: &EndpointInner, request: &rsipstack::sip::Request) {
    /// let response = endpoint.make_response(
    ///     &request,
    ///     rsipstack::sip::StatusCode::NotFound,
    ///     None
    /// );
    /// # }
    /// ```
    ///
    /// ## Provisional Response
    ///
    /// ```rust,no_run
    /// # use rsipstack::transaction::endpoint::EndpointInner;
    /// # fn example(endpoint: &EndpointInner, request: &rsipstack::sip::Request) {
    /// let response = endpoint.make_response(
    ///     &request,
    ///     rsipstack::sip::StatusCode::Ringing,
    ///     None
    /// );
    /// # }
    /// ```
    ///
    /// # Response Categories
    ///
    /// * **1xx Provisional** - Request received, processing continues
    /// * **2xx Success** - Request successfully received, understood, and accepted
    /// * **3xx Redirection** - Further action needed to complete request
    /// * **4xx Client Error** - Request contains bad syntax or cannot be fulfilled
    /// * **5xx Server Error** - Server failed to fulfill valid request
    /// * **6xx Global Failure** - Request cannot be fulfilled at any server
    ///
    /// # Usage Context
    ///
    /// This method is used by:
    /// * Server transactions to create responses
    /// * Dialog layer for dialog-specific responses
    /// * Application layer for handling incoming requests
    /// * Error handling for protocol violations
    ///
    /// # Header Compliance
    ///
    /// The response includes all headers required by RFC 3261:
    /// * Via headers are copied exactly (for response routing)
    /// * Call-ID is preserved (dialog/transaction identification)
    /// * From/To headers maintain dialog state
    /// * CSeq is copied for transaction matching
    /// * User-Agent identifies the responding endpoint
    ///
    /// # Content Handling
    ///
    /// * If body is provided, Content-Length should be added separately
    /// * Content-Type should be added for non-empty bodies
    /// * Body encoding is handled by the application layer
    pub fn make_response(
        &self,
        req: &Request,
        status_code: StatusCode,
        body: Option<Vec<u8>>,
    ) -> Response {
        let mut headers = req.headers.clone();
        headers.retain(|h| {
            matches!(
                h,
                Header::Via(_)
                    | Header::CallId(_)
                    | Header::From(_)
                    | Header::To(_)
                    | Header::CSeq(_)
            )
        });
        headers.push(Header::ContentLength(
            body.as_ref().map_or(0u32, |b| b.len() as u32).into(),
        ));
        headers.unique_push(Header::UserAgent(self.user_agent.clone().into()));
        Response {
            status_code,
            version: req.version().clone(),
            headers,
            body: body.unwrap_or_default(),
        }
    }

    // make ack from response, for ack to non-200 reponse, should pass the original invite
    pub fn make_ack(&self, invite: &Request, resp: &Response) -> Result<Request> {
        let mut headers = resp.headers.clone();
        let request_uri;
        if resp.status_code.kind() != crate::sip::StatusCodeKind::Successful {
            // Non-2xx ACK stays in the original INVITE transaction.
            request_uri = invite.uri.clone();
            headers.extend(
                invite
                    .headers
                    .iter()
                    .filter(|header| matches!(header, Header::Route(_)))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
        } else {
            // 2xx ACK is a separate request built from the dialog remote target and route set.
            if let Ok(top_most_via) = sip_header!(
                headers.iter_mut(),
                Header::Via,
                Error::missing_header("Via")
            ) {
                if let Ok(mut typed_via) = top_most_via.typed() {
                    typed_via.params.clear();
                    typed_via.params.push(make_via_branch());
                    *top_most_via = typed_via.into();
                }
            }
            let mut route_set: Vec<UriWithParams> = Vec::new();
            for header in resp.headers.iter() {
                if let Header::RecordRoute(record_route) = header {
                    for typed in
                        crate::sip::typed::RecordRoute::parse_header_list(record_route.value())
                            .unwrap_or_default()
                    {
                        route_set.push(typed.uri);
                    }
                }
            }
            route_set.reverse();

            let contact = resp.contact_header()?;

            let remote_target_uri = contact.typed()?.uri;

            let route_headers = match route_set.as_slice() {
                [] => {
                    request_uri = remote_target_uri;
                    Vec::new()
                }
                [head, rest @ ..] => {
                    // loose routing
                    if head.has_lr() {
                        request_uri = remote_target_uri;
                        route_set
                    } else {
                        // Strict routing promotes the first route URI into the Request-URI
                        // and appends the remote target as the last Route value.
                        let mut request_uri_value = head.clone();
                        request_uri_value.headers.clear();
                        request_uri = request_uri_value;

                        let mut strict_routes = rest.to_vec();
                        strict_routes.push(remote_target_uri.clone());

                        strict_routes
                    }
                }
            };

            headers.extend(
                route_headers
                    .iter()
                    .cloned()
                    .map(|route| {
                        let typed_route = TypedRoute::from(route);
                        Header::Route(typed_route.into())
                    })
                    .collect::<Vec<_>>(),
            );
        }

        headers.retain(|h| {
            matches!(
                h,
                Header::Via(_)
                    | Header::CallId(_)
                    | Header::From(_)
                    | Header::To(_)
                    | Header::CSeq(_)
                    | Header::Route(_)
            )
        });
        headers.push(Header::MaxForwards(70.into()));
        headers.iter_mut().for_each(|h| {
            if let Header::CSeq(cseq) = h {
                cseq.mut_method(crate::sip::Method::Ack).ok();
            }
        });
        headers.push(Header::ContentLength(0u32.into())); // 0 because of vec![] below
        headers.unique_push(Header::UserAgent(self.user_agent.clone().into()));
        Ok(Request {
            method: crate::sip::Method::Ack,
            uri: request_uri,
            headers: headers.into(),
            body: vec![],
            version: crate::sip::Version::V2,
        })
    }
}
