use super::{endpoint::EndpointInner, make_call_id};
use crate::{transaction::make_via_branch, Result};
use rsip::{
    header,
    headers::{ContentLength, Route},
    prelude::{ToTypedHeader, UntypedHeader},
    Error, Header, Request, Response, StatusCode,
};

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
    /// let from = rsip::typed::From {
    ///     display_name: None,
    ///     uri: rsip::Uri::try_from("sip:alice@example.com")?,
    ///     params: vec![rsip::Param::Tag("alice-tag".into())],
    /// };
    /// let to = rsip::typed::To {
    ///     display_name: None,
    ///     uri: rsip::Uri::try_from("sip:bob@example.com")?,
    ///     params: vec![],
    /// };
    ///
    /// let request = endpoint.make_request(
    ///     rsip::Method::Invite,
    ///     rsip::Uri::try_from("sip:bob@example.com")?,
    ///     via,
    ///     from,
    ///     to,
    ///     1
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
        method: rsip::Method,
        req_uri: rsip::Uri,
        via: rsip::typed::Via,
        from: rsip::typed::From,
        to: rsip::typed::To,
        seq: u32,
    ) -> rsip::Request {
        let headers = vec![
            Header::Via(via.into()),
            Header::CallId(make_call_id(self.option.callid_suffix.as_deref())),
            Header::From(from.into()),
            Header::To(to.into()),
            Header::CSeq(rsip::typed::CSeq { seq, method }.into()),
            Header::MaxForwards(70.into()),
            Header::UserAgent(self.user_agent.clone().into()),
        ];
        rsip::Request {
            method,
            uri: req_uri,
            headers: headers.into(),
            body: vec![],
            version: rsip::Version::V2,
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
    /// # fn example(endpoint: &EndpointInner, request: &rsip::Request, sdp_answer: String) {
    /// let response = endpoint.make_response(
    ///     &request,
    ///     rsip::StatusCode::OK,
    ///     Some(sdp_answer.into_bytes())
    /// );
    /// # }
    /// ```
    ///
    /// ## Error Response
    ///
    /// ```rust,no_run
    /// # use rsipstack::transaction::endpoint::EndpointInner;
    /// # fn example(endpoint: &EndpointInner, request: &rsip::Request) {
    /// let response = endpoint.make_response(
    ///     &request,
    ///     rsip::StatusCode::NotFound,
    ///     None
    /// );
    /// # }
    /// ```
    ///
    /// ## Provisional Response
    ///
    /// ```rust,no_run
    /// # use rsipstack::transaction::endpoint::EndpointInner;
    /// # fn example(endpoint: &EndpointInner, request: &rsip::Request) {
    /// let response = endpoint.make_response(
    ///     &request,
    ///     rsip::StatusCode::Ringing,
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

    pub fn make_ack(&self, resp: &Response, request_uri: rsip::Uri) -> Result<Request> {
        let mut headers = resp.headers.clone();
        if matches!(resp.status_code.kind(), rsip::StatusCodeKind::Successful) {
            //For non-2xx final responses (3xx–6xx), the ACK stays within the original INVITE client transaction.
            if let Ok(top_most_via) = header!(
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
        }
        // update route set from Record-Route header
        let mut route_set = Vec::new();
        for header in resp.headers.iter() {
            if let Header::RecordRoute(record_route) = header {
                route_set.push(Header::Route(Route::from(record_route.value())));
            }
        }
        route_set.reverse();
        headers.extend(route_set);

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
                cseq.mut_method(rsip::Method::Ack).ok();
            }
        });
        headers.push(Header::ContentLength(ContentLength::default())); // 0 because of vec![] below
        headers.unique_push(Header::UserAgent(self.user_agent.clone().into()));
        Ok(rsip::Request {
            method: rsip::Method::Ack,
            uri: request_uri,
            headers: headers.into(),
            body: vec![],
            version: rsip::Version::V2,
        })
    }
}
