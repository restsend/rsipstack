use super::{endpoint::EndpointInner, make_call_id};
use crate::prelude::*;
use crate::sip::{
    prelude::{HeadersExt, ToTypedHeader},
    typed::Route as TypedRoute,
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
        let call_id = call_id.unwrap_or_else(|| {
            make_call_id(
                self.option.callid_suffix.as_deref(),
                self.option.callid_format,
            )
        });
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
            wire_reason: None,
            version: *req.version(),
            headers,
            body: body.unwrap_or_default(),
        }
    }

    /// A response to a CANCEL, with the To header (and tag) of the INVITE's
    /// last response when there is one (RFC 3261 §9.2).
    pub(crate) fn make_cancel_response(
        &self,
        cancel: &Request,
        status_code: StatusCode,
        invite_response: Option<&Response>,
    ) -> Response {
        let mut resp = self.make_response(cancel, status_code, None);
        if let Some(to) = invite_response.and_then(|r| r.to_header().ok()) {
            for header in resp.headers.iter_mut() {
                if let Header::To(t) = header {
                    *t = to.clone();
                }
            }
        }
        resp
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
                let _ = top_most_via.update_first_value(|via| {
                    let mut typed_via = via.typed()?;
                    typed_via.params.clear();
                    typed_via.params.push(make_via_branch());
                    Ok(typed_via.into())
                });
            }
            // The 2xx ACK goes to the remote target. Routes are always loose,
            // like every other request the stack builds.
            request_uri = resp.contact_header()?.typed()?.uri;

            // An INVITE that already carries a To tag is a re-INVITE inside a
            // confirmed dialog. The dialog's route set is fixed (RFC 3261
            // §12.2) and the re-INVITE was sent with it as its Route headers,
            // so the ACK reuses them; a 2xx to a re-INVITE usually repeats no
            // Record-Route, and one it does repeat must not change the route.
            let in_dialog = invite
                .to_header()
                .ok()
                .and_then(|to| to.tag().ok().flatten())
                .is_some_and(|tag| !tag.value().is_empty());
            if in_dialog {
                headers.extend(
                    invite
                        .headers
                        .iter()
                        .filter(|header| matches!(header, Header::Route(_)))
                        .cloned()
                        .collect::<Vec<_>>(),
                );
            } else {
                // The 2xx to the dialog-creating INVITE defines the route set:
                // its Record-Route in reverse order (RFC 3261 §12.1.2).
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

                headers.extend(
                    route_set
                        .into_iter()
                        .map(|route| Header::Route(TypedRoute::from(route).into()))
                        .collect::<Vec<_>>(),
                );
            }
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
                    | Header::SessionId(_)
            )
        });
        // RFC 7989 §6/§10.1: the ACK is sent by the INVITE originator, so its
        // local-uuid is the INVITE's, while the peer's UUID comes from the
        // response being acknowledged. Without a Session-ID on the INVITE the
        // endpoint does not participate and the response header is untouched.
        let invite_local = invite.session_id_header().and_then(|s| s.local_uuid());
        let resp_peer = resp.session_id_header().and_then(|s| s.local_uuid());
        match (invite_local, resp_peer) {
            (Some(local), Some(peer)) => {
                for h in headers.iter_mut() {
                    if let Header::SessionId(sid) = h {
                        if let Ok(updated) =
                            crate::sip::headers::SessionId::from_pair(&local, &peer)
                        {
                            *sid = updated;
                        }
                    }
                }
            }
            (Some(local), None) if resp.session_id_header().is_none() => {
                if let Ok(sid) = crate::sip::headers::SessionId::from_local(&local) {
                    headers.push(Header::SessionId(sid));
                }
            }
            _ => {}
        }
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
            headers,
            body: vec![],
            version: crate::sip::Version::V2,
        })
    }
}
