use super::test_dialog_states::{create_invite_request, create_test_endpoint};
use crate::dialog::{dialog::DialogInner, DialogId};
use crate::sip::{Header, HeadersExt, Method, Response, SipMessage, StatusCode, Transport};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transport::SipConnection;
use tokio::sync::mpsc::unbounded_channel;

#[tokio::test]
async fn proxy_via_id_survives_received_and_responses() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    for id in ["0", "1", "01", "a2", "001"] {
        for combined in [false, true] {
            let mut invite = create_invite_request("caller", "", "proxy-via");
            let caller_via = invite.via_header()?.value().to_owned();
            let proxy_via =
                format!("SIP/2.0/UDP private.example.com:5070;branch=z9hG4bKproxy;rport;i={id}");
            if combined {
                invite
                    .via_header_mut()?
                    .replace(format!("{proxy_via}, {caller_via}"));
            } else {
                invite.headers.push_front(Header::Via(proxy_via.into()));
            }
            invite.headers.push(Header::RecordRoute(
                "<sip:private.example.com:5070;r2=on;lr>".into(),
            ));
            invite.headers.push(Header::RecordRoute(
                "<sip:public.example.com:5060;r2=on;lr>".into(),
            ));
            let key = TransactionKey::from_request(&invite, TransactionRole::Client)?;
            let parsed = SipMessage::try_from(invite.to_string().as_str())?;
            let SipMessage::Request(received) = SipConnection::update_msg_received(
                parsed,
                "127.0.0.1:15070".parse().unwrap(),
                Transport::Udp,
            )?
            else {
                panic!("expected request")
            };
            let top = received.top_via_header()?;
            assert!(top.value().contains(&format!(";i={id}")));
            assert!(top.value().contains(";received=127.0.0.1"));
            assert!(top.value().contains(";rport=15070"));
            assert!(received.to_string().contains(&caller_via));
            let (state_tx, _state_rx) = unbounded_channel();
            let (tu_tx, _tu_rx) = unbounded_channel();
            let dialog = DialogInner::new(
                TransactionRole::Server,
                DialogId {
                    call_id: "proxy-via".into(),
                    local_tag: "pbx".into(),
                    remote_tag: "caller".into(),
                },
                received.clone(),
                endpoint.inner.clone(),
                state_tx,
                None,
                None,
                tu_tx,
            )?;
            for status in [
                StatusCode::Trying,
                StatusCode::Ringing,
                StatusCode::OK,
                StatusCode::BusyHere,
            ] {
                for response in [
                    endpoint
                        .inner
                        .make_response(&received, status.clone(), None),
                    dialog.make_response(&received, status.clone(), None, None),
                ] {
                    let SipMessage::Response(wire) =
                        SipMessage::try_from(response.to_string().as_str())?
                    else {
                        panic!("expected response")
                    };
                    assert_eq!(wire.top_via_header()?.value(), top.value());
                    assert!(wire.to_string().contains(&caller_via));
                    assert_eq!(
                        TransactionKey::from_response(&wire, TransactionRole::Client)?,
                        key
                    );
                }
                let response = dialog.make_response(&received, status, None, None);
                assert_eq!(
                    response.record_route_headers(),
                    received.record_route_headers()
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn proxy_record_route_server_keeps_order_and_parameters() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let expected = [
        "<sip:127.0.0.1:5070;r2=on;lr>",
        "<sip:127.0.0.1:5060;r2=on;lr>",
        "<sip:other.example.com:5080;lr;edge=keep>",
    ];
    for fields in [
        expected.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        vec![expected.join(", ")],
        vec![expected[..2].join(", "), expected[2].into()],
    ] {
        let mut invite = create_invite_request("caller", "", "proxy-route-server");
        for field in fields {
            invite.headers.push(Header::RecordRoute(field.into()));
        }
        let (state_tx, _state_rx) = unbounded_channel();
        let (tu_tx, _tu_rx) = unbounded_channel();
        let dialog = DialogInner::new(
            TransactionRole::Server,
            DialogId {
                call_id: "proxy-route-server".into(),
                local_tag: "pbx".into(),
                remote_tag: "caller".into(),
            },
            invite,
            endpoint.inner.clone(),
            state_tx,
            None,
            None,
            tu_tx,
        )?;
        for method in [Method::Bye, Method::Invite] {
            let request = dialog.make_request(method, None, None, None, None, None)?;
            let routes: Vec<_> = request.route_headers().iter().map(|r| r.value()).collect();
            assert_eq!(routes, expected, "UAS must keep Record-Route order");
            assert_eq!(
                request.destination().to_string(),
                "sip:127.0.0.1:5070;r2=on;lr"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn proxy_record_route_client_reverses_values_across_header_fields() -> crate::Result<()> {
    let endpoint = create_test_endpoint().await?;
    let recorded = [
        "<sip:127.0.0.1:5070;r2=on;lr>",
        "<sip:127.0.0.1:5060;r2=on;lr>",
        "<sip:other.example.com:5080;lr;edge=keep>",
    ];
    let expected: Vec<_> = recorded.iter().rev().copied().collect();
    for fields in [
        recorded.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        vec![recorded.join(", ")],
        vec![recorded[..2].join(", "), recorded[2].into()],
    ] {
        let mut invite = create_invite_request("caller", "", "proxy-route-client");
        invite.headers.push(Header::RecordRoute(
            "<sip:request-only.example.com:5095;lr>".into(),
        ));
        let mut response: Response = endpoint.inner.make_response(&invite, StatusCode::OK, None);
        response
            .headers
            .push(Header::Contact("<sip:pbx@127.0.0.1:5090>".into()));
        for field in fields {
            response.headers.push(Header::RecordRoute(field.into()));
        }
        let (state_tx, _state_rx) = unbounded_channel();
        let (tu_tx, _tu_rx) = unbounded_channel();
        let dialog = DialogInner::new(
            TransactionRole::Client,
            DialogId {
                call_id: "proxy-route-client".into(),
                local_tag: "caller".into(),
                remote_tag: "pbx".into(),
            },
            invite.clone(),
            endpoint.inner.clone(),
            state_tx,
            None,
            None,
            tu_tx,
        )?;
        let before_response = dialog.make_request(Method::Options, None, None, None, None, None)?;
        assert!(
            before_response.route_headers().is_empty(),
            "UAC must not learn its route set from the outgoing request"
        );
        dialog.update_route_set_from_response(&response);
        for request in [
            endpoint.inner.make_ack(&invite, &response)?,
            dialog.make_request(Method::Bye, None, None, None, None, None)?,
            dialog.make_request(Method::Invite, None, None, None, None, None)?,
        ] {
            let routes: Vec<_> = request.route_headers().iter().map(|r| r.value()).collect();
            assert_eq!(
                routes, expected,
                "UAC must reverse entries, including combined fields"
            );
            assert_eq!(
                request.destination().to_string(),
                "sip:other.example.com:5080;lr;edge=keep"
            );
        }
    }
    Ok(())
}
