use super::{endpoint::Endpoint, EndpointBuilder};
use crate::{
    transport::{udp::UdpConnection, TransportLayer},
    Result,
};
use tokio_util::sync::CancellationToken;

mod test_before_send;
mod test_client;
mod test_endpoint;
mod test_provisional_responses;
mod test_server;
mod test_server_invite_drop;
mod test_transaction_states;

pub(super) async fn create_test_endpoint(addr: Option<&str>) -> Result<Endpoint> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());

    if let Some(addr) = addr {
        let peer = UdpConnection::create_connection(addr.parse()?, None, None).await?;
        tl.add_transport(peer.into());
    }

    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .build();
    Ok(endpoint)
}
#[cfg(test)]
mod tests {
    use super::{Endpoint, EndpointBuilder};
    use crate::{
        dialog::registration::Registration,
        sip::{
            prelude::HeadersExt,
            typed::{Contact, From, To},
            {Method, Param, Transport},
        },
        transaction::{
            endpoint::EndpointOption,
            {make_call_id, make_tag, make_uuid_v4, make_via_branch, random_text, CallIdFormat},
        },
        transport::SipAddr,
        Result,
    };
    #[test]
    fn test_random_text() {
        let text = random_text(10);
        assert_eq!(text.len(), 10);
        let branch = make_via_branch();
        let branch = branch.to_string();
        assert_eq!(branch.len(), 27); // ;branch=z9hG4bK
    }

    fn assert_uuid_v4(s: &str) {
        // Dashes-free 32-char hex form (see make_uuid_v4).
        assert_eq!(s.len(), 32);
        let chars: Vec<char> = s.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            match i {
                12 => assert_eq!(*c, '4'),
                16 => assert!(matches!(c, '8' | '9' | 'a' | 'b')),
                _ => assert!(c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            }
        }
    }

    #[test]
    fn test_make_uuid_v4() {
        assert_uuid_v4(&make_uuid_v4());
        assert_ne!(make_uuid_v4(), make_uuid_v4());
    }

    #[test]
    fn test_make_call_id() {
        let call_id = make_call_id(None, CallIdFormat::UuidWithSuffix).0;
        let (uuid, suffix) = call_id.split_once('@').unwrap();
        assert_uuid_v4(uuid);
        assert_eq!(suffix, "restsend.com");

        let call_id = make_call_id(Some("example.com"), CallIdFormat::UuidWithSuffix).0;
        let (uuid, suffix) = call_id.split_once('@').unwrap();
        assert_uuid_v4(uuid);
        assert_eq!(suffix, "example.com");

        let call_id = make_call_id(Some("example.com"), CallIdFormat::Uuid).0;
        assert_uuid_v4(&call_id);
        assert!(!call_id.contains('@'));

        let call_id = make_call_id(None, CallIdFormat::Uuid).0;
        assert_uuid_v4(&call_id);
    }

    #[test]
    fn test_callid_format_default() {
        assert_eq!(CallIdFormat::default(), CallIdFormat::UuidWithSuffix);
        assert_eq!(
            EndpointOption::default().callid_format,
            CallIdFormat::UuidWithSuffix
        );
    }

    fn build_endpoint(option: EndpointOption) -> Endpoint {
        EndpointBuilder::new()
            .with_user_agent("rsipstack-test")
            .with_option(option)
            .build()
    }

    fn udp_sip_addr() -> crate::Result<SipAddr> {
        Ok(SipAddr {
            r#type: Some(Transport::Udp),
            addr: "127.0.0.1:5060".try_into()?,
        })
    }

    #[test]
    fn test_make_request_callid_format() -> Result<()> {
        let endpoint = build_endpoint(EndpointOption::default());
        let via = endpoint.inner.get_via(Some(udp_sip_addr()?), None)?;
        let req = endpoint.inner.make_request(
            Method::Register,
            "sip:example.com".try_into()?,
            via,
            From {
                display_name: None,
                uri: "sip:alice@example.com".try_into()?,
                params: vec![Param::Tag(make_tag())],
            },
            To {
                display_name: None,
                uri: "sip:bob@example.com".try_into()?,
                params: vec![],
            },
            1,
            None,
        );
        let call_id = req.call_id_header()?.value().to_string();
        let (uuid, suffix) = call_id.split_once('@').unwrap();
        assert_uuid_v4(uuid);
        assert_eq!(suffix, "restsend.com");

        let endpoint = build_endpoint(EndpointOption {
            callid_suffix: Some("example.com".into()),
            callid_format: CallIdFormat::Uuid,
            ..Default::default()
        });
        let via = endpoint.inner.get_via(Some(udp_sip_addr()?), None)?;
        let req = endpoint.inner.make_request(
            Method::Register,
            "sip:example.com".try_into()?,
            via,
            From {
                display_name: None,
                uri: "sip:alice@example.com".try_into()?,
                params: vec![Param::Tag(make_tag())],
            },
            To {
                display_name: None,
                uri: "sip:bob@example.com".try_into()?,
                params: vec![],
            },
            1,
            None,
        );
        let call_id = req.call_id_header()?.value().to_string();
        assert_uuid_v4(&call_id);
        assert!(!call_id.contains('@'));
        Ok(())
    }

    #[test]
    fn test_registration_callid_format() -> Result<()> {
        let endpoint = build_endpoint(EndpointOption::default());
        let reg = Registration::new(endpoint.inner.clone(), None);
        let (uuid, suffix) = reg.call_id.0.split_once('@').unwrap();
        assert_uuid_v4(uuid);
        assert_eq!(suffix, "restsend.com");

        let endpoint = build_endpoint(EndpointOption {
            callid_format: CallIdFormat::Uuid,
            ..Default::default()
        });
        let reg = Registration::new(endpoint.inner.clone(), None);
        assert_uuid_v4(&reg.call_id.0);
        assert!(!reg.call_id.0.contains('@'));
        Ok(())
    }

    #[test]
    fn test_linphone_contact() {
        let line = "sip:bob@localhost;transport=udp";
        let contact_uri = Contact::parse(line).expect("failed to parse contact").uri;
        assert_eq!(contact_uri.to_string(), "sip:bob@localhost");

        let line = "<sip:bob@localhost;transport=udp>;expires=3600;+org.linphone.specs=\"lime\"";
        let contact_uri = Contact::parse(line).expect("failed to parse contact").uri;
        assert_eq!(contact_uri.to_string(), "sip:bob@localhost");

        let line = "<sip:bob@restsend.com;transport=udp>;message-expires=2419200;+sip.instance=\"<urn:uuid:12345-81fa-4fe3-aa6c-17bffdbcf619>\"";
        let contact_uri = Contact::parse(line).expect("failed to parse contact").uri;
        assert_eq!(contact_uri.to_string(), "sip:bob@restsend.com");
        let line = "<sip:linphone@domain.com;gr=urn:uuid:c8651907-f0b2-0027-bdbd-ce4ed05c9ef4>;+org.linphone.specs=\"ephemeral/1.1,groupchat/1.1,lime\"";
        let contact_uri = Contact::parse(line).expect("failed to parse contact").uri;
        assert_eq!(
            contact_uri.to_string(),
            "sip:linphone@domain.com;gr=urn:uuid:c8651907-f0b2-0027-bdbd-ce4ed05c9ef4"
        );
    }
}
