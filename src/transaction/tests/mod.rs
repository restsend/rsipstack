use super::{endpoint::Endpoint, EndpointBuilder};
use crate::{
    transport::{udp::UdpConnection, TransportLayer},
    Result,
};
use tokio_util::sync::CancellationToken;

mod test_client;
mod test_endpoint;
mod test_provisional_responses;
mod test_server;
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
    use crate::{
        rsip_ext::extract_uri_from_contact,
        transaction::{make_via_branch, random_text},
    };
    #[test]
    fn test_random_text() {
        let text = random_text(10);
        assert_eq!(text.len(), 10);
        let branch = make_via_branch();
        let branch = branch.to_string();
        assert_eq!(branch.len(), 27); // ;branch=z9hG4bK
    }

    #[test]
    fn test_linphone_contact() {
        let line = "sip:bob@localhost;transport=udp";
        let contact_uri = extract_uri_from_contact(line).expect("failed to parse contact");
        assert_eq!(contact_uri.to_string(), "sip:bob@localhost");

        let line = "<sip:bob@localhost;transport=udp>;expires=3600;+org.linphone.specs=\"lime\"";
        let contact_uri = extract_uri_from_contact(line).expect("failed to parse contact");
        assert_eq!(contact_uri.to_string(), "sip:bob@localhost");

        let line = "<sip:bob@restsend.com;transport=udp>;message-expires=2419200;+sip.instance=\"<urn:uuid:12345-81fa-4fe3-aa6c-17bffdbcf619>\"";
        let contact_uri = extract_uri_from_contact(line).expect("failed to parse contact");
        assert_eq!(contact_uri.to_string(), "sip:bob@restsend.com");
        let line = "<sip:linphone@domain.com;gr=urn:uuid:c8651907-f0b2-0027-bdbd-ce4ed05c9ef4>;+org.linphone.specs=\"ephemeral/1.1,groupchat/1.1,lime\"";
        let contact_uri = extract_uri_from_contact(line).expect("failed to parse contact");
        assert_eq!(
            contact_uri.to_string(),
            "sip:linphone@domain.com;gr=urn:uuid:c8651907-f0b2-0027-bdbd-ce4ed05c9ef4"
        );
    }
}
