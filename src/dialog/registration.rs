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
    Result,
};
use rsip::{Response, SipMessage, StatusCode};
use tracing::info;

pub struct Registration {
    pub last_seq: u32,
    pub endpoint: EndpointInnerRef,
    pub credential: Option<Credential>,
    pub contact: Option<rsip::typed::Contact>,
    pub allow: rsip::headers::Allow,
}

impl Registration {
    pub fn new(endpoint: EndpointInnerRef, credential: Option<Credential>) -> Self {
        Self {
            last_seq: 0,
            endpoint,
            credential,
            contact: None,
            allow: Default::default(),
        }
    }

    pub fn expires(&self) -> u32 {
        self.contact
            .as_ref()
            .and_then(|c| c.expires())
            .map(|e| e.seconds().unwrap_or(50))
            .unwrap_or(50)
    }

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

        let first_addr = self
            .endpoint
            .get_addrs()
            .first()
            .ok_or(crate::Error::Error("no address found".to_string()))?
            .clone();

        let contact = self
            .contact
            .clone()
            .unwrap_or_else(|| rsip::typed::Contact {
                display_name: None,
                uri: rsip::Uri {
                    auth: to.uri.auth.clone(),
                    scheme: Some(rsip::Scheme::Sip),
                    host_with_port: first_addr.addr.into(),
                    params: vec![],
                    headers: vec![],
                },
                params: vec![],
            });
        let via = self.endpoint.get_via(None)?;
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
                        if auth_sent {
                            info!("received {} response after auth sent", resp.status_code);
                            return Ok(resp);
                        }

                        if let Some(cred) = &self.credential {
                            self.last_seq += 1;
                            tx = handle_client_authenticate(self.last_seq, tx, resp, cred).await?;
                            tx.send().await?;
                            auth_sent = true;
                            continue;
                        } else {
                            info!("received {} response without credential", resp.status_code);
                            return Ok(resp);
                        }
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
}
