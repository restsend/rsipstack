use crate::{
    transaction::{key::TransactionRole, transaction::Transaction},
    Error, Result,
};
use rsip::{
    prelude::{HeadersExt, UntypedHeader},
    Request, Response,
};

pub mod authenticate;
pub mod client_dialog;
pub mod dialog;
pub mod dialog_layer;
pub mod invitation;
pub mod publication;
pub mod registration;
pub mod server_dialog;
pub mod subscription;

#[cfg(test)]
mod tests;

/// SIP Dialog Identifier
///
/// `DialogId` uniquely identifies a SIP dialog. According to RFC 3261, a dialog is
/// identified by the Call-ID, local tag, and remote tag.
///
/// # Fields
///
/// * `call_id` - The Call-ID header field value from SIP messages, identifying a call session
/// * `from_tag` - The tag parameter from the From header field, identifying the dialog initiator
/// * `to_tag` - The tag parameter from the To header field, identifying the dialog recipient
///
/// # Examples
///
/// ```rust
/// use rsipstack::dialog::DialogId;
///
/// let dialog_id = DialogId {
///     call_id: "1234567890@example.com".to_string(),
///     from_tag: "alice-tag-123".to_string(),
///     to_tag: "bob-tag-456".to_string(),
/// };
///
/// println!("Dialog ID: {}", dialog_id);
/// ```
///
/// # Notes
///
/// - During early dialog establishment, `to_tag` may be an empty string
/// - Dialog ID remains constant throughout the dialog lifetime
/// - Used for managing and routing SIP messages at the dialog layer
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

impl TryFrom<(&Request, TransactionRole)> for DialogId {
    type Error = crate::Error;

    fn try_from((request, direction): (&Request, TransactionRole)) -> Result<Self> {
        let call_id = request.call_id_header()?.value().to_string();

        let from_tag = match request.from_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("from tag not found".to_string())),
        };

        let to_tag = match request.to_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => "".to_string(),
        };

        match direction {
            TransactionRole::Client => Ok(DialogId {
                call_id,
                local_tag: from_tag,
                remote_tag: to_tag,
            }),
            TransactionRole::Server => Ok(DialogId {
                call_id,
                local_tag: to_tag,
                remote_tag: from_tag,
            }),
        }
    }
}

impl TryFrom<(&Response, TransactionRole)> for DialogId {
    type Error = crate::Error;

    fn try_from((resp, direction): (&Response, TransactionRole)) -> Result<Self> {
        let call_id = resp.call_id_header()?.value().to_string();

        let from_tag = match resp.from_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("from tag not found".to_string())),
        };

        let to_tag = match resp.to_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("to tag not found".to_string())),
        };

        match direction {
            TransactionRole::Client => Ok(DialogId {
                call_id,
                local_tag: from_tag,
                remote_tag: to_tag,
            }),
            TransactionRole::Server => Ok(DialogId {
                call_id,
                local_tag: to_tag,
                remote_tag: from_tag,
            }),
        }
    }
}

impl TryFrom<&Transaction> for DialogId {
    type Error = crate::Error;

    fn try_from(value: &Transaction) -> std::result::Result<Self, Self::Error> {
        DialogId::try_from((&value.original, value.role()))
    }
}

impl std::fmt::Display for DialogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}-{}", self.call_id, self.local_tag, self.remote_tag)
    }
}
