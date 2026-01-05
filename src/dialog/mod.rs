use crate::{Error, Result};
use rsip::{
    prelude::{HeadersExt, UntypedHeader},
    Request, Response,
};

pub mod authenticate;
pub mod client_dialog;
pub mod dialog;
pub mod dialog_layer;
pub mod invitation;
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
#[derive(Clone, Debug)]
pub struct DialogId {
    pub call_id: String,
    pub from_tag: String,
    pub to_tag: String,
}

impl PartialEq for DialogId {
    fn eq(&self, other: &DialogId) -> bool {
        if self.call_id != other.call_id {
            return false;
        }
        if self.from_tag == other.from_tag && self.to_tag == other.to_tag {
            return true;
        }
        if self.from_tag == other.to_tag && self.to_tag == other.from_tag {
            return true;
        }
        false
    }
}

impl Eq for DialogId {}
impl std::hash::Hash for DialogId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.call_id.hash(state);
        if self.from_tag > self.to_tag {
            self.from_tag.hash(state);
            self.to_tag.hash(state);
        } else {
            self.to_tag.hash(state);
            self.from_tag.hash(state);
        }
    }
}

impl TryFrom<&Request> for DialogId {
    type Error = crate::Error;

    fn try_from(request: &Request) -> Result<Self> {
        let call_id = request.call_id_header()?.value().to_string();

        let from_tag = match request.from_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("from tag not found".to_string())),
        };

        let to_tag = match request.to_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => "".to_string(),
        };

        Ok(DialogId {
            call_id,
            from_tag,
            to_tag,
        })
    }
}

impl TryFrom<&Response> for DialogId {
    type Error = crate::Error;

    fn try_from(resp: &Response) -> Result<Self> {
        let call_id = resp.call_id_header()?.value().to_string();

        let from_tag = match resp.from_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("from tag not found".to_string())),
        };

        let to_tag = match resp.to_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("to tag not found".to_string())),
        };

        Ok(DialogId {
            call_id,
            from_tag,
            to_tag,
        })
    }
}

impl std::fmt::Display for DialogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.from_tag > self.to_tag {
            if self.to_tag.is_empty() {
                write!(f, "{}-{}", self.call_id, self.from_tag)
            } else {
                write!(f, "{}-{}-{}", self.call_id, self.from_tag, self.to_tag)
            }
        } else {
            write!(f, "{}-{}-{}", self.call_id, self.to_tag, self.from_tag)
        }
    }
}
