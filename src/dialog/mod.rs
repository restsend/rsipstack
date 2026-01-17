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
/// * `local_tag` - The tag identifying the local UA in the dialog
/// * `remote_tag` - The tag identifying the remote UA in the dialog
///
/// # Examples
///
/// ```rust
/// use rsipstack::dialog::DialogId;
///
/// let dialog_id = DialogId {
///     call_id: "1234567890@example.com".to_string(),
///     local_tag: "alice-tag-123".to_string(),
///     remote_tag: "bob-tag-456".to_string(),
/// };
///
/// println!("Dialog ID: {}", dialog_id);
/// ```
///
/// # Notes
///
/// - During early dialog establishment, `remote_tag` may be an empty string
/// - Dialog ID remains constant throughout the dialog lifetime
/// - Used for managing and routing SIP messages at the dialog layer
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

impl DialogId {
    /// Create a DialogId from a Request from the perspective of a UAC (sender).
    /// In this case from-tag is the local-tag and to-tag is the remote-tag.
    pub fn from_uac_request(request: &rsip::Request) -> Result<Self> {
        let call_id = request.call_id_header()?.value().to_string();

        let local_tag = match request.from_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("from tag not found".to_string())),
        };

        let remote_tag = match request.to_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => "".to_string(),
        };

        Ok(DialogId {
            call_id,
            local_tag,
            remote_tag,
        })
    }

    /// Create a DialogId from a Request from the perspective of a UAS (receiver).
    /// In this case to-tag is the local-tag and from-tag is the remote-tag.
    pub fn from_uas_request(request: &rsip::Request) -> Result<Self> {
        let call_id = request.call_id_header()?.value().to_string();

        let local_tag = match request.to_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => "".to_string(),
        };

        let remote_tag = match request.from_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("from tag not found".to_string())),
        };

        Ok(DialogId {
            call_id,
            local_tag,
            remote_tag,
        })
    }

    /// Create a DialogId from a Response from the perspective of a UAC.
    /// In this case from-tag is the local-tag and to-tag is the remote-tag.
    pub fn from_uac_response(resp: &rsip::Response) -> Result<Self> {
        let call_id = resp.call_id_header()?.value().to_string();

        let local_tag = match resp.from_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("from tag not found".to_string())),
        };

        let remote_tag = match resp.to_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("to tag not found".to_string())),
        };

        Ok(DialogId {
            call_id,
            local_tag,
            remote_tag,
        })
    }

    /// Create a DialogId from a Response from the perspective of a UAS.
    /// In this case to-tag is the local-tag and from-tag is the remote-tag.
    pub fn from_uas_response(resp: &rsip::Response) -> Result<Self> {
        let call_id = resp.call_id_header()?.value().to_string();

        let local_tag = match resp.to_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("to tag not found".to_string())),
        };

        let remote_tag = match resp.from_header()?.tag()? {
            Some(tag) => tag.value().to_string(),
            None => return Err(Error::Error("from tag not found".to_string())),
        };

        Ok(DialogId {
            call_id,
            local_tag,
            remote_tag,
        })
    }
}

impl TryFrom<&Request> for DialogId {
    type Error = crate::Error;

    /// Default to UAS perspective for incoming requests.
    /// NOTE: Possible dialog matching issues in self-call scenarios.
    /// Use DialogId::from_uas_request or from_uac_request instead.
    fn try_from(request: &Request) -> Result<Self> {
        Self::from_uas_request(request)
    }
}

impl TryFrom<&Response> for DialogId {
    type Error = crate::Error;

    /// Default to UAC perspective for incoming responses.
    /// NOTE: Possible dialog matching issues in self-call scenarios.
    /// Use DialogId::from_uas_response or from_uac_response instead.
    fn try_from(resp: &Response) -> Result<Self> {
        Self::from_uac_response(resp)
    }
}

impl std::fmt::Display for DialogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.remote_tag.is_empty() {
            write!(f, "{}-{}", self.call_id, self.local_tag)
        } else {
            write!(f, "{}-{}-{}", self.call_id, self.local_tag, self.remote_tag)
        }
    }
}
