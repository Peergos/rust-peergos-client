//! Email message and attachment types, a faithful port of
//! `peergos.shared.email.EmailMessage` and `peergos.shared.email.Attachment`.
//!
//! The CBOR wire format is bit-for-bit compatible with the Java implementation:
//! the outer wrapper is `[18, map]` where 18 is `CBOR_PEERGOS_EMAIL_INT`, and
//! every field key matches the Java `TreeMap` ordering.

use peergos_cbor::{CborObject, Cborable};
use peergos_core::error::{Error, Result};

/// `MimeTypes.CBOR_PEERGOS_EMAIL_INT` — the MIME-type tag wrapping every
/// serialized email.
pub const CBOR_PEERGOS_EMAIL_INT: i64 = 18;

const VERSION_1: &str = "1";

// ---------------------------------------------------------------------------
// Attachment
// ---------------------------------------------------------------------------

/// An email attachment (`Attachment`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub size: i64,
    pub mime_type: String,
    pub uuid: String,
}

impl Attachment {
    pub fn new(filename: impl Into<String>, size: i64, mime_type: impl Into<String>, uuid: impl Into<String>) -> Self {
        Attachment {
            filename: filename.into(),
            size,
            mime_type: mime_type.into(),
            uuid: uuid.into(),
        }
    }
}

impl Cborable for Attachment {
    /// CBOR map with keys `f`, `s`, `t`, `u` matching Java's `Attachment.toCbor`.
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("f", CborObject::Str(self.filename.clone()))
            .put("s", CborObject::Long(self.size))
            .put("t", CborObject::Str(self.mime_type.clone()))
            .put("u", CborObject::Str(self.uuid.clone()))
            .build()
    }
}

impl Attachment {
    pub fn from_cbor(cbor: &CborObject) -> Result<Attachment> {
        if cbor.as_map().is_none() {
            return Err(Error::Cbor("Attachment not a map".into()));
        }
        Ok(Attachment {
            filename: cbor.get("f").and_then(|c| c.as_string()).ok_or_else(|| Error::Cbor("Attachment missing 'f'".into()))?.to_string(),
            size: cbor.get("s").and_then(|c| c.as_long()).unwrap_or(0),
            mime_type: cbor.get("t").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            uuid: cbor.get("u").and_then(|c| c.as_string()).unwrap_or("").to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// EmailMessage
// ---------------------------------------------------------------------------

/// An email message (`EmailMessage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailMessage {
    pub id: String,
    pub msg_id: String,
    pub from: String,
    pub subject: String,
    pub created: i64,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub content: String,
    pub unread: bool,
    pub star: bool,
    pub attachments: Vec<Attachment>,
    pub ical_event: String,
    pub replying_to_email: Option<Box<EmailMessage>>,
    pub forwarding_to_email: Option<Box<EmailMessage>>,
    pub send_error: Option<String>,
}

impl EmailMessage {
    /// Create a new email message with sensible defaults.
    pub fn new(
        id: impl Into<String>,
        from: impl Into<String>,
        subject: impl Into<String>,
        to: Vec<String>,
        content: impl Into<String>,
    ) -> Self {
        EmailMessage {
            id: id.into(),
            msg_id: String::new(),
            from: from.into(),
            subject: subject.into(),
            created: now_epoch_secs(),
            to,
            cc: Vec::new(),
            bcc: Vec::new(),
            content: content.into(),
            unread: true,
            star: false,
            attachments: Vec::new(),
            ical_event: String::new(),
            replying_to_email: None,
            forwarding_to_email: None,
            send_error: None,
        }
    }

    /// Prepare the message for sending: set the message id, from address, and
    /// timestamp (`EmailMessage.prepare`).
    pub fn prepare(&self, generated_msg_id: String, from_email: String, sent_time: i64) -> EmailMessage {
        EmailMessage {
            id: self.id.clone(),
            msg_id: generated_msg_id,
            from: from_email,
            subject: self.subject.clone(),
            created: sent_time,
            to: self.to.clone(),
            cc: self.cc.clone(),
            bcc: self.bcc.clone(),
            content: self.content.clone(),
            unread: self.unread,
            star: self.star,
            attachments: self.attachments.clone(),
            ical_event: self.ical_event.clone(),
            replying_to_email: self.replying_to_email.clone(),
            forwarding_to_email: self.forwarding_to_email.clone(),
            send_error: self.send_error.clone(),
        }
    }

    /// Return a copy with replaced attachments (`EmailMessage.withAttachments`).
    pub fn with_attachments(&self, attachments: Vec<Attachment>) -> EmailMessage {
        EmailMessage {
            id: self.id.clone(),
            msg_id: self.msg_id.clone(),
            from: self.from.clone(),
            subject: self.subject.clone(),
            created: self.created,
            to: self.to.clone(),
            cc: self.cc.clone(),
            bcc: self.bcc.clone(),
            content: self.content.clone(),
            unread: self.unread,
            star: self.star,
            attachments,
            ical_event: self.ical_event.clone(),
            replying_to_email: self.replying_to_email.clone(),
            forwarding_to_email: self.forwarding_to_email.clone(),
            send_error: self.send_error.clone(),
        }
    }

    /// Return a copy with a send error set (`EmailMessage.withError`).
    pub fn with_error(&self, error: impl Into<String>) -> EmailMessage {
        EmailMessage {
            id: self.id.clone(),
            msg_id: self.msg_id.clone(),
            from: self.from.clone(),
            subject: self.subject.clone(),
            created: self.created,
            to: self.to.clone(),
            cc: self.cc.clone(),
            bcc: self.bcc.clone(),
            content: self.content.clone(),
            unread: self.unread,
            star: self.star,
            attachments: self.attachments.clone(),
            ical_event: self.ical_event.clone(),
            replying_to_email: self.replying_to_email.clone(),
            forwarding_to_email: self.forwarding_to_email.clone(),
            send_error: Some(error.into()),
        }
    }
}

impl Cborable for EmailMessage {
    /// CBOR: `[18, {"v":"1", "i":id, "m":msgId, "f":from, "h":subject,
    ///   "t":epochSecs, "d":to, "c":cc, "b":bcc, "z":content, "u":unread,
    ///   "s":star, "a":attachments, "e":icalEvent,
    ///   "r":replyingTo?, "o":forwardingTo?, "x":sendError?}]`
    fn to_cbor(&self) -> CborObject {
        let mut m = CborObject::map()
            .put("v", CborObject::Str(VERSION_1.to_string()))
            .put("i", CborObject::Str(self.id.clone()))
            .put("m", CborObject::Str(self.msg_id.clone()))
            .put("f", CborObject::Str(self.from.clone()))
            .put("h", CborObject::Str(self.subject.clone()))
            .put("t", CborObject::Long(self.created))
            .put("d", CborObject::List(self.to.iter().map(|s| CborObject::Str(s.clone())).collect()))
            .put("c", CborObject::List(self.cc.iter().map(|s| CborObject::Str(s.clone())).collect()))
            .put("b", CborObject::List(self.bcc.iter().map(|s| CborObject::Str(s.clone())).collect()))
            .put("z", CborObject::Str(self.content.clone()))
            .put("u", CborObject::Boolean(self.unread))
            .put("s", CborObject::Boolean(self.star))
            .put("a", CborObject::List(self.attachments.iter().map(Cborable::to_cbor).collect()))
            .put("e", CborObject::Str(self.ical_event.clone()));

        if let Some(r) = &self.replying_to_email {
            m = m.put("r", r.to_cbor());
        }
        if let Some(o) = &self.forwarding_to_email {
            m = m.put("o", o.to_cbor());
        }
        if let Some(x) = &self.send_error {
            m = m.put("x", CborObject::Str(x.clone()));
        }

        CborObject::List(vec![CborObject::Long(CBOR_PEERGOS_EMAIL_INT), m.build()])
    }
}

impl EmailMessage {
    pub fn from_cbor(cbor: &CborObject) -> Result<EmailMessage> {
        let list = cbor.as_list().ok_or_else(|| Error::Cbor("EmailMessage not a list".into()))?;
        let mime_tag = list.first().and_then(|c| c.as_long())
            .ok_or_else(|| Error::Cbor("EmailMessage missing mime tag".into()))?;
        if mime_tag != CBOR_PEERGOS_EMAIL_INT {
            return Err(Error::Cbor(format!("bad EmailMessage mime tag: {mime_tag}")));
        }
        let m = list.get(1).ok_or_else(|| Error::Cbor("EmailMessage missing body map".into()))?;

        let version = m.get("v").and_then(|c| c.as_string()).unwrap_or("");
        if version != VERSION_1 {
            return Err(Error::Cbor(format!("unsupported EmailMessage version: {version}")));
        }

        Ok(EmailMessage {
            id: m.get("i").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            msg_id: m.get("m").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            from: m.get("f").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            subject: m.get("h").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            created: m.get("t").and_then(|c| c.as_long()).unwrap_or(0),
            to: string_list(m, "d"),
            cc: string_list(m, "c"),
            bcc: string_list(m, "b"),
            content: m.get("z").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            unread: m.get("u").and_then(|c| c.as_bool()).unwrap_or(true),
            star: m.get("s").and_then(|c| c.as_bool()).unwrap_or(false),
            attachments: m.get("a")
                .and_then(|c| c.as_list())
                .unwrap_or(&[])
                .iter()
                .map(Attachment::from_cbor)
                .collect::<Result<Vec<_>>>()?,
            ical_event: m.get("e").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            replying_to_email: m.get("r")
                .map(|c| EmailMessage::from_cbor(c).map(Box::new))
                .transpose()?,
            forwarding_to_email: m.get("o")
                .map(|c| EmailMessage::from_cbor(c).map(Box::new))
                .transpose()?,
            send_error: m.get("x").and_then(|c| c.as_string()).map(|s| s.to_string()),
        })
    }
}

/// Extract a list of strings from a CBOR map key.
fn string_list(m: &CborObject, key: &str) -> Vec<String> {
    m.get(key)
        .and_then(|c| c.as_list())
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| c.as_string().map(|s| s.to_string()))
        .collect()
}

fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_round_trip() {
        let a = Attachment::new("test.pdf", 1024, "application/pdf", "uuid-123");
        let cbor = a.to_cbor();
        let decoded = Attachment::from_cbor(&cbor).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn email_message_round_trip() {
        let msg = EmailMessage {
            id: "id-1".into(),
            msg_id: "msgid-1".into(),
            from: "alice@example.com".into(),
            subject: "Hello".into(),
            created: 1700000000,
            to: vec!["bob@example.com".into()],
            cc: vec![],
            bcc: vec![],
            content: "Hi Bob!".into(),
            unread: true,
            star: false,
            attachments: vec![Attachment::new("file.txt", 100, "text/plain", "att-1")],
            ical_event: String::new(),
            replying_to_email: None,
            forwarding_to_email: None,
            send_error: None,
        };
        let cbor = msg.to_cbor();
        let decoded = EmailMessage::from_cbor(&cbor).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn email_mime_tag_prefix() {
        let msg = EmailMessage::new("id", "from@x.com", "subj", vec![], "body");
        let bytes = msg.serialize();
        // First two bytes: cbor array(2) + long(18) = [0x82, 0x12]
        assert_eq!(bytes[0], 0x82);
        assert_eq!(bytes[1], 18);
    }

    #[test]
    fn nested_reply_round_trip() {
        let inner = EmailMessage::new("inner", "bob@x.com", "Re: Hi", vec![], "original");
        let outer = EmailMessage {
            replying_to_email: Some(Box::new(inner.clone())),
            ..EmailMessage::new("outer", "alice@x.com", "Re: Re: Hi", vec![], "reply")
        };
        let cbor = outer.to_cbor();
        let decoded = EmailMessage::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.replying_to_email.as_ref().unwrap().id, "inner");
    }
}
