use crate::{
    address::{Identity, ShareAddress},
    error::DocumentError,
};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{ed25519::signature::Signature, Signer};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Document {
    pub author: Identity,
    pub text: String,
    pub text_hash: String,
    pub format: String,
    pub path: String,
    pub signature: String,
    pub timestamp: SystemTime,
    pub share: ShareAddress,
    pub share_signature: String,
    pub delete_after: Option<SystemTime>,
    pub attachment_size: Option<i32>,
    pub attachment_hash: Option<String>,
}

impl Document {
    pub fn new(
        author: Identity,
        text: String,
        text_hash: Option<String>,
        format: String,
        path: String,
        signature: String,
        timestamp: SystemTime,
        share: ShareAddress,
        share_signature: String,
        delete_after: Option<SystemTime>,
        attachment_size: Option<i32>,
        attachment_hash: Option<String>,
    ) -> Result<Self, DocumentError> {
        let document = Self {
            author,
            text: text.clone(),
            text_hash: text_hash.unwrap_or(Document::hash_text(text)),
            format,
            path,
            signature,
            timestamp,
            share,
            share_signature,
            delete_after,
            attachment_size,
            attachment_hash,
        };

        if !document.validate_text() {
            return Err(DocumentError::InvalidText);
        }

        if !document.validate_text_hash() {
            return Err(DocumentError::InvalidTextHash);
        }

        if !document.validate_format() {
            return Err(DocumentError::InvalidFormat);
        }

        if !document.validate_path() {
            return Err(DocumentError::InvalidPath);
        }

        if !document.validate_signature() {
            return Err(DocumentError::InvalidSignature);
        }

        if !document.validate_timestamp() {
            return Err(DocumentError::InvalidTimestamp);
        }

        if !document.validate_share_signature() {
            return Err(DocumentError::InvalidShareSignature);
        }

        if !document.validate_delete_after() {
            return Err(DocumentError::InvalidDeleteAfter);
        }

        if !document.validate_attachment_size() {
            return Err(DocumentError::InvalidAttachmentSize);
        }

        if !document.validate_attachment_hash() {
            return Err(DocumentError::InvalidAttachmentHash);
        }

        Ok(document)
    }

    pub fn hash_document(&self) -> String {
        let mut hasher = Sha256::new();
        if self.attachment_hash.is_some() && self.attachment_size.is_some() {
            hasher.update(format!(
                "attachment_hash\t{}\nattachment_size\t{}\n",
                self.attachment_hash.as_ref().unwrap_or(&String::default()),
                self.attachment_size.as_ref().unwrap_or(&i32::default())
            ));
        }
        hasher.update(format!("author\t{}\ndelete_after\t{}\nformat\t{}\npath\t{}\nshare\t{}\nshare_signature\t{}\ntext_hash\t{}\ntimestamp\t{}\n", self.author, self.delete_after_as_u128(), self.format, self.path, self.share, self.share_signature, self.text_hash, self.timestamp_as_u128()));
        format!("b{}", BASE32_NOPAD.encode(&hasher.finalize()))
    }

    pub fn hash_text(text: String) -> String {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        format!("b{}", BASE32_NOPAD.encode(&hasher.finalize()))
    }

    pub fn timestamp_as_u128(&self) -> u128 {
        self.timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
    }

    pub fn delete_after_as_u128(&self) -> u128 {
        self.delete_after
            .map(|delete_after| {
                delete_after
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros()
            })
            .unwrap_or_default()
    }

    pub fn validate_text(&self) -> bool {
        self.text.as_bytes().len() <= 8000
            && (self.attachment_hash.is_some()
                && self.attachment_size.is_some()
                && !self.text.is_empty()
                || self.attachment_hash.is_none()
                    && self.attachment_size.is_none()
                    && self.text.is_empty())
    }

    pub fn validate_text_hash(&self) -> bool {
        self.text_hash.chars().nth(0).unwrap_or_default() == 'b'
            && self.text_hash.len() == 53
            && BASE32_NOPAD.decode(self.text_hash[1..].as_bytes()).is_ok()
            && self.text_hash == Document::hash_text(self.text.clone())
    }

    pub fn validate_timestamp(&self) -> bool {
        let timestamp_int = self.timestamp_as_u128();
        timestamp_int >= (10 as u128).pow(13) && timestamp_int <= (2 as u128).pow(53) - 2
    }

    pub fn validate_delete_after(&self) -> bool {
        self.delete_after
            .map(|delete_after| {
                let delete_after_int = delete_after
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros();
                delete_after_int >= (10 as u128).pow(13)
                    && delete_after_int <= (2 as u128).pow(53) - 2
                    && delete_after > self.timestamp
            })
            .unwrap_or_default()
    }

    pub fn validate_format(&self) -> bool {
        self.format.is_ascii()
            && !self.format.contains(|c: char| c.is_ascii_whitespace())
            && !self.format.contains(|c: char| c.is_ascii_control())
    }

    pub fn validate_path(&self) -> bool {
        self.path.is_ascii()
            && !self.path.contains(|c: char| c.is_ascii_whitespace())
            && !self.path.contains(|c: char| c.is_ascii_control())
            && self.path.len() >= 2
            && self.path.len() <= 512
            && self.path.chars().nth(0).unwrap_or_default() == '/'
            && &self.path[0..2] != "/@"
            && !self.path.contains("//")
            && ((self.delete_after.is_none() && !self.path.contains("!"))
                || (self.delete_after.is_some() && self.path.contains("!")))
            && !self.path.contains("?")
            && !self.path.contains("#")
            && !self.path.contains(";")
            && !self.path.contains("<")
            && !self.path.contains(">")
            && !self.path.contains("\"")
            && !self.path.contains("[")
            && !self.path.contains("\\")
            && !self.path.contains("]")
            && !self.path.contains("^")
            && !self.path.contains("{")
            && !self.path.contains("|")
            && !self.path.contains("}")
            && (self.attachment_hash.is_some()
                && self.attachment_size.is_some()
                && Path::new(&self.path).extension().is_some()
                || self.attachment_hash.is_none()
                    && self.attachment_size.is_none()
                    && Path::new(&self.path).extension().is_none())
            && (!self.path.contains("~")
                || self
                    .path
                    .contains(&("~@".to_owned() + &self.author.shortname)))
    }

    pub fn validate_signature(&self) -> bool {
        self.signature.chars().nth(0).unwrap_or_default() == 'b'
            && BASE32_NOPAD.decode(self.signature[1..].as_bytes()).is_ok()
            && ((self.format == "es.5" && self.signature.len() == 104) || self.format != "es.5")
            && self.signature
                == format!(
                    "b{}",
                    BASE32_NOPAD.encode(
                        &self
                            .author
                            .keypair
                            .sign(&self.hash_document().as_bytes())
                            .as_bytes()
                    )
                )
    }

    pub fn validate_share_signature(&self) -> bool {
        self.share_signature.chars().nth(0).unwrap_or_default() == 'b'
            && BASE32_NOPAD
                .decode(self.share_signature[1..].as_bytes())
                .is_ok()
            && ((self.format == "es.5" && self.share_signature.len() == 104)
                || self.format != "es.5")
    }

    pub fn validate_attachment_size(&self) -> bool {
        self.attachment_size
            .map(|attachment_size| attachment_size >= 0 && attachment_size <= 2_i32.pow(53) - 2)
            .unwrap_or_default()
    }

    pub fn validate_attachment_hash(&self) -> bool {
        self.attachment_hash
            .as_ref()
            .map(|attachment_hash| {
                attachment_hash.chars().nth(0).unwrap_or_default() == 'b'
                    && attachment_hash.len() == 53
                    && BASE32_NOPAD.decode(attachment_hash[1..].as_bytes()).is_ok()
            })
            .unwrap_or_default()
    }
}
