use crate::address::Identity;
use data_encoding::BASE32_NOPAD;
use std::time::Instant;

pub struct Document {
    pub author: Identity,
    pub text: String,
    pub text_hash: String,
    pub format: String,
    pub path: String,
    pub signature: String,
    pub timestamp: Instant,
    pub share: String,
    pub share_signature: String,
    pub delete_after: Option<Instant>,
    pub attachment_size: Option<i32>,
    pub attachment_hash: Option<String>,
}

impl Document {
    pub fn validate_text_hash(&self) -> bool {
        self.text_hash.len() == 53 && BASE32_NOPAD.decode(self.text_hash[1..].as_bytes()).is_ok()
    }
}
