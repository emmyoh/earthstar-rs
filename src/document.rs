use crate::address::Identity;
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct Document {
    pub author: Identity,
    pub text: String,
    pub text_hash: String,
    pub format: String,
    pub path: String,
    pub signature: String,
    pub timestamp: SystemTime,
    pub share: String,
    pub share_signature: String,
    pub delete_after: Option<Instant>,
    pub attachment_size: Option<i32>,
    pub attachment_hash: Option<String>,
}

impl Document {
    pub fn hash_text(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.text.as_bytes());
        format!("b{}", BASE32_NOPAD.encode(&hasher.finalize()))
    }

    pub fn timestamp_as_u128(&self) -> u128 {
        self.timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
    }

    pub fn validate_text_hash(&self) -> bool {
        self.text_hash.chars().nth(0).unwrap_or_default() == 'b'
            && self.text_hash.len() == 53
            && BASE32_NOPAD.decode(self.text_hash[1..].as_bytes()).is_ok()
            && self.text_hash == self.hash_text()
    }

    pub fn validate_timestamp(&self) -> bool {
        let timestamp_int = self.timestamp_as_u128();
        timestamp_int > (10 as u128).pow(13) && timestamp_int < (2 as u128).pow(53) - 2
    }
}
