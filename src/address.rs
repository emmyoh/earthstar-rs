use crate::error::{IdentityError, ShareAddressError};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::fmt::{self};

pub struct Identity {
    pub shortname: String,
    pub keypair: Keypair,
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "@{}.b{}",
            self.shortname,
            BASE32_NOPAD.encode(self.keypair.public.as_bytes())
        )
    }
}

impl Identity {
    pub fn new(shortname: String, keypair: Option<Keypair>) -> Result<Self, IdentityError> {
        if !(shortname.len() >= 1 && shortname.len() < 16) {
            return Err(IdentityError::InvalidLength);
        }
        if shortname
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() || !c.is_ascii_lowercase())
        {
            return Err(IdentityError::InvalidCharacters);
        }
        if shortname.chars().nth(0).unwrap_or('0').is_ascii_digit() {
            return Err(IdentityError::StartsWithDigit);
        }
        let keypair = match keypair {
            Some(kp) => kp,
            None => {
                let mut csprng = OsRng {};
                Keypair::generate(&mut csprng)
            }
        };
        Ok(Self { shortname, keypair })
    }
}

pub struct ShareAddress {
    pub name: String,
    pub keypair: Keypair,
}

impl fmt::Display for ShareAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "+{}.b{}",
            self.name,
            BASE32_NOPAD.encode(self.keypair.public.as_bytes())
        )
    }
}

impl ShareAddress {
    pub fn new(name: String, keypair: Option<Keypair>) -> Result<Self, ShareAddressError> {
        if !(name.len() >= 1 && name.len() < 16) {
            return Err(ShareAddressError::InvalidLength);
        }
        if name
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() || !c.is_ascii_lowercase())
        {
            return Err(ShareAddressError::InvalidCharacters);
        }
        if name.chars().nth(0).unwrap_or('0').is_ascii_digit() {
            return Err(ShareAddressError::StartsWithDigit);
        }
        let keypair = match keypair {
            Some(kp) => kp,
            None => {
                let mut csprng = OsRng {};
                Keypair::generate(&mut csprng)
            }
        };
        Ok(Self { name, keypair })
    }
}
