use miette::Diagnostic;
use thiserror::Error;

#[derive(Error, Diagnostic, Debug)]
pub enum ShareAddressError {
    #[error("Share name uses invalid characters. Only lowercase, alphanumeric ASCII characters are allowed.")]
    #[diagnostic(code(share_address::name::invalid_characters))]
    InvalidCharacters,
    #[error("Share name is of invalid length. Must be between 1 (inclusive) and 16 (exclusive) characters long.")]
    #[diagnostic(code(share_address::name::invalid_length))]
    InvalidLength,
    #[error("Share name cannot start with a digit.")]
    #[diagnostic(code(share_address::name::starts_with_digit))]
    StartsWithDigit,
}

#[derive(Error, Diagnostic, Debug)]
pub enum IdentityError {
    #[error("Identity shortname uses invalid characters. Only lowercase, alphanumeric ASCII characters are allowed.")]
    #[diagnostic(code(identity::name::invalid_characters))]
    InvalidCharacters,
    #[error("Identity shortname is of invalid length. Must be between 1 (inclusive) and 5 (exclusive) characters long.")]
    #[diagnostic(code(identity::name::invalid_length))]
    InvalidLength,
    #[error("Identity shortname cannot start with a digit.")]
    #[diagnostic(code(identity::name::starts_with_digit))]
    StartsWithDigit,
}
