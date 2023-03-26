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

#[derive(Error, Diagnostic, Debug)]
pub enum DocumentError {
    #[error("Document text must be less than or equal to 8 000 bytes, and cannot be empty if an attachment is present.")]
    #[diagnostic(code(document::invalid_text))]
    InvalidText,
    #[error("Document text hash must be a valid SHA-256 hash of the document text, encoded in Base32 (RFC 4648, no padding) with a leading `b'.")]
    #[diagnostic(code(document::invalid_text_hash))]
    InvalidTextHash,
    #[error("Document format must be a string of printable ASCII characters.")]
    #[diagnostic(code(document::invalid_format))]
    InvalidFormat,
    #[error("Document path must be:\n- a string of printable ASCII characters\n- a string of valid URL path characters (ie, cannot include any of the following characters, `<>\"[\\]^`{{|}}')\n- cannot include `#', `?', or `;'\n- can only contain a file extension if an attachment is present\n- is a path that the document author is allowed to write to.")]
    #[diagnostic(code(document::invalid_path))]
    InvalidPath,
    #[error("Document signature must be a valid Ed25519 signature of the document, encoded in Base32 (RFC 4648, no padding) with a leading `b', with a total length of 104 characters (in `es.5' format).")]
    #[diagnostic(code(document::invalid_signature))]
    InvalidSignature,
    #[error("Document timestamp must be a valid Unix timestamp in microseconds, between 10^13 and 2^53 - 2, inclusive.")]
    #[diagnostic(code(document::invalid_timestamp))]
    InvalidTimestamp,
    #[error("Document share signature must be encoded in Base32 (RFC 4648, no padding) with a leading `b', with a total length of 104 characters (in `es.5' format).")]
    #[diagnostic(code(document::invalid_share_signature))]
    InvalidShareSignature,
    #[error("Document `delete_after' timestamp must be a valid Unix timestamp in microseconds, between 10^13 and 2^53 - 2, inclusive, and must be strictly greater than the document timestamp.")]
    #[diagnostic(code(document::invalid_delete_after))]
    InvalidDeleteAfter,
    #[error("Document attachment size must be an integer between 0 and 2^53 - 2, inclusive.")]
    #[diagnostic(code(document::invalid_attachment_size))]
    InvalidAttachmentSize,
    #[error("Document attachment hash must be a valid SHA-256 hash of the attachment, encoded in Base32 (RFC 4648, no padding) with a leading `b', with a total length of 53 characters.")]
    #[diagnostic(code(document::invalid_attachment_hash))]
    InvalidAttachmentHash,
}
