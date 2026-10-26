//! Reading the credentials for `add-endpoint`.
//!
//! They come from a file the person prepared or from standard input, never from an argument (see
//! `cli`). What is read is bounded, so a path to the wrong file (a disk image, a device) cannot make
//! this program read without limit, and nothing read is ever printed: an error says what was wrong
//! with the input, not what the input said.

use std::io::Read;

use dnet_config::credentials::{EndpointCredentials, MAX_STORED_LEN};

use crate::cli::CredentialsSource;

/// What a PowerShell redirect puts at the start of a text file, and a JSON parser does not accept.
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// The bytes `source` holds, if there are few enough of them to be credentials.
pub fn read_bytes(source: &CredentialsSource) -> Result<Vec<u8>, String> {
    match source {
        CredentialsSource::File(path) => {
            let file = std::fs::File::open(path)
                .map_err(|e| format!("the credentials file could not be opened ({})", e.kind()))?;
            read_limited(file)
        }
        CredentialsSource::Stdin => read_limited(std::io::stdin().lock()),
    }
}

/// Everything `reader` gives, up to one byte past the limit so that "too long" can be told from
/// "exactly at the limit".
fn read_limited(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_STORED_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("the credentials could not be read ({})", e.kind()))?;
    if bytes.len() > MAX_STORED_LEN {
        return Err(format!(
            "the credentials are longer than {MAX_STORED_LEN} bytes; this is not a credentials file"
        ));
    }
    Ok(bytes)
}

/// A signed document (a keys document or a feed) from a file, as the text the service will verify.
/// Bounded by the size cap every source of such a document is held to; not interpreted here.
pub fn read_document(path: &str) -> Result<String, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("a document file could not be opened ({})", e.kind()))?;
    let cap = dnet_core::feed::ENVELOPE_MAX_BYTES;
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("a document file could not be read ({})", e.kind()))?;
    if bytes.len() > cap {
        return Err(format!(
            "a document file is longer than {cap} bytes, which no signed document is"
        ));
    }
    let bytes = bytes.strip_prefix(BOM).unwrap_or(&bytes);
    String::from_utf8(bytes.to_vec()).map_err(|_| "a document file is not text".to_string())
}

/// The credentials in `bytes`, in the form the service stores them (`EndpointCredentials`).
pub fn parse(bytes: &[u8]) -> Result<EndpointCredentials, String> {
    let bytes = bytes.strip_prefix(BOM).unwrap_or(bytes);
    let credentials = EndpointCredentials::from_plaintext_json(bytes)
        .map_err(|e| format!("the credentials are not usable: {e}"))?;
    if credentials.is_empty() {
        return Err("the credentials are not usable: they hold no connection method".to_string());
    }
    Ok(credentials)
}

#[cfg(test)]
pub(crate) mod tests;
