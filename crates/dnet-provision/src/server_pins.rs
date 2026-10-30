//! T149 — the server-side cores a release carries, by processor, with their checksums (T093 gap).
//!
//! The setup script downloads each core by address and refuses it unless its SHA-256 matches. Those values
//! cannot be compiled in: they are made when a release is built (`cargo xtask build-server-cores`), after
//! the client's own code is fixed. So the release carries them in `server-pins.json`, installed beside the
//! service in the folder only administrators can change, and this reads it.
//!
//! It is read as untrusted input all the same: strict schema, bounded size, every value checked with the
//! script's own rules (`CorePin`), and nothing quoted in an error.

use serde::{Deserialize, Serialize};

use crate::bootstrap::{BootstrapError, CorePin, ServerArch, ServerCores};

/// The only format this build reads and writes.
pub const PINS_VERSION: u32 = 1;
/// Larger than any real file by a wide margin.
pub const MAX_PINS_BYTES: usize = 64 * 1024;
/// The name the file has, beside the service.
pub const FILE_NAME: &str = "server-pins.json";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinsError {
    #[error("the server downloads list is larger than {MAX_PINS_BYTES} bytes")]
    TooLarge,
    #[error("the server downloads list is not in the expected form ({0})")]
    Malformed(&'static str),
    #[error("the server downloads list is for format version {0}, which this version cannot read")]
    Version(u32),
    #[error("the server downloads list has an invalid {0}")]
    Invalid(&'static str),
    #[error("this release has no downloads for {0} servers")]
    NoBuild(&'static str),
}

/// One built file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltFile {
    pub file: String,
    pub sha256: String,
}

/// One core, built for both processors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedCore {
    pub name: String,
    pub version: String,
    pub licence: String,
    pub source: String,
    pub amd64: BuiltFile,
    pub arm64: BuiltFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPins {
    pub version: u32,
    /// Where the files are: an `https` address ending in `/`.
    pub base_url: String,
    pub primary_core: PinnedCore,
    pub amneziawg: PinnedCore,
}

impl ServerPins {
    /// Read a list. Every value is checked; none is repeated in an error.
    pub fn parse(text: &str) -> Result<Self, PinsError> {
        if text.len() > MAX_PINS_BYTES {
            return Err(PinsError::TooLarge);
        }
        let pins: ServerPins = serde_json::from_str(text).map_err(|e| {
            use serde_json::error::Category;
            PinsError::Malformed(match e.classify() {
                Category::Io => "unreadable",
                Category::Syntax => "not valid JSON",
                Category::Data => "a field is missing, unknown or of the wrong type",
                Category::Eof => "ends unexpectedly",
            })
        })?;
        if pins.version != PINS_VERSION {
            return Err(PinsError::Version(pins.version));
        }
        // Everything a script would be built from, for both processors, is checked now.
        for arch in [ServerArch::Amd64, ServerArch::Arm64] {
            pins.cores_for(arch)?;
        }
        Ok(pins)
    }

    /// The cores for a server of this kind, as the script is built from them.
    pub fn cores_for(&self, arch: ServerArch) -> Result<ServerCores, PinsError> {
        let make = |core: &PinnedCore, which: &'static str| -> Result<CorePin, PinsError> {
            let built = match arch {
                ServerArch::Amd64 => &core.amd64,
                ServerArch::Arm64 => &core.arm64,
            };
            if !self.base_url.starts_with("https://") || !self.base_url.ends_with('/') {
                return Err(PinsError::Invalid("download address"));
            }
            if built.file.is_empty()
                || built.file.len() > 100
                || !built
                    .file
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                || built.file.starts_with('.')
            {
                return Err(PinsError::Invalid("file name"));
            }
            let pin = CorePin {
                name: core.name.clone(),
                version: core.version.clone(),
                url: format!("{}{}", self.base_url, built.file),
                sha256: built.sha256.clone(),
                licence: core.licence.clone(),
                source: core.source.clone(),
            };
            pin.validate(which).map_err(|e| match e {
                BootstrapError::Unsafe(_) | BootstrapError::Invalid(_) => PinsError::Invalid(which),
            })?;
            Ok(pin)
        };
        Ok(ServerCores {
            arch,
            primary_core: make(&self.primary_core, "primary core entry")?,
            amneziawg: make(&self.amneziawg, "AmneziaWG entry")?,
        })
    }

    /// The list as written next to a release. Round-trips through [`Self::parse`].
    pub fn render(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).expect("plain data serialises");
        text.push('\n');
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn built(file: &str, tag: char) -> Value {
        json!({ "file": file, "sha256": tag.to_string().repeat(64) })
    }

    fn good() -> Value {
        json!({
            "version": 1,
            "base_url": "https://example.test/releases/download/v0.1.0/",
            "primary_core": {
                "name": "primary-core", "version": "v1.14.0", "licence": "GPL-3.0-or-later",
                "source": "https://example.test/source",
                "amd64": built("primary-core-linux-amd64", 'a'),
                "arm64": built("primary-core-linux-arm64", 'b'),
            },
            "amneziawg": {
                "name": "amneziawg-go", "version": "v3.1.20260828", "licence": "MIT",
                "source": "https://example.test/awg",
                "amd64": built("amneziawg-go-linux-amd64", 'c'),
                "arm64": built("amneziawg-go-linux-arm64", 'd'),
            },
        })
    }

    fn parse(value: &Value) -> Result<ServerPins, PinsError> {
        ServerPins::parse(&value.to_string())
    }

    #[test]
    fn a_good_list_gives_each_kind_of_server_its_own_files() {
        let pins = parse(&good()).unwrap();
        let amd = pins.cores_for(ServerArch::Amd64).unwrap();
        let arm = pins.cores_for(ServerArch::Arm64).unwrap();
        assert_eq!(amd.arch, ServerArch::Amd64);
        assert_eq!(
            amd.primary_core.url,
            "https://example.test/releases/download/v0.1.0/primary-core-linux-amd64"
        );
        assert_eq!(arm.primary_core.sha256, "b".repeat(64));
        assert_eq!(
            arm.amneziawg.url,
            "https://example.test/releases/download/v0.1.0/amneziawg-go-linux-arm64"
        );
        assert_ne!(amd.amneziawg.sha256, arm.amneziawg.sha256);
    }

    #[test]
    fn what_is_written_is_read_back_the_same() {
        let pins = parse(&good()).unwrap();
        assert_eq!(ServerPins::parse(&pins.render()).unwrap(), pins);
    }

    #[test]
    fn a_list_that_would_make_a_script_the_script_refuses_is_refused_here() {
        type Mutation = Box<dyn Fn(&mut Value)>;
        let mutations: Vec<(&str, Mutation)> = vec![
            (
                "http",
                Box::new(|v| v["base_url"] = json!("http://example.test/d/")),
            ),
            (
                "no slash",
                Box::new(|v| v["base_url"] = json!("https://example.test/d")),
            ),
            (
                "shell",
                Box::new(|v| v["base_url"] = json!("https://example.test/$(id)/")),
            ),
            (
                "short sum",
                Box::new(|v| v["primary_core"]["amd64"]["sha256"] = json!("abc")),
            ),
            (
                "upper sum",
                Box::new(|v| v["primary_core"]["arm64"]["sha256"] = json!("A".repeat(64))),
            ),
            (
                "path file",
                Box::new(|v| v["amneziawg"]["amd64"]["file"] = json!("../x")),
            ),
            (
                "hidden file",
                Box::new(|v| v["amneziawg"]["arm64"]["file"] = json!(".x")),
            ),
            (
                "empty file",
                Box::new(|v| v["amneziawg"]["arm64"]["file"] = json!("")),
            ),
            (
                "space file",
                Box::new(|v| v["amneziawg"]["arm64"]["file"] = json!("a b")),
            ),
            (
                "bad name",
                Box::new(|v| v["primary_core"]["name"] = json!("Primary Core")),
            ),
            (
                "quote version",
                Box::new(|v| v["primary_core"]["version"] = json!("v1';id;'")),
            ),
            (
                "source",
                Box::new(|v| v["amneziawg"]["source"] = json!("x y")),
            ),
        ];
        for (what, mutate) in mutations {
            let mut v = good();
            mutate(&mut v);
            assert!(
                matches!(parse(&v), Err(PinsError::Invalid(_))),
                "{what}: {:?}",
                parse(&v)
            );
        }
    }

    #[test]
    fn the_shape_is_strict() {
        let mut v = good();
        v["surprise-field-name"] = json!(1);
        assert!(matches!(parse(&v), Err(PinsError::Malformed(_))));
        let mut v = good();
        v.as_object_mut().unwrap().remove("amneziawg");
        assert!(matches!(parse(&v), Err(PinsError::Malformed(_))));
        let mut v = good();
        v["primary_core"].as_object_mut().unwrap().remove("arm64");
        assert!(matches!(parse(&v), Err(PinsError::Malformed(_))));
        let mut v = good();
        v["version"] = json!(2);
        assert_eq!(parse(&v), Err(PinsError::Version(2)));
        assert!(matches!(
            ServerPins::parse("not json"),
            Err(PinsError::Malformed(_))
        ));
        assert!(matches!(
            ServerPins::parse(""),
            Err(PinsError::Malformed(_))
        ));
        let big = " ".repeat(MAX_PINS_BYTES + 1);
        assert_eq!(ServerPins::parse(&big), Err(PinsError::TooLarge));
    }

    /// The limits are exact: a list of exactly the largest size is read, one byte more is not, and a file
    /// name of a hundred characters is accepted where a hundred and one is not.
    #[test]
    fn the_limits_are_where_they_are_said_to_be() {
        assert_eq!(MAX_PINS_BYTES, 65_536);
        let text = good().to_string();
        let exactly = format!("{text}{}", " ".repeat(MAX_PINS_BYTES - text.len()));
        assert_eq!(exactly.len(), MAX_PINS_BYTES);
        assert!(ServerPins::parse(&exactly).is_ok());
        assert_eq!(
            ServerPins::parse(&format!("{exactly} ")),
            Err(PinsError::TooLarge)
        );

        let mut v = good();
        v["primary_core"]["amd64"]["file"] = json!("a".repeat(100));
        assert!(parse(&v).is_ok());
        v["primary_core"]["amd64"]["file"] = json!("a".repeat(101));
        assert!(matches!(parse(&v), Err(PinsError::Invalid(_))));
        // Each way a name can be wrong is enough on its own.
        for bad in ["", "a b", "a/b", ".hidden", &"a".repeat(101)] {
            let mut v = good();
            v["amneziawg"]["arm64"]["file"] = json!(bad);
            assert!(matches!(parse(&v), Err(PinsError::Invalid(_))), "{bad:?}");
        }
        for fine in ["a", "a.b-c_d", "primary-core-linux-amd64"] {
            let mut v = good();
            v["amneziawg"]["arm64"]["file"] = json!(fine);
            assert!(parse(&v).is_ok(), "{fine:?}");
        }
    }

    #[test]
    fn nothing_the_file_said_is_repeated_in_an_error() {
        let mut v = good();
        v["primary_core"]["version"] = json!("SENTINEL';id;'");
        v["surprise-SENTINEL"] = json!(1);
        let text = parse(&v).unwrap_err().to_string();
        assert!(!text.contains("SENTINEL"), "{text}");
        let mut v = good();
        v["primary_core"]["version"] = json!("SENTINEL';id;'");
        let text = parse(&v).unwrap_err().to_string();
        assert!(!text.contains("SENTINEL"), "{text}");
    }
}
