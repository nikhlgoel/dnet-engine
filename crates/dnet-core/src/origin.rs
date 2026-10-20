//! A known origin a probe fetches from: scheme, host and port, and nothing else.
//!
//! Here, and not in the prober, because it is configuration: an endpoint's stored credentials name
//! the origin its probes and live checks fetch from, and the configuration crate must be able to
//! refuse a bad one when it is stored, with the same rule the prober applies when it is used.

/// The known origin a probe fetches from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    host: String,
    port: u16,
}

/// Why an origin URL was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OriginError {
    #[error("the origin must be an http:// URL")]
    NotHttp,
    #[error("the origin has no host")]
    NoHost,
    #[error("the origin port is not valid")]
    BadPort,
    #[error("the origin must be just scheme, host and port, with no path or credentials")]
    Extra,
}

impl Origin {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Parse `http://host[:port][/]`. The port defaults to 80. Anything else in the URL (a path,
    /// a query, credentials) is refused so a probe cannot be pointed somewhere unexpected.
    pub fn parse(url: &str) -> Result<Origin, OriginError> {
        let rest = url.strip_prefix("http://").ok_or(OriginError::NotHttp)?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#', '@']) {
            return Err(OriginError::Extra);
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or(OriginError::BadPort)?;
                (host, port)
            }
            None => (rest, 80),
        };
        if host.is_empty() {
            return Err(OriginError::NoHost);
        }
        // Letters, digits, dots and hyphens only. That excludes an IPv6 literal (a probe does not
        // take one) and, more to the point, anything that could add a header line to the request
        // the host is written into: CR, LF, spaces, NUL.
        if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(OriginError::Extra);
        }
        Ok(Origin {
            host: host.to_string(),
            port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_urls_parse_to_host_and_port() {
        let o = Origin::parse("http://203.0.113.80:8080").unwrap();
        assert_eq!((o.host(), o.port()), ("203.0.113.80", 8080));
        assert_eq!(Origin::parse("http://example.net/").unwrap().port(), 80);
        assert_eq!(
            Origin::parse("http://example.net").unwrap().host(),
            "example.net"
        );
    }

    /// The host is written into a request line, so it must not be able to add a header.
    #[test]
    fn a_host_that_could_inject_a_header_is_refused() {
        for bad in [
            "http://a b.net",
            "http://a\r\nX-Evil: 1.net",
            "http://a\nb",
            "http://a\0b",
            "http://under_score.net",
            "http://[::1]:80",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn origin_urls_with_anything_else_are_refused() {
        assert_eq!(
            Origin::parse("https://example.net"),
            Err(OriginError::NotHttp)
        );
        assert_eq!(Origin::parse("example.net:80"), Err(OriginError::NotHttp));
        assert_eq!(Origin::parse("http://"), Err(OriginError::NoHost));
        assert_eq!(Origin::parse("http://:80"), Err(OriginError::NoHost));
        assert_eq!(
            Origin::parse("http://example.net:0"),
            Err(OriginError::BadPort)
        );
        assert_eq!(
            Origin::parse("http://example.net:99999"),
            Err(OriginError::BadPort)
        );
        assert_eq!(
            Origin::parse("http://example.net:abc"),
            Err(OriginError::BadPort)
        );
        assert_eq!(
            Origin::parse("http://example.net/bytes/1"),
            Err(OriginError::Extra)
        );
        assert_eq!(
            Origin::parse("http://user@example.net"),
            Err(OriginError::Extra)
        );
        assert_eq!(
            Origin::parse("http://example.net?x=1"),
            Err(OriginError::Extra)
        );
    }
}
