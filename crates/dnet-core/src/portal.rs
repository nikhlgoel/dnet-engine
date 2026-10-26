//! T077 — is a captive portal in the way, and where does its login page live? (FR-026, US6.)
//!
//! A captive portal is a network that answers every request with its own page until the person signs
//! in. To a tunnel it looks like total failure: every endpoint and every profile seems blocked. So the
//! product has to be able to tell "a portal wants a login" from "everything is blocked", and say the
//! right one (`FailureCause::CaptivePortalUnsatisfied`), with a way to the login page.
//!
//! # How it is told
//!
//! The same way the operating system tells: fetch a small page whose exact content is known and see
//! whether it comes back unchanged. Windows' own probes are `www.msftconnecttest.com/connecttest.txt`
//! (body `Microsoft Connect Test`) and `www.msftncsi.com/ncsi.txt` (body `Microsoft NCSI`). Their hosts
//! are bypassed by the built-in rules (`builtin_rules`) so the probe travels the physical network the
//! way a portal needs, before any tunnel exists.
//!
//! This module only **classifies what came back**. Making the request is `dnetd`'s; keeping this pure
//! makes every case testable without a network.
//!
//! - An unchanged known body: [`PortalState::Open`]. The network is not intercepting.
//! - A redirect, or any other body, or an HTML page where text was expected: [`PortalState::Intercepted`],
//!   with the login address when the response gave one.
//! - A failure to connect at all, a timeout, a refused connection: [`PortalState::Unreachable`]. A dead
//!   network is not a portal, and is not called one.
//! - Anything the module cannot make sense of: [`PortalState::Inconclusive`], never a guess either way.
//!
//! # The login address is untrusted
//!
//! It comes from whoever runs the network. It is offered to the person to open in their own browser,
//! never fetched by the product, and only if it is a plain `http` or `https` address: [`login_url`].
//! No other scheme, no credentials in it, no control character, and a bounded length.
//!
//! Pure logic: no I/O.

/// One of the two probes the operating system itself uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    ConnectTest,
    Ncsi,
}

impl Probe {
    /// Host to fetch, over plain HTTP: a portal can only intercept what it can read.
    pub fn host(self) -> &'static str {
        match self {
            Probe::ConnectTest => "www.msftconnecttest.com",
            Probe::Ncsi => "www.msftncsi.com",
        }
    }

    pub fn path(self) -> &'static str {
        match self {
            Probe::ConnectTest => "/connecttest.txt",
            Probe::Ncsi => "/ncsi.txt",
        }
    }

    /// The exact body that comes back when nothing is in the way.
    pub fn expected_body(self) -> &'static str {
        match self {
            Probe::ConnectTest => "Microsoft Connect Test",
            Probe::Ncsi => "Microsoft NCSI",
        }
    }
}

/// What a probe request came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// An HTTP response arrived.
    Http {
        status: u16,
        /// The `Location` header, if there was one.
        location: Option<String>,
        /// The start of the body (at most a few hundred bytes are ever needed).
        body: String,
    },
    /// No response: could not connect, timed out, was reset.
    NoAnswer,
}

/// What the network is doing, as far as one probe can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalState {
    /// The probe came back unchanged: nothing is intercepting.
    Open,
    /// Something answered in place of the probe's server. `login` is where it says to sign in, if it
    /// said, already checked by [`login_url`].
    Intercepted { login: Option<String> },
    /// Nothing answered: there is no working network to be a portal on.
    Unreachable,
    /// An answer that is neither the expected one nor recognisably a portal's.
    Inconclusive,
}

/// Classify one probe's response.
pub fn classify(probe: Probe, response: &Response) -> PortalState {
    let Response::Http {
        status,
        location,
        body,
    } = response
    else {
        return PortalState::Unreachable;
    };
    match *status {
        200 if body.trim() == probe.expected_body() => PortalState::Open,
        // A redirect is how most portals send a browser to their login page.
        300..=399 => PortalState::Intercepted {
            login: location.as_deref().and_then(login_url),
        },
        // A page where a short fixed text was expected: the portal's own page, served in place.
        200 => PortalState::Intercepted { login: None },
        // A portal may also answer in place with a sign-in challenge.
        401 | 403 | 407 => PortalState::Intercepted { login: None },
        // Everything else (a server error, an empty 204, an odd code) proves nothing.
        _ => PortalState::Inconclusive,
    }
}

/// Combine the two probes into one reading. If **either** came back unchanged the network is open:
/// two independent servers do not both fail to answer unchanged on a free network, but a portal
/// that whitelists one of the two probe hosts (some do, to keep the operating system quiet) would
/// otherwise be reported as open by one and intercepted by the other.
///
/// Policy: `Open` if either probe is open; else `Intercepted` if either is, keeping the first login
/// address; else `Unreachable` if both are; else `Inconclusive`.
pub fn combine(first: &PortalState, second: &PortalState) -> PortalState {
    use PortalState::*;
    if matches!(first, Open) || matches!(second, Open) {
        return Open;
    }
    match (first, second) {
        (Intercepted { login: a }, Intercepted { login: b }) => Intercepted {
            login: a.clone().or_else(|| b.clone()),
        },
        (Intercepted { login }, _) | (_, Intercepted { login }) => Intercepted {
            login: login.clone(),
        },
        (Unreachable, Unreachable) => Unreachable,
        _ => Inconclusive,
    }
}

/// The longest login address kept.
pub const MAX_LOGIN_URL: usize = 2048;

/// A login address made safe to offer: only a plain `http` or `https` address, with a host, no
/// credentials, no control or whitespace character, and a bounded length. `None` for anything else.
///
/// It is **offered to the person** to open in their own browser. The product never requests it.
pub fn login_url(raw: &str) -> Option<String> {
    let url = raw.trim();
    if url.is_empty()
        || url.len() > MAX_LOGIN_URL
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.starts_with(':') {
        return None;
    }
    // The host must not be only punctuation or a port.
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    if host.is_empty() || host.trim_matches(['.', '[', ']']).is_empty() {
        return None;
    }
    Some(url.to_owned())
}

/// Where to send a person who has to sign in when the network did not say: the probe address itself,
/// which a portal redirects a browser away from.
pub fn fallback_login_url(probe: Probe) -> String {
    format!("http://{}{}", probe.host(), probe.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(probe: Probe) -> Response {
        Response::Http {
            status: 200,
            location: None,
            body: probe.expected_body().to_owned(),
        }
    }

    fn redirect(to: &str) -> Response {
        Response::Http {
            status: 302,
            location: Some(to.to_owned()),
            body: String::new(),
        }
    }

    fn page(status: u16, body: &str) -> Response {
        Response::Http {
            status,
            location: None,
            body: body.to_owned(),
        }
    }

    #[test]
    fn the_expected_body_means_the_network_is_open() {
        for probe in [Probe::ConnectTest, Probe::Ncsi] {
            assert_eq!(classify(probe, &ok(probe)), PortalState::Open);
        }
        // Surrounding whitespace is not interception.
        assert_eq!(
            classify(Probe::Ncsi, &page(200, "Microsoft NCSI\r\n")),
            PortalState::Open
        );
    }

    #[test]
    fn the_other_probes_body_is_not_the_expected_one() {
        // A portal that answers every host with one canned text is caught by checking the exact body.
        assert_eq!(
            classify(Probe::ConnectTest, &page(200, Probe::Ncsi.expected_body())),
            PortalState::Intercepted { login: None }
        );
    }

    #[test]
    fn a_redirect_is_a_portal_and_its_login_address_is_kept_when_it_is_safe() {
        assert_eq!(
            classify(
                Probe::ConnectTest,
                &redirect("http://192.168.50.1/login?mac=aa")
            ),
            PortalState::Intercepted {
                login: Some("http://192.168.50.1/login?mac=aa".into())
            }
        );
        // Whatever redirect code.
        for status in [301, 302, 303, 307, 308] {
            let r = Response::Http {
                status,
                location: Some("https://portal.example/".into()),
                body: String::new(),
            };
            assert!(
                matches!(
                    classify(Probe::Ncsi, &r),
                    PortalState::Intercepted { login: Some(_) }
                ),
                "{status}"
            );
        }
    }

    #[test]
    fn a_redirect_to_an_unsafe_address_is_still_a_portal_but_offers_no_address() {
        for bad in [
            "javascript:alert(1)",
            "file:///C:/Windows",
            "ftp://x/",
            "http://user:pw@host/",
            "http://",
            "",
            "http://a b/",
            "http://host/\u{1b}[2J",
        ] {
            assert_eq!(
                classify(Probe::Ncsi, &redirect(bad)),
                PortalState::Intercepted { login: None },
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_page_where_text_was_expected_is_a_portal_without_an_address() {
        assert_eq!(
            classify(
                Probe::ConnectTest,
                &page(200, "<html><body>Sign in to WiFi")
            ),
            PortalState::Intercepted { login: None }
        );
        for status in [401, 403, 407] {
            assert_eq!(
                classify(Probe::ConnectTest, &page(status, "")),
                PortalState::Intercepted { login: None },
                "{status}"
            );
        }
    }

    #[test]
    fn no_answer_is_a_dead_network_not_a_portal() {
        assert_eq!(
            classify(Probe::ConnectTest, &Response::NoAnswer),
            PortalState::Unreachable
        );
    }

    #[test]
    fn answers_that_prove_nothing_are_inconclusive() {
        for status in [100, 204, 404, 500, 503, 999] {
            assert_eq!(
                classify(Probe::ConnectTest, &page(status, "")),
                PortalState::Inconclusive,
                "{status}"
            );
        }
    }

    #[test]
    fn two_probes_are_combined_conservatively() {
        use PortalState::*;
        let intercepted = |l: Option<&str>| Intercepted {
            login: l.map(str::to_owned),
        };
        // Open wins: a portal that lets one probe host through does not make the network a portal.
        assert_eq!(combine(&Open, &intercepted(None)), Open);
        assert_eq!(combine(&intercepted(None), &Open), Open);
        // Both intercepted keeps the first address given.
        assert_eq!(
            combine(&intercepted(None), &intercepted(Some("http://a/"))),
            intercepted(Some("http://a/"))
        );
        assert_eq!(
            combine(
                &intercepted(Some("http://x/")),
                &intercepted(Some("http://y/"))
            ),
            intercepted(Some("http://x/"))
        );
        // One intercepted and one that proves nothing is still intercepted.
        assert_eq!(combine(&intercepted(None), &Unreachable), intercepted(None));
        assert_eq!(
            combine(&Inconclusive, &intercepted(None)),
            intercepted(None)
        );
        // Nothing answered at all.
        assert_eq!(combine(&Unreachable, &Unreachable), Unreachable);
        assert_eq!(combine(&Unreachable, &Inconclusive), Inconclusive);
        assert_eq!(combine(&Inconclusive, &Inconclusive), Inconclusive);
    }

    #[test]
    fn a_login_address_must_be_a_plain_web_address() {
        for good in [
            "http://portal.example/login",
            "https://portal.example:8443/a?b=c#d",
            "HTTP://Portal.Example/",
            "http://10.0.0.1/",
            "http://[fe80::1]/x",
        ] {
            assert_eq!(login_url(good).as_deref(), Some(good), "{good}");
        }
        let long = format!("http://a.example/{}", "x".repeat(MAX_LOGIN_URL));
        for bad in [
            "",
            "  ",
            "portal.example/login",
            "//portal.example/",
            "http:/portal.example/",
            "data:text/html,<script>",
            "http://u@h/",
            "http://:80/",
            "http:///path",
            "http://h/a b",
            "http://h/\n/x",
            long.as_str(),
        ] {
            assert_eq!(login_url(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn when_the_network_does_not_say_where_to_sign_in_the_probe_address_is_offered() {
        assert_eq!(
            fallback_login_url(Probe::ConnectTest),
            "http://www.msftconnecttest.com/connecttest.txt"
        );
        assert!(login_url(&fallback_login_url(Probe::Ncsi)).is_some());
    }

    #[test]
    fn the_probe_hosts_are_the_ones_the_built_in_rules_bypass() {
        // The probe must travel the physical network, before any tunnel: the built-in rules exempt
        // exactly these hosts (FR-026), and this test keeps the two lists from drifting.
        use crate::builtin_rules::CAPTIVE_PORTAL_PROBE_SUFFIXES;
        for probe in [Probe::ConnectTest, Probe::Ncsi] {
            assert!(
                CAPTIVE_PORTAL_PROBE_SUFFIXES
                    .iter()
                    .any(|s| probe.host() == *s || probe.host().ends_with(&format!(".{s}"))),
                "{} would be tunnelled, so a portal could never be reached",
                probe.host()
            );
        }
    }
}
