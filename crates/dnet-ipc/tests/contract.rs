//! T022 — IPC contract tests IPC-01 to IPC-09.
//!
//! Contract: `specs/001-network-resilience-client/contracts/ipc-protocol.md`.
//!
//! Written before the implementation (Constitution Principle IV). Every test in this
//! file is expected to FAIL until tasks T032–T035 land. The functions under test have
//! `todo!()` bodies, so the suite compiles and then fails at runtime for the right
//! reason, rather than failing to build.
//!
//! Scope, recorded here so nothing is dropped silently:
//! - **IPC-01** tests the authorization *decision*. The OS half — impersonating the
//!   pipe client and showing that routing state is unchanged — is verified by attack at
//!   the T039 gate, which needs a real second token.
//! - **IPC-07** tests destination exclusion as the contract specifies it. Credential
//!   exclusion is checked by the PRV-02 sentinel scan and the T112 diagnostics work,
//!   where real credential material exists to scan for.
//! - **`MAX_FRAME_LEN`** (1 MiB) is a chosen default. The contract requires a limit but
//!   does not set its value.

use std::collections::HashSet;
use std::time::Duration;

use dnet_core::profile::CoreBinding;
use dnet_core::session::FailureCause;
use dnet_core::tier::FailoverTier;
use dnet_ipc::authz::{authorize, ClientIdentity, ConsoleSession};
use dnet_ipc::frame::{self, FrameError, HEADER_LEN, MAX_FRAME_LEN};
use dnet_ipc::protocol::{
    build_diagnostic_bundle, check_tier_consent, decode_failure_cause, decode_state_snapshot,
    encode_failure_cause, validate_because, ConnectionStatus, DiagnosticInput, IpcError, Request,
    RequestClass,
};
use dnet_ipc::server::{pipe_sddl, serve_connection, PIPE_NAME};
use proptest::prelude::*;
use tokio::io::AsyncWriteExt;

const CONSOLE_USER: &str = "S-1-5-21-1000-1000-1000-1001";

fn console() -> ConsoleSession {
    ConsoleSession {
        session_id: 1,
        user_sid: CONSOLE_USER.to_string(),
    }
}

fn console_client() -> ClientIdentity {
    ClientIdentity {
        sid: CONSOLE_USER.to_string(),
        session_id: 1,
        authenticated: true,
    }
}

/// An authenticated user in a different session, such as a second RDP login.
fn other_session_client() -> ClientIdentity {
    ClientIdentity {
        sid: "S-1-5-21-1000-1000-1000-2002".to_string(),
        session_id: 2,
        authenticated: true,
    }
}

fn framed(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("test payload fits in u32");
    let mut bytes = len.to_le_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

// ====================================================================== IPC-01
// Unprivileged, non-console client issuing `Connect` receives `Unauthorized`.

#[test]
fn ipc01_request_classes_match_the_contract_table() {
    use Request::*;
    for r in [
        GetState,
        GetSession,
        ListEndpoints,
        ListProfiles,
        ListRules,
        GetDiagnostics,
    ] {
        assert_eq!(r.class(), RequestClass::ReadOnly, "{r:?}");
    }
    for r in [
        Connect {
            acknowledge_tier2: false,
        },
        Disconnect,
        AddEndpoint,
        RemoveEndpoint,
        SetEndpointEnabled,
        AddRule,
        RemoveRule,
        SetProfileParams,
        EnableBrutal,
        SetEncryptedDnsHandling,
        StartProvisioning,
        CancelProvisioning,
    ] {
        assert_eq!(r.class(), RequestClass::Mutating, "{r:?}");
    }
    assert_eq!(Subscribe.class(), RequestClass::Stream);
}

#[test]
fn ipc01_client_in_another_session_is_refused_a_mutating_request() {
    let result = authorize(
        RequestClass::Mutating,
        &other_session_client(),
        Some(&console()),
    );
    assert!(
        matches!(result, Err(IpcError::Unauthorized { .. })),
        "got {result:?}"
    );
}

#[test]
fn ipc01_same_session_with_a_different_user_is_refused_a_mutating_request() {
    // Being in the console session is not enough: the SID must be the logged-on user.
    let impostor = ClientIdentity {
        sid: "S-1-5-21-9999-9999-9999-3003".to_string(),
        session_id: 1,
        authenticated: true,
    };
    let result = authorize(RequestClass::Mutating, &impostor, Some(&console()));
    assert!(
        matches!(result, Err(IpcError::Unauthorized { .. })),
        "got {result:?}"
    );
}

#[test]
fn ipc01_mutation_is_refused_when_there_is_no_console_session() {
    let result = authorize(RequestClass::Mutating, &console_client(), None);
    assert!(
        matches!(result, Err(IpcError::Unauthorized { .. })),
        "got {result:?}"
    );
}

#[test]
fn ipc01_unauthenticated_client_is_refused_even_read_only_requests() {
    let anonymous = ClientIdentity {
        authenticated: false,
        ..console_client()
    };
    for class in [
        RequestClass::ReadOnly,
        RequestClass::Stream,
        RequestClass::Mutating,
    ] {
        let result = authorize(class, &anonymous, Some(&console()));
        assert!(
            matches!(result, Err(IpcError::Unauthorized { .. })),
            "{class:?}: {result:?}"
        );
    }
}

#[test]
fn ipc01_console_user_may_mutate() {
    assert_eq!(
        authorize(RequestClass::Mutating, &console_client(), Some(&console())),
        Ok(())
    );
}

#[test]
fn ipc01_authenticated_non_console_client_may_read_and_subscribe() {
    for class in [RequestClass::ReadOnly, RequestClass::Stream] {
        assert_eq!(
            authorize(class, &other_session_client(), Some(&console())),
            Ok(()),
            "{class:?}"
        );
    }
}

#[test]
fn ipc01_refusal_always_carries_a_reason() {
    // Rejection is explicit; a silent refusal is a defect.
    match authorize(
        RequestClass::Mutating,
        &other_session_client(),
        Some(&console()),
    ) {
        Err(IpcError::Unauthorized { reason }) => {
            assert!(
                !reason.trim().is_empty(),
                "Unauthorized must explain itself"
            );
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

// ====================================================================== IPC-02
// Never a NULL DACL; the SDDL grants exactly the contracted rights.

/// The ACE groups `(...)` in an SDDL string, in order.
fn aces(sddl: &str) -> Vec<String> {
    sddl.split('(')
        .skip(1)
        .filter_map(|rest| rest.split_once(')').map(|(ace, _)| format!("({ace})")))
        .collect()
}

#[test]
fn ipc02_pipe_name_matches_the_contract() {
    assert_eq!(PIPE_NAME, r"\\.\pipe\DNetEngine\control");
}

#[test]
fn ipc02_pipe_is_never_created_with_a_null_dacl() {
    let sddl = pipe_sddl();
    assert!(
        sddl.starts_with("D:"),
        "SDDL must carry an explicit DACL: {sddl}"
    );
    assert!(
        !sddl.contains("NO_ACCESS_CONTROL"),
        "NULL DACL grants everyone everything: {sddl}"
    );
    // An *empty* DACL is the opposite failure: it denies everyone, including the tray.
    assert!(!aces(sddl).is_empty(), "empty DACL: {sddl}");
}

#[test]
fn ipc02_sddl_grants_exactly_the_contracted_rights() {
    // SYSTEM and Administrators: full control. Authenticated Users: read and write.
    // No other principal — no Everyone, no Anonymous.
    let mut granted = aces(pipe_sddl());
    granted.sort();
    let mut contracted = vec![
        "(A;;GA;;;SY)".to_string(),
        "(A;;GA;;;BA)".to_string(),
        "(A;;GRGW;;;AU)".to_string(),
    ];
    contracted.sort();
    assert_eq!(granted, contracted);
}

// ====================================================================== IPC-03
// Every FailureCause round-trips and is distinguishable; "Unknown" fails to decode.

fn all_failure_causes() -> Vec<FailureCause> {
    vec![
        FailureCause::NoEndpointReachable,
        FailureCause::AllProfilesBlocked,
        FailureCause::CaptivePortalUnsatisfied,
        FailureCause::InsufficientPrivilege,
        FailureCause::CoreFailedPersistently {
            core: CoreBinding::PrimaryCore,
        },
        FailureCause::CoreFailedPersistently {
            core: CoreBinding::AmneziaWgCore,
        },
        FailureCause::NoUsablePath,
        FailureCause::ConfigurationInvalid {
            detail: "profile B has no endpoint".to_string(),
        },
    ]
}

#[test]
fn ipc03_every_failure_cause_round_trips() {
    for cause in all_failure_causes() {
        let wire = encode_failure_cause(&cause);
        let decoded = decode_failure_cause(&wire)
            .unwrap_or_else(|e| panic!("{cause:?} did not decode from {wire}: {e}"));
        assert_eq!(decoded, cause);
    }
}

#[test]
fn ipc03_failure_causes_are_distinguishable_on_the_wire() {
    let causes = all_failure_causes();
    let encodings: HashSet<String> = causes.iter().map(encode_failure_cause).collect();
    assert_eq!(
        encodings.len(),
        causes.len(),
        "two causes share an encoding"
    );
}

#[test]
fn ipc03_wire_shape_matches_the_contract() {
    let wire = encode_failure_cause(&FailureCause::AllProfilesBlocked);
    let value: serde_json::Value =
        serde_json::from_str(&wire).expect("a failure cause encodes as JSON");
    assert_eq!(value["cause"], "AllProfilesBlocked", "wire: {wire}");
}

#[test]
fn ipc03_unknown_is_not_a_permitted_cause() {
    for wire in [
        r#"{"cause":"Unknown"}"#,
        r#"{"cause":"Unknown","detail":"x"}"#,
    ] {
        assert!(decode_failure_cause(wire).is_err(), "decoded {wire}");
    }
}

// ====================================================================== IPC-04
// Tier 2 while Tier 1 is viable returns TierDowngradeRequiresConsent.

#[test]
fn ipc04_tier2_while_tier1_is_viable_requires_consent() {
    let result = check_tier_consent(FailoverTier::Tier2, true, false);
    assert!(
        matches!(
            result,
            Err(IpcError::TierDowngradeRequiresConsent {
                tier: FailoverTier::Tier2
            })
        ),
        "got {result:?}"
    );
}

#[test]
fn ipc04_acknowledged_tier2_is_allowed() {
    assert_eq!(check_tier_consent(FailoverTier::Tier2, true, true), Ok(()));
}

#[test]
fn ipc04_tier2_needs_no_consent_when_no_tier1_profile_is_viable() {
    assert_eq!(
        check_tier_consent(FailoverTier::Tier2, false, false),
        Ok(())
    );
}

#[test]
fn ipc04_tier1_never_requires_consent() {
    for tier1_viable in [true, false] {
        for acknowledged in [true, false] {
            assert_eq!(
                check_tier_consent(FailoverTier::Tier1, tier1_viable, acknowledged),
                Ok(())
            );
        }
    }
}

// ====================================================================== IPC-05
// A StateSnapshot with an active profile always carries a non-null tier.

#[test]
fn ipc05_active_profile_without_a_tier_is_rejected() {
    let json = r#"{"status":"Connected","active_profile":{"id":"hy2-default","kind":"Hysteria2"}}"#;
    assert!(decode_state_snapshot(json).is_err());
}

#[test]
fn ipc05_active_profile_with_a_null_tier_is_rejected() {
    let json = r#"{"status":"Connected","active_profile":{"id":"hy2-default","kind":"Hysteria2","tier":null}}"#;
    assert!(decode_state_snapshot(json).is_err());
}

#[test]
fn ipc05_active_profile_with_an_unknown_tier_is_rejected() {
    let json = r#"{"status":"Connected","active_profile":{"id":"hy2-default","kind":"Hysteria2","tier":"Tier3"}}"#;
    assert!(decode_state_snapshot(json).is_err());
}

#[test]
fn ipc05_active_profile_carries_its_tier() {
    let json = r#"{"status":"Connected","active_profile":{"id":"awg-default","kind":"AmneziaWg","tier":"Tier1"}}"#;
    let snapshot = decode_state_snapshot(json).expect("a valid snapshot decodes");
    assert_eq!(snapshot.status, ConnectionStatus::Connected);
    let profile = snapshot.active_profile.expect("active profile present");
    assert_eq!(profile.tier, FailoverTier::Tier1);
}

#[test]
fn ipc05_disconnected_snapshot_has_no_active_profile() {
    let json = r#"{"status":"Disconnected","active_profile":null}"#;
    let snapshot = decode_state_snapshot(json).expect("a valid snapshot decodes");
    assert_eq!(snapshot.status, ConnectionStatus::Disconnected);
    assert_eq!(snapshot.active_profile, None);
}

// ====================================================================== IPC-06
// Every ConnectionEvent has a non-empty `because` that is not the event name.

#[test]
fn ipc06_empty_because_is_rejected() {
    for because in ["", "   ", "\n\t"] {
        assert!(
            validate_because("ProfileSelected", because).is_err(),
            "{because:?}"
        );
    }
}

#[test]
fn ipc06_because_that_restates_the_event_name_is_rejected() {
    for because in ["ProfileSelected", "profileselected", "  ProfileSelected  "] {
        assert!(
            validate_because("ProfileSelected", because).is_err(),
            "{because:?}"
        );
    }
}

#[test]
fn ipc06_explanatory_because_is_accepted() {
    let because = "AmneziaWG probe timed out after 6s; Hysteria 2 carried 1.2 Mbit/s";
    assert_eq!(validate_because("ProfileSelected", because), Ok(()));
}

// ====================================================================== IPC-07
// A DiagnosticBundle contains no browsing destinations by default.

const KNOWN_DOMAIN: &str = "known-destination.example";

fn session_input(destination_logging_enabled: bool) -> DiagnosticInput {
    DiagnosticInput {
        events: vec!["ProfileSelected hy2-default: AmneziaWG probe timed out after 6s".to_string()],
        destinations: vec![KNOWN_DOMAIN.to_string()],
        destination_logging_enabled,
    }
}

#[test]
fn ipc07_bundle_excludes_destinations_by_default() {
    let bundle = build_diagnostic_bundle(&session_input(false));
    assert!(
        !bundle.contains(KNOWN_DOMAIN),
        "a destination leaked into the default bundle"
    );
}

#[test]
fn ipc07_bundle_is_not_vacuously_empty() {
    // Guards the exclusion test above: an empty bundle would pass it trivially.
    let bundle = build_diagnostic_bundle(&session_input(false));
    assert!(
        bundle.contains("hy2-default"),
        "bundle omitted session events: {bundle}"
    );
}

#[test]
fn ipc07_destinations_appear_only_when_explicitly_enabled() {
    let bundle = build_diagnostic_bundle(&session_input(true));
    assert!(bundle.contains(KNOWN_DOMAIN));
}

// ====================================================================== IPC-08
// Malformed, oversized, and truncated frames are rejected without panicking.

#[test]
fn ipc08_complete_frame_decodes() {
    let bytes = framed(br#"{"GetState":null}"#);
    let frame = frame::decode(&bytes).expect("decodes").expect("complete");
    assert_eq!(frame.payload, r#"{"GetState":null}"#);
    assert_eq!(frame.consumed, bytes.len());
}

#[test]
fn ipc08_length_prefix_is_little_endian() {
    // Read as big-endian, this prefix would be 33 MiB and rejected as oversized.
    let frame = frame::decode(&[0x02, 0x00, 0x00, 0x00, b'a', b'b'])
        .expect("decodes")
        .expect("complete");
    assert_eq!(frame.payload, "ab");
}

#[test]
fn ipc08_truncated_header_waits_for_more_bytes() {
    let header = 5u32.to_le_bytes();
    for n in 0..HEADER_LEN {
        assert_eq!(
            frame::decode(&header[..n]),
            Ok(None),
            "header truncated to {n} bytes"
        );
    }
}

#[test]
fn ipc08_truncated_payload_waits_for_more_bytes() {
    let bytes = framed(b"hello");
    assert_eq!(frame::decode(&bytes[..bytes.len() - 1]), Ok(None));
}

#[test]
fn ipc08_oversized_length_is_rejected_from_the_header_alone() {
    // Must be rejected on the prefix alone, without waiting for (or allocating) the
    // payload an attacker claims to be sending.
    let declared = MAX_FRAME_LEN + 1;
    let header = u32::try_from(declared).expect("fits in u32").to_le_bytes();
    assert_eq!(
        frame::decode(&header),
        Err(FrameError::Oversized {
            declared,
            max: MAX_FRAME_LEN,
        })
    );
}

#[test]
fn ipc08_maximum_u32_length_is_rejected() {
    let result = frame::decode(&u32::MAX.to_le_bytes());
    assert!(
        matches!(result, Err(FrameError::Oversized { .. })),
        "got {result:?}"
    );
}

#[test]
fn ipc08_invalid_utf8_is_malformed() {
    assert_eq!(
        frame::decode(&framed(&[0xFF, 0xFE, 0xFD])),
        Err(FrameError::Malformed)
    );
}

#[test]
fn ipc08_only_the_first_frame_is_consumed() {
    let mut two = framed(b"first");
    let first_len = two.len();
    two.extend(framed(b"second"));
    let frame = frame::decode(&two).expect("decodes").expect("complete");
    assert_eq!(frame.payload, "first");
    assert_eq!(frame.consumed, first_len);
}

#[test]
fn ipc08_encode_then_decode_round_trips() {
    let bytes = frame::encode(r#"{"GetState":null}"#).expect("encodes");
    let frame = frame::decode(&bytes).expect("decodes").expect("complete");
    assert_eq!(frame.payload, r#"{"GetState":null}"#);
    assert_eq!(frame.consumed, bytes.len());
}

#[test]
fn ipc08_encode_rejects_an_oversized_payload() {
    let result = frame::encode(&"a".repeat(MAX_FRAME_LEN + 1));
    assert!(
        matches!(result, Err(FrameError::Oversized { .. })),
        "got {result:?}"
    );
}

proptest! {
    #[test]
    fn ipc08_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = frame::decode(&bytes);
    }

    #[test]
    fn ipc08_decode_never_claims_more_than_it_was_given(
        bytes in prop::collection::vec(any::<u8>(), 0..2048)
    ) {
        if let Ok(Some(f)) = frame::decode(&bytes) {
            prop_assert!(f.consumed <= bytes.len());
            prop_assert!(f.payload.len() <= MAX_FRAME_LEN);
            prop_assert_eq!(f.consumed, HEADER_LEN + f.payload.len());
        }
    }

    #[test]
    fn ipc08_any_small_payload_round_trips(s in "\\PC{0,200}") {
        let bytes = frame::encode(&s).expect("small payloads encode");
        let f = frame::decode(&bytes).expect("decodes").expect("complete");
        prop_assert_eq!(f.payload, s);
    }
}

// ====================================================================== IPC-09
// A client disconnecting mid-request leaves no orphaned server task.

const TASK_EXIT_DEADLINE: Duration = Duration::from_secs(2);

#[tokio::test]
async fn ipc09_client_disconnecting_mid_request_leaves_no_orphaned_task() {
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(serve_connection(server));

    // A header announcing 16 bytes, followed by only one of them.
    client
        .write_all(&[16, 0, 0, 0, b'{'])
        .await
        .expect("write partial frame");
    drop(client);

    let joined = tokio::time::timeout(TASK_EXIT_DEADLINE, task)
        .await
        .expect("server task still running after the client disconnected: orphaned");
    assert!(
        joined.is_ok(),
        "server task panicked instead of ending cleanly: {joined:?}"
    );
}

#[tokio::test]
async fn ipc09_undecodable_frame_ends_the_connection() {
    // IPC-08 requires rejection "without leaking the connection". The client stays
    // connected here, so only the server can end the task.
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(serve_connection(server));

    client
        .write_all(&framed(&[0xFF]))
        .await
        .expect("write malformed frame");

    let joined = tokio::time::timeout(TASK_EXIT_DEADLINE, task)
        .await
        .expect("server kept the connection open after an undecodable frame");
    assert!(joined.is_ok(), "server task panicked: {joined:?}");
    drop(client);
}
