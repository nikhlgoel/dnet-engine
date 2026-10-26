//! What each command sends to the service, and what the window is told of the answer.

mod support;

use dnet_ipc::client::ClientError;
use dnet_ipc::protocol::Request;
use dnet_view::Bridge;
use serde_json::{json, Value};
use support::*;

const ENDPOINT: &str = "5b1f0c1e-8a43-4c51-9a79-0f6d1a9c2f10";

fn echo_ok(extra: Value) -> FakeLink {
    FakeLink::new(move |_| done(extra.clone()))
}

// ---------------------------------------------------------------------- the one control

#[tokio::test]
async fn turning_on_asks_the_service_to_choose_and_claims_no_consent() {
    let link = echo_ok(json!({ "accepted": true }));
    let seen = link.seen.clone();
    let out = Bridge::new(link).stabilize(true, false).await;
    assert_eq!(out, json!({ "ok": true }));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Request::Connect {
            acknowledge_tier2: false,
            profile: None,
            endpoint: None
        }]
    );
}

#[tokio::test]
async fn consent_is_sent_only_when_the_person_gave_it() {
    let link = echo_ok(json!({}));
    let seen = link.seen.clone();
    Bridge::new(link).stabilize(true, true).await;
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Request::Connect {
            acknowledge_tier2: true,
            profile: None,
            endpoint: None
        }]
    );
}

#[tokio::test]
async fn turning_off_is_a_disconnect() {
    let link = echo_ok(json!({}));
    let seen = link.seen.clone();
    assert_eq!(
        Bridge::new(link).stabilize(false, false).await,
        json!({ "ok": true })
    );
    assert_eq!(*seen.lock().unwrap(), vec![Request::Disconnect]);
}

#[tokio::test]
async fn a_tier_two_method_is_refused_until_the_person_agrees() {
    let link = FakeLink::new(|_| {
        refusal(
            "TierDowngradeRequiresConsent",
            "a method that breaks connections would be used",
        )
    });
    let out = Bridge::new(link).stabilize(true, false).await;
    assert_eq!(out["ok"], json!(false));
    assert_eq!(out["code"], json!("TierConsentRequired"));
    assert_eq!(
        out["reason"],
        json!("a method that breaks connections would be used")
    );
}

#[tokio::test]
async fn each_refusal_keeps_its_code_and_the_services_own_words() {
    for (wire, window) in [
        ("ServiceBusy", "ServiceBusy"),
        ("NotConnected", "NotConnected"),
        ("InvalidRequest", "Refused"),
        ("Unauthorized", "Refused"),
        ("InternalError", "Refused"),
    ] {
        let link = FakeLink::new(move |_| refusal(wire, "the reason in the service's words"));
        let out = Bridge::new(link).stabilize(true, false).await;
        assert_eq!(out["code"], json!(window), "{wire}");
        assert_eq!(out["reason"], json!("the reason in the service's words"));
    }
}

#[tokio::test]
async fn a_refusal_with_no_reason_still_says_something() {
    let link = FakeLink::new(|_| refusal("InternalError", ""));
    let out = Bridge::new(link).stabilize(true, false).await;
    assert_eq!(
        out["reason"],
        json!("The service declined, and gave no reason.")
    );
}

#[tokio::test]
async fn a_service_that_is_not_there_says_so_in_the_clients_own_words() {
    let link = FakeLink::new(|_| {
        Err(ClientError::Unreachable(
            "the DNet Engine service is not running".into(),
        ))
    });
    let out = Bridge::new(link).stabilize(true, false).await;
    assert_eq!(
        out,
        json!({ "ok": false, "reason": "the DNet Engine service is not running", "code": "ServiceBusy" })
    );
}

#[tokio::test]
async fn a_reason_is_cleaned_and_bounded_before_it_reaches_the_web_view() {
    let hostile = format!("pay\u{202e}load\u{7}{}", "x".repeat(1000));
    let link = FakeLink::new(move |_| refusal("InternalError", &hostile));
    let out = Bridge::new(link).stabilize(true, false).await;
    let reason = out["reason"].as_str().unwrap();
    assert!(reason.starts_with("pay?load?x"), "{reason}");
    assert_eq!(
        reason.chars().count(),
        401,
        "400 characters and an ellipsis"
    );
    assert!(reason.ends_with('…'));
}

// ---------------------------------------------------------------------- endpoints

#[tokio::test]
async fn adding_an_endpoint_sends_it_and_returns_only_its_id() {
    let link = echo_ok(json!({ "endpoint": ENDPOINT }));
    let seen = link.seen.clone();
    let out = Bridge::new(link)
        .add_endpoint("home", "203.0.113.9", &credentials_text())
        .await;
    assert_eq!(out, json!({ "ok": true, "id": ENDPOINT }));
    let requests = seen.lock().unwrap();
    assert!(
        matches!(requests.as_slice(), [Request::AddEndpoint(new)] if new.label() == "home" && new.host() == "203.0.113.9")
    );
}

#[tokio::test]
async fn a_byte_order_mark_from_a_windows_editor_is_tolerated() {
    let link = echo_ok(json!({ "endpoint": ENDPOINT }));
    let text = format!("\u{feff}{}", credentials_text());
    assert_eq!(
        Bridge::new(link)
            .add_endpoint("home", "203.0.113.9", &text)
            .await["ok"],
        json!(true)
    );
}

#[tokio::test]
async fn a_mistake_is_caught_before_anything_is_sent() {
    let cases = [
        ("an empty label", "", "203.0.113.9", credentials_text()),
        (
            "a label with an accent",
            "café",
            "203.0.113.9",
            credentials_text(),
        ),
        (
            "a host with a scheme",
            "home",
            "https://203.0.113.9",
            credentials_text(),
        ),
        (
            "a host with a port",
            "home",
            "203.0.113.9:443",
            credentials_text(),
        ),
        (
            "the unspecified address",
            "home",
            "0.0.0.0",
            credentials_text(),
        ),
        (
            "not JSON",
            "home",
            "203.0.113.9",
            "this is not json".to_owned(),
        ),
        (
            "a file that is no credentials",
            "home",
            "203.0.113.9",
            "{}".to_owned(),
        ),
        ("too large", "home", "203.0.113.9", " ".repeat(20_000)),
    ];
    for (what, label, host, credentials) in cases {
        let link = FakeLink::new(|_| panic!("nothing may be sent"));
        let out = Bridge::new(link)
            .add_endpoint(label, host, &credentials)
            .await;
        assert_eq!(out["ok"], json!(false), "{what}");
        assert_eq!(out["code"], json!("Refused"), "{what}");
    }
}

#[tokio::test]
async fn what_went_wrong_is_named_but_the_file_is_never_repeated() {
    let link = FakeLink::new(|_| panic!("nothing may be sent"));
    let bad = format!("{{\"version\":1,\"reality\":\"{SENTINEL_UUID}\"}}");
    let out = Bridge::new(link)
        .add_endpoint("home", "203.0.113.9", &bad)
        .await;
    assert!(!out.to_string().contains(SENTINEL_UUID), "{out}");
}

#[tokio::test]
async fn the_credentials_never_come_back() {
    let link = echo_ok(json!({ "endpoint": ENDPOINT }));
    let out = Bridge::new(link)
        .add_endpoint("home", "203.0.113.9", &credentials_text())
        .await;
    assert!(!out.to_string().contains(SENTINEL_UUID), "{out}");
}

#[tokio::test]
async fn an_answer_that_does_not_say_which_endpoint_is_not_success() {
    let link = echo_ok(json!({}));
    let out = Bridge::new(link)
        .add_endpoint("home", "203.0.113.9", &credentials_text())
        .await;
    assert_eq!(out["ok"], json!(false));
}

#[tokio::test]
async fn removing_and_switching_name_the_endpoint_by_the_services_own_grammar() {
    let link = echo_ok(json!({ "applied": true }));
    let seen = link.seen.clone();
    let bridge = Bridge::new(link);
    assert_eq!(
        bridge.remove_endpoint(ENDPOINT).await,
        json!({ "ok": true })
    );
    assert_eq!(
        bridge.set_endpoint_enabled(ENDPOINT, false).await,
        json!({ "ok": true })
    );
    let requests = seen.lock().unwrap();
    assert!(matches!(requests[0], Request::RemoveEndpoint { .. }));
    assert!(matches!(
        requests[1],
        Request::SetEndpointEnabled { enabled: false, .. }
    ));
}

#[tokio::test]
async fn an_id_that_is_not_an_id_is_refused_without_asking() {
    for bad in [
        "",
        "not-a-uuid",
        "../../etc",
        "5b1f0c1e-8a43-4c51-9a79-0f6d1a9c2f10; drop",
    ] {
        let link = FakeLink::new(|_| panic!("nothing may be sent"));
        let out = Bridge::new(link).remove_endpoint(bad).await;
        assert_eq!(out["ok"], json!(false), "{bad:?}");
    }
}

#[tokio::test]
async fn a_change_the_service_did_not_confirm_is_not_reported_as_made() {
    let link = echo_ok(json!({ "applied": false }));
    assert_eq!(
        Bridge::new(link).remove_endpoint(ENDPOINT).await["ok"],
        json!(false)
    );
    let link = echo_ok(json!({}));
    assert_eq!(
        Bridge::new(link).set_endpoint_enabled(ENDPOINT, true).await["ok"],
        json!(false)
    );
}

#[tokio::test]
async fn changing_endpoints_while_connected_shows_the_services_reason() {
    let link = FakeLink::new(|_| refusal("InvalidRequest", "disconnect before changing endpoints"));
    let out = Bridge::new(link).remove_endpoint(ENDPOINT).await;
    assert_eq!(out["reason"], json!("disconnect before changing endpoints"));
}

// ---------------------------------------------------------------------- encrypted name lookups

#[tokio::test]
async fn blocking_needs_no_consent_and_says_nothing_more() {
    let link = echo_ok(json!({ "block": true }));
    let seen = link.seen.clone();
    assert_eq!(
        Bridge::new(link).set_encrypted_dns(true).await,
        json!({ "ok": true })
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Request::SetEncryptedDnsHandling { block: true }]
    );
}

#[tokio::test]
async fn opting_out_returns_what_it_costs_in_the_services_words() {
    let link = echo_ok(
        json!({ "block": false, "consequence": "Rules for sites will not apply to those programs." }),
    );
    let out = Bridge::new(link).set_encrypted_dns(false).await;
    assert_eq!(
        out,
        json!({ "ok": true, "consequence": "Rules for sites will not apply to those programs." })
    );
}

#[tokio::test]
async fn an_opt_out_with_no_consequence_is_malformed_and_is_not_dressed_as_explained() {
    for reply in [
        json!({ "block": false }),
        json!({ "block": false, "consequence": "" }),
    ] {
        let out = Bridge::new(echo_ok(reply)).set_encrypted_dns(false).await;
        assert_eq!(out["ok"], json!(false));
        assert!(out.get("consequence").is_none());
    }
}

// ---------------------------------------------------------------------- updates

#[tokio::test]
async fn checking_for_updates_says_which_network_it_uses() {
    for route in ["tunnel", "physical"] {
        let link = echo_ok(json!({ "started": true, "route": route }));
        assert_eq!(
            Bridge::new(link).check_updates().await,
            json!({ "ok": true, "route": route })
        );
    }
}

#[tokio::test]
async fn a_check_that_did_not_start_or_did_not_say_where_is_not_success() {
    for reply in [
        json!({ "started": false, "route": "tunnel" }),
        json!({ "started": true }),
        json!({ "started": true, "route": "somewhere" }),
    ] {
        assert_eq!(
            Bridge::new(echo_ok(reply)).check_updates().await["ok"],
            json!(false)
        );
    }
}

#[tokio::test]
async fn a_build_with_no_trust_anchor_says_so() {
    let link = FakeLink::new(|_| refusal("InternalError", "not available in this build yet"));
    let out = Bridge::new(link).check_updates().await;
    assert_eq!(out["reason"], json!("not available in this build yet"));
}

// ---------------------------------------------------------------------- questions

#[tokio::test]
async fn the_state_is_required_but_paths_and_stats_may_be_unavailable() {
    let link = service(state_disconnected(), None, None);
    let seen = link.seen.clone();
    let view = Bridge::new(link).snapshot(None, 5).await.unwrap();
    assert_eq!(view["status"], json!("Disconnected"));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Request::GetState, Request::GetPaths, Request::GetStats]
    );

    let link =
        FakeLink::new(|_| refusal("Unauthorized", "this account may not use the control pipe"));
    assert_eq!(
        Bridge::new(link).snapshot(None, 5).await.unwrap_err(),
        "this account may not use the control pipe"
    );

    let link = FakeLink::new(|_| Err(ClientError::Closed));
    assert!(Bridge::new(link).snapshot(None, 5).await.is_err());
}

#[tokio::test]
async fn a_state_that_contradicts_itself_is_refused_not_drawn() {
    // Connected with nothing carrying.
    let mut state = state_connected("Tier2", &[]);
    state["active_profile"] = Value::Null;
    let link = service(
        state,
        Some(paths_not_watching()),
        Some(stats_not_connected()),
    );
    let err = Bridge::new(link).snapshot(None, 5).await.unwrap_err();
    assert!(err.contains("could not be read"), "{err}");
}

#[tokio::test]
async fn a_paths_reply_that_is_not_believable_is_treated_as_no_answer() {
    // A network that was not measured, claiming a figure: the decoder refuses it, so nothing is drawn from it.
    let mut paths = paths_two_networks(false);
    paths["paths"][2]["rtt_ms"] = json!(1.0);
    let link = service(
        state_connected("Tier2", &[]),
        Some(paths),
        Some(stats_connected()),
    );
    let view = Bridge::new(link).snapshot(None, 5).await.unwrap();
    assert_eq!(view["paths"]["watching"], json!(false));
    assert_eq!(view["paths"]["paths"], json!([]));
}

#[tokio::test]
async fn the_lists_refuse_what_is_not_a_list() {
    let link = echo_ok(json!({ "endpoints": "many" }));
    assert!(Bridge::new(link).endpoints().await.is_err());
    let link = echo_ok(json!({ "rules": [] }));
    assert!(
        Bridge::new(link).rules().await.is_err(),
        "no encrypted-name setting"
    );
    let link = echo_ok(
        json!({ "endpoints": [{ "id": "a", "label": "b", "address": "c", "enabled": true, "health": "Splendid" }] }),
    );
    assert!(Bridge::new(link).endpoints().await.is_err());
}

#[tokio::test]
async fn what_the_build_can_do_is_said_plainly() {
    let caps = Bridge::new(echo_ok(json!({}))).capabilities();
    assert_eq!(caps, json!({ "provisioning": false, "updates": true }));
}

#[tokio::test]
async fn the_login_page_is_not_faked() {
    let out = Bridge::new(echo_ok(json!({}))).open_login_page();
    assert_eq!(out["ok"], json!(false));
    assert!(out["reason"]
        .as_str()
        .unwrap()
        .contains("Open any web page"));
}
