// SPDX-License-Identifier: GPL-3.0-or-later
//! The event stream as the Activity view reads it: every line has a reason, and what cannot be read is skipped.

mod support;

use dnet_ipc::client::Connection;
use dnet_ipc::frame;
use dnet_view::events::{follow, Ended};
use serde_json::{json, Value};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

/// The service's half: read the `Subscribe`, answer it with `first`, then send each frame and hang up.
async fn serve(mut server: DuplexStream, first: String, frames: Vec<String>) {
    let mut request = [0_u8; 256];
    let n = server.read(&mut request).await.unwrap();
    assert!(n > 4, "a request was expected");
    assert!(String::from_utf8_lossy(&request[4..n]).contains("Subscribe"));
    server
        .write_all(&frame::encode(&first).unwrap())
        .await
        .unwrap();
    for payload in frames {
        server
            .write_all(&frame::encode(&payload).unwrap())
            .await
            .unwrap();
    }
}

async fn run(
    first: &str,
    frames: Vec<String>,
    stop_after: usize,
) -> (Result<Ended, dnet_ipc::client::ClientError>, Vec<Value>) {
    let (client, server) = duplex(8192);
    let writer = tokio::spawn(serve(server, first.to_owned(), frames));
    let mut connection = Connection::new(client);
    let mut lines = Vec::new();
    let ended = follow(&mut connection, |line, _| {
        lines.push(line);
        lines.len() < stop_after
    })
    .await;
    writer.await.unwrap();
    (ended, lines)
}

fn event(value: Value) -> String {
    value.to_string()
}

#[tokio::test]
async fn each_event_becomes_a_line_with_its_reason() {
    let frames = vec![
        event(
            json!({ "event": "ProfileSelected", "profile": "hy2-default", "because": "Hysteria 2 carried 1.2 Mbit/s", "seq": 1 }),
        ),
        event(
            json!({ "event": "Degraded", "path": "7", "quality": "Poor", "staying": "OnlyPath", "because": "the network is slow and it is the only one", "seq": 2 }),
        ),
    ];
    let (ended, lines) = run(r#"{"subscribed":true,"backlog":2}"#, frames, usize::MAX).await;
    assert_eq!(ended.unwrap(), Ended::Closed);
    assert_eq!(
        lines,
        vec![
            json!({ "seq": 1, "event": "ProfileSelected", "because": "Hysteria 2 carried 1.2 Mbit/s" }),
            json!({ "seq": 2, "event": "Degraded", "because": "the network is slow and it is the only one" }),
        ]
    );
}

#[tokio::test]
async fn what_cannot_be_read_or_has_no_reason_is_skipped_and_the_rest_carries_on() {
    let frames = vec![
        "this is not json".to_owned(),
        event(json!({ "event": "NoReason", "because": "", "seq": 1 })),
        event(json!({ "event": "Repeats", "because": "Repeats", "seq": 2 })),
        event(json!({ "because": "no name", "seq": 3 })),
        event(json!({ "event": "Fine", "because": "this one is fine", "seq": 4 })),
    ];
    let (ended, lines) = run(r#"{"subscribed":true,"backlog":0}"#, frames, usize::MAX).await;
    assert_eq!(ended.unwrap(), Ended::Closed);
    assert_eq!(
        lines,
        vec![json!({ "seq": 4, "event": "Fine", "because": "this one is fine" })]
    );
}

#[tokio::test]
async fn an_event_from_the_outside_is_cleaned_before_it_is_handed_on() {
    let frames = vec![event(
        json!({ "event": "Disc\u{202e}onnected", "because": "so\u{7}me\u{200b}thing happened", "seq": 9 }),
    )];
    let (_, lines) = run(r#"{"subscribed":true,"backlog":1}"#, frames, usize::MAX).await;
    assert_eq!(
        lines,
        vec![json!({ "seq": 9, "event": "Disc?onnected", "because": "so?me?thing happened" })]
    );
}

#[tokio::test]
async fn a_missing_sequence_number_is_null_not_invented() {
    let frames = vec![event(
        json!({ "event": "Fine", "because": "this one is fine" }),
    )];
    let (_, lines) = run(r#"{"subscribed":true,"backlog":1}"#, frames, usize::MAX).await;
    assert_eq!(lines[0]["seq"], Value::Null);
}

#[tokio::test]
async fn the_caller_can_stop_following() {
    let frames = vec![
        event(json!({ "event": "One", "because": "the first thing", "seq": 1 })),
        event(json!({ "event": "Two", "because": "the second thing", "seq": 2 })),
    ];
    let (ended, lines) = run(r#"{"subscribed":true,"backlog":2}"#, frames, 1).await;
    assert_eq!(ended.unwrap(), Ended::Stopped);
    assert_eq!(lines.len(), 1);
}

#[tokio::test]
async fn a_refused_subscription_says_why_and_no_events_follow() {
    let (ended, lines) = run(
        r#"{"error":"ServiceBusy","detail":"too many windows are open","retryable":true}"#,
        vec![],
        usize::MAX,
    )
    .await;
    assert_eq!(
        ended.unwrap(),
        Ended::Refused {
            detail: "too many windows are open".to_owned()
        }
    );
    assert!(lines.is_empty());
}

#[tokio::test]
async fn a_stream_that_ends_mid_frame_is_an_error_not_a_quiet_end() {
    let (client, mut server) = duplex(8192);
    let writer = tokio::spawn(async move {
        let mut request = [0_u8; 256];
        let _ = server.read(&mut request).await.unwrap();
        server
            .write_all(&frame::encode(r#"{"subscribed":true,"backlog":0}"#).unwrap())
            .await
            .unwrap();
        // The start of a frame that never finishes.
        server.write_all(&[200, 0, 0, 0, b'{']).await.unwrap();
    });
    let mut connection = Connection::new(client);
    let ended = follow(&mut connection, |_, _| true).await;
    writer.await.unwrap();
    assert!(ended.is_err(), "{ended:?}");
}

#[tokio::test]
async fn a_refusal_is_cleaned_like_everything_else_from_the_service() {
    let hostile =
        r#"{"error":"ServiceBusy","detail":"too\u202e many\u0007 windows","retryable":true}"#;
    let (ended, _) = run(hostile, vec![], usize::MAX).await;
    assert_eq!(
        ended.unwrap(),
        Ended::Refused {
            detail: "too? many? windows".to_owned()
        }
    );
}

#[tokio::test]
async fn the_services_replay_is_told_apart_from_what_happens_live() {
    let frames = vec![
        event(json!({ "event": "One", "because": "the first thing", "seq": 1 })),
        "garbage that still counts as a replayed frame".to_owned(),
        event(json!({ "event": "Two", "because": "the second thing", "seq": 2 })),
        event(json!({ "event": "Three", "because": "the third thing", "seq": 3 })),
    ];
    let (client, server) = duplex(8192);
    let writer = tokio::spawn(serve(
        server,
        r#"{"subscribed":true,"backlog":3}"#.to_owned(),
        frames,
    ));
    let mut connection = Connection::new(client);
    let mut seen = Vec::new();
    follow(&mut connection, |line, replay| {
        seen.push((line["seq"].as_u64().unwrap(), replay));
        true
    })
    .await
    .unwrap();
    writer.await.unwrap();
    assert_eq!(seen, vec![(1, true), (2, true), (3, false)]);
}

#[tokio::test]
async fn a_reply_that_does_not_count_the_replay_means_everything_is_live() {
    for first in [
        r#"{"subscribed":true}"#,
        r#"{"subscribed":true,"backlog":"many"}"#,
        r#"{"subscribed":true,"backlog":-1}"#,
    ] {
        let frames = vec![event(
            json!({ "event": "One", "because": "the first thing", "seq": 1 }),
        )];
        let (client, server) = duplex(8192);
        let writer = tokio::spawn(serve(server, first.to_owned(), frames));
        let mut connection = Connection::new(client);
        let mut replays = Vec::new();
        follow(&mut connection, |_, replay| {
            replays.push(replay);
            true
        })
        .await
        .unwrap();
        writer.await.unwrap();
        assert_eq!(replays, vec![false], "{first}");
    }
}
