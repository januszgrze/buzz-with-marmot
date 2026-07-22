//! End-to-end coverage for the relay-facing Marmot Nostr transport boundary.
//!
//! These tests intentionally exercise only opaque transport envelopes. MLS
//! creation, decryption, and convergence belong to upstream MDK and are covered
//! by the separate MDK interoperability harness.
//!
//! Start a relay and run:
//!
//! ```text
//! cargo test -p buzz-test-client --test e2e_marmot_transport -- --ignored
//! ```

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use buzz_test_client::{BuzzTestClient, RelayMessage};
use nostr::{Alphabet, EventBuilder, Filter, Keys, Kind, SingleLetterTag, Tag};

const KIND_MARMOT_GROUP_MESSAGE: u16 = 445;
const KIND_MARMOT_WELCOME_RUMOR: u16 = 444;
const MINIMUM_OPAQUE_GROUP_ENVELOPE_BYTES: usize = 12 + 16;

fn relay_url() -> String {
    std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:3000".to_string())
}

fn routing_id() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

fn group_event(keys: &Keys, route: &str, extra_tags: Vec<Tag>) -> nostr::Event {
    let mut tags = vec![Tag::parse(["h", route]).expect("valid h tag")];
    tags.extend(extra_tags);
    EventBuilder::new(
        Kind::Custom(KIND_MARMOT_GROUP_MESSAGE),
        BASE64_STANDARD.encode([0_u8; MINIMUM_OPAQUE_GROUP_ENVELOPE_BYTES]),
    )
    .tags(tags)
    .sign_with_keys(keys)
    .expect("sign Marmot transport event")
}

fn h_filter(route: &str) -> Filter {
    Filter::new()
        .kind(Kind::Custom(KIND_MARMOT_GROUP_MESSAGE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), route)
}

#[tokio::test]
#[ignore]
async fn authenticated_member_can_publish_ephemeral_marmot_envelope() {
    let auth_keys = Keys::generate();
    let ephemeral_keys = Keys::generate();
    let route = routing_id();
    let mut client = BuzzTestClient::connect(&relay_url(), &auth_keys)
        .await
        .expect("connect and authenticate");

    let event = group_event(&ephemeral_keys, &route, Vec::new());
    assert_ne!(event.pubkey, auth_keys.public_key());

    let response = client.send_event(event).await.expect("publish event");
    assert!(
        response.accepted,
        "relay rejected valid Marmot envelope: {}",
        response.message
    );

    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn bare_marmot_welcome_rumor_is_rejected() {
    let auth_keys = Keys::generate();
    let mut client = BuzzTestClient::connect(&relay_url(), &auth_keys)
        .await
        .expect("connect and authenticate");

    // Kind 444 is an unsigned rumor carried inside a NIP-59 gift wrap. It is
    // registered for client parsing, but is never a valid direct relay write.
    let event = EventBuilder::new(
        Kind::Custom(KIND_MARMOT_WELCOME_RUMOR),
        BASE64_STANDARD.encode([0_u8; MINIMUM_OPAQUE_GROUP_ENVELOPE_BYTES]),
    )
    .sign_with_keys(&auth_keys)
    .expect("sign direct Welcome rumor");

    let response = client.send_event(event).await.expect("publish event");
    assert!(
        !response.accepted,
        "relay accepted a bare Marmot Welcome rumor"
    );

    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn exact_h_subscription_receives_only_its_marmot_route() {
    let subscriber_keys = Keys::generate();
    let publisher_keys = Keys::generate();
    let ephemeral_keys = Keys::generate();
    let wanted_route = routing_id();
    let other_route = routing_id();
    let subscription_id = format!("marmot-route-{}", uuid::Uuid::new_v4());

    let mut subscriber = BuzzTestClient::connect(&relay_url(), &subscriber_keys)
        .await
        .expect("connect subscriber");
    subscriber
        .subscribe(&subscription_id, vec![h_filter(&wanted_route)])
        .await
        .expect("subscribe to Marmot route");
    subscriber
        .collect_until_eose(&subscription_id, Duration::from_secs(5))
        .await
        .expect("initial EOSE");

    let mut publisher = BuzzTestClient::connect(&relay_url(), &publisher_keys)
        .await
        .expect("connect publisher");

    let unrelated = group_event(&ephemeral_keys, &other_route, Vec::new());
    let unrelated_response = publisher
        .send_event(unrelated)
        .await
        .expect("publish unrelated route");
    assert!(unrelated_response.accepted, "unrelated envelope rejected");

    let wanted = group_event(&Keys::generate(), &wanted_route, Vec::new());
    let wanted_id = wanted.id;
    let wanted_response = publisher
        .send_event(wanted)
        .await
        .expect("publish wanted route");
    assert!(wanted_response.accepted, "wanted envelope rejected");

    let received = subscriber
        .recv_event(Duration::from_secs(5))
        .await
        .expect("receive wanted route");
    match received {
        RelayMessage::Event {
            subscription_id: received_subscription_id,
            event,
        } => {
            assert_eq!(received_subscription_id, subscription_id);
            assert_eq!(event.id, wanted_id);
            assert_eq!(event.kind, Kind::Custom(KIND_MARMOT_GROUP_MESSAGE));
        }
        other => panic!("expected Marmot EVENT, got {other:?}"),
    }

    publisher.disconnect().await.expect("disconnect publisher");
    subscriber
        .disconnect()
        .await
        .expect("disconnect subscriber");
}

#[tokio::test]
#[ignore]
async fn marmot_subscription_without_h_is_closed() {
    let keys = Keys::generate();
    let subscription_id = format!("marmot-no-h-{}", uuid::Uuid::new_v4());
    let mut client = BuzzTestClient::connect(&relay_url(), &keys)
        .await
        .expect("connect");

    client
        .subscribe(
            &subscription_id,
            vec![Filter::new().kind(Kind::Custom(KIND_MARMOT_GROUP_MESSAGE))],
        )
        .await
        .expect("send broadened subscription");

    let response = client
        .recv_event(Duration::from_secs(5))
        .await
        .expect("receive CLOSED");
    match response {
        RelayMessage::Closed {
            subscription_id: received_subscription_id,
            message,
        } => {
            assert_eq!(received_subscription_id, subscription_id);
            assert!(
                message.contains("#h")
                    || message.to_ascii_lowercase().contains("marmot")
                    || message.to_ascii_lowercase().contains("restricted"),
                "unexpected CLOSED reason: {message}"
            );
        }
        other => panic!("expected CLOSED, got {other:?}"),
    }

    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn marmot_envelope_with_non_transport_tag_is_rejected() {
    let auth_keys = Keys::generate();
    let route = routing_id();
    let mut client = BuzzTestClient::connect(&relay_url(), &auth_keys)
        .await
        .expect("connect");
    let forbidden_tag =
        Tag::parse(["p", &Keys::generate().public_key().to_hex()]).expect("valid p tag");
    let event = group_event(&Keys::generate(), &route, vec![forbidden_tag]);

    let response = client.send_event(event).await.expect("publish event");
    assert!(
        !response.accepted,
        "relay accepted Marmot envelope with a forbidden tag"
    );

    client.disconnect().await.expect("disconnect");
}
