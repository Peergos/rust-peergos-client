//! CRDT-level integration tests: drive a two-member chat entirely through the
//! `Chat` state machine and in-memory [`RamMessageStore`]s, mirroring what
//! `ChatController`/`Messenger` do against the filesystem.

use super::*;
use crate::feed::Content;
use peergos_core::keys::{OwnerProof, PublicKeyHash, SigningKeyPair, SigningPrivateKeyAndPublicHash};
use peergos_core::ram::RamStorage;
use peergos_core::storage::ContentAddressedStorage;
use std::sync::Arc;

/// A user's identity: a random Ed25519 keypair whose hash is an inline identity
/// multihash, so signatures verify without a populated block store.
struct User {
    signer: SigningPrivateKeyAndPublicHash,
    identity: PublicKeyHash,
}

fn user() -> User {
    let kp = SigningKeyPair::random().unwrap();
    let signer = kp.to_private_and_hash().unwrap();
    let identity = signer.public_key_hash.clone();
    User { signer, identity }
}

/// Append an update's new messages to `store` and return the new chat state,
/// mirroring `ChatController.commitUpdate` (append log, then adopt state).
async fn commit(store: &RamMessageStore, prev_upto: i64, update: ChatUpdate) -> Chat {
    store.add_messages(prev_upto, update.new_messages).await.unwrap();
    update.state
}

#[tokio::test]
async fn two_member_chat_end_to_end() {
    let cas: Arc<dyn ContentAddressedStorage> = Arc::new(RamStorage::new());
    let uid = "chat$alice$uuid".to_string();

    let alice = user();
    let bob = user();

    // --- Alice creates the chat and joins it ------------------------------
    let priv_a = Chat::generate_chat_identity().unwrap();
    let store_a = RamMessageStore::new();
    let mut chat_a = Chat::create_new(uid.clone(), "alice", alice.identity.clone());

    let host = chat_a.host().clone();
    let chat_id = OwnerProof::build(&alice.signer, &priv_a.chat_identity.public_key_hash).unwrap();
    let upto = chat_a.host().messages_merged_upto;
    let update = chat_a
        .join(&host, chat_id, priv_a.chat_id_public.clone(), &alice.signer, &store_a, cas.as_ref())
        .await
        .unwrap();
    chat_a = commit(&store_a, upto, update).await;
    assert!(chat_a.host().chat_identity.is_some(), "alice should have a chat identity after joining");
    assert_eq!(store_a.len(), 1);

    // --- Alice makes herself admin and sets a title -----------------------
    for msg in [
        Message::GroupState { key: ADMINS_STATE_KEY.to_string(), value: "alice".to_string() },
        Message::GroupState { key: "title".to_string(), value: "Our Chat".to_string() },
    ] {
        let upto = chat_a.host().messages_merged_upto;
        let update = chat_a
            .send_message(msg, &priv_a.chat_identity, &alice.signer, &store_a, cas.as_ref())
            .await
            .unwrap();
        chat_a = commit(&store_a, upto, update).await;
    }
    assert_eq!(chat_a.get_title(), "Our Chat");
    assert!(chat_a.get_admins().contains("alice"));

    // --- Alice invites Bob ------------------------------------------------
    let upto = chat_a.host().messages_merged_upto;
    let update = chat_a
        .invite_members(vec!["bob".to_string()], vec![bob.identity.clone()], &priv_a.chat_identity, &alice.signer, &store_a, cas.as_ref())
        .await
        .unwrap();
    chat_a = commit(&store_a, upto, update).await;
    let bob_id = chat_a.get_member("bob").expect("bob invited").id.clone();

    // --- Bob clones Alice's state + log, then joins -----------------------
    let priv_b = Chat::generate_chat_identity().unwrap();
    let store_b = RamMessageStore::new();
    // Copy the shared message log.
    let all = store_a.get_messages_from(0).await.unwrap();
    store_b.add_messages(0, all).await.unwrap();
    // Copy the state rooted at Bob (Messenger.cloneLocallyAndJoin).
    let bob_member = Member::new(
        "bob".to_string(),
        bob_id.clone(),
        bob.identity.clone(),
        None,
        chat_a.host().messages_merged_upto,
        0,
        false,
    );
    let mut chat_b = chat_a.copy(bob_member).unwrap();
    let host_b = chat_b.host().clone();
    let chat_id_b = OwnerProof::build(&bob.signer, &priv_b.chat_identity.public_key_hash).unwrap();
    let upto = chat_b.host().messages_merged_upto;
    let update = chat_b
        .join(&host_b, chat_id_b, priv_b.chat_id_public.clone(), &bob.signer, &store_b, cas.as_ref())
        .await
        .unwrap();
    chat_b = commit(&store_b, upto, update).await;

    // Bob's cloned state already carries the group properties.
    assert_eq!(chat_b.get_title(), "Our Chat");
    assert!(chat_b.get_admins().contains("alice"));

    // --- Alice merges Bob's mirror: she should see Bob has joined ---------
    let upto = chat_a.host().messages_merged_upto;
    let update = chat_a.merge(&bob_id, &alice.signer, &store_b, cas.as_ref()).await.unwrap();
    chat_a = commit(&store_a, upto, update).await;
    assert!(
        chat_a.get_member("bob").expect("bob known").chat_identity.is_some(),
        "alice should see bob's chat identity after merging"
    );

    // --- Alice sends a text message; Bob merges and sees it ---------------
    let upto = chat_a.host().messages_merged_upto;
    let update = chat_a
        .send_message(
            Message::Application(ApplicationMessage::text("hello bob")),
            &priv_a.chat_identity,
            &alice.signer,
            &store_a,
            cas.as_ref(),
        )
        .await
        .unwrap();
    chat_a = commit(&store_a, upto, update).await;

    let upto = chat_b.host().messages_merged_upto;
    let update = chat_b.merge(&chat_a.host().id.clone(), &bob.signer, &store_a, cas.as_ref()).await.unwrap();
    chat_b = commit(&store_b, upto, update).await;

    let got_hello = chat_b.get_recent().iter().any(|env| match &env.payload {
        Message::Application(m) => m.body.iter().any(|c| matches!(c, Content::Text(t) if t == "hello bob")),
        _ => false,
    });
    assert!(got_hello, "bob should have received alice's message after merging");

    // Both agree on the member set.
    assert!(chat_a.get_member("bob").is_some() && chat_b.get_member("alice").is_some());
}

#[test]
fn chat_state_cbor_roundtrip() {
    let alice = user();
    let chat = Chat::create_new("chat$alice$uuid", "alice", alice.identity);
    let reparsed = Chat::from_cbor(&peergos_cbor::Cborable::to_cbor(&chat)).unwrap();
    assert_eq!(reparsed, chat);
}

#[test]
fn message_cbor_roundtrips() {
    use peergos_cbor::Cborable;
    let alice = user();
    let msgs = vec![
        Message::Application(ApplicationMessage::text("hi")),
        Message::GroupState { key: "title".into(), value: "T".into() },
        Message::Invite { username: "bob".into(), identity: alice.identity.clone(), recipient_id: Id::new(vec![0, 1]) },
        Message::RemoveMember { chat_uid: "u".into(), member_to_remove: Id::new(vec![0, 1]) },
        Message::Delete { target: MessageRef::new(bare_hash(b"x")) },
    ];
    for m in msgs {
        assert_eq!(Message::from_cbor(&m.to_cbor()).unwrap(), m);
    }
}
