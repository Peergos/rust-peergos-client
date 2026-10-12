//! Social and publishing behaviour against the in-process mock server: blocking
//! versus unfollowing (`BlockTests`), follow request processing, custom groups,
//! resumable follower removal and publishing through secret links.

use peergos_core::mutable::MutablePointers;
use peergos_core::{ContentAddressedStorage, HttpPoster};
use peergos_fs::UserContext;
use peergos_mock_server::MockServer;
use std::sync::Arc;

type Poster = Arc<dyn HttpPoster>;
type Store = Arc<dyn ContentAddressedStorage>;
type Mut = Arc<dyn MutablePointers>;

struct Net {
    _server: MockServer,
    poster: Poster,
    store: Store,
    mutable: Mut,
}

impl Net {
    fn new() -> Net {
        let server = MockServer::new();
        let (poster, store, mutable) = server.connect();
        Net { _server: server, poster, store, mutable }
    }

    async fn sign_up(&self, username: &str) -> UserContext {
        UserContext::sign_up(username, "pw", None, self.poster.clone(), self.store.clone(), self.mutable.clone()).await.unwrap()
    }

    async fn login(&self, username: &str) -> UserContext {
        UserContext::sign_in(username, "pw", None, self.poster.clone(), self.store.clone(), self.mutable.clone()).await.unwrap()
    }

    async fn send_request(&self, from: &str, to: &str) -> peergos_core::error::Result<bool> {
        let ctx = self.login(from).await;
        peergos_fs::send_follow_request(ctx.user().unwrap(), to, true, self.poster.as_ref(), self.store.clone(), self.mutable.as_ref())
            .await
    }

    /// `to` answers `from`'s request; `from` then processes the reply.
    async fn answer(&self, from: &str, to: &str, accept: bool, reciprocate: bool) {
        let ctx = self.login(to).await;
        let user = ctx.user().unwrap();
        let reqs = ctx.social_state().await.unwrap().pending_incoming_requests;
        let req = reqs.iter().find(|r| r.sender() == Some(from)).expect("request from sender");
        if accept {
            peergos_fs::accept_follow_request(user, req, reciprocate, self.poster.as_ref(), self.store.clone(), self.mutable.as_ref())
                .await
                .unwrap();
        } else {
            peergos_fs::reject_follow_request(user, req, reciprocate, self.poster.as_ref(), self.store.clone(), self.mutable.as_ref())
                .await
                .unwrap();
        }
        self.login(from).await.social_state().await.unwrap();
    }

    async fn friends(&self, a: &str, b: &str) {
        self.send_request(a, b).await.unwrap();
        self.answer(a, b, true, true).await;
    }

    async fn following(&self, username: &str) -> Vec<String> {
        self.login(username).await.social_state().await.unwrap().following
    }
}

#[tokio::test]
async fn befriending_records_and_clears_the_pending_request() {
    let net = Net::new();
    net.sign_up("alice").await;
    net.sign_up("bob").await;
    net.send_request("alice", "bob").await.unwrap();
    let alice = net.login("alice").await.social_state().await.unwrap();
    assert_eq!(alice.pending_outgoing, vec!["bob".to_string()]);
    assert!(!alice.followers.contains(&"bob".to_string()), "a pending request isn't a follower");

    net.answer("alice", "bob", true, true).await;
    let alice = net.login("alice").await.social_state().await.unwrap();
    assert!(alice.pending_outgoing.is_empty());
    assert_eq!(alice.friend_names(), vec!["bob".to_string()]);
    let bob = net.login("bob").await.social_state().await.unwrap();
    assert_eq!(bob.friend_names(), vec!["alice".to_string()]);

    // both built-in groups hold the friend
    let ctx = net.login("alice").await;
    for name in [peergos_fs::FOLLOWERS_GROUP, peergos_fs::FRIENDS_GROUP] {
        let uid = alice.group_uid(name).unwrap();
        assert!(ctx.get_group_members(&uid).await.unwrap().contains("bob"), "{name} group");
    }
}

#[tokio::test]
async fn already_friends_cannot_request_again() {
    let net = Net::new();
    net.sign_up("alice").await;
    net.sign_up("bob").await;
    net.friends("alice", "bob").await;
    assert!(net.send_request("alice", "bob").await.is_err());
}

#[tokio::test]
async fn rejecting_a_request_leaves_no_follower() {
    let net = Net::new();
    net.sign_up("alice").await;
    net.sign_up("bob").await;
    net.send_request("alice", "bob").await.unwrap();
    net.answer("alice", "bob", false, false).await;
    let bob = net.login("bob").await.social_state().await.unwrap();
    assert!(!bob.followers.contains(&"alice".to_string()));
    let alice = net.login("alice").await.social_state().await.unwrap();
    assert!(alice.pending_outgoing.is_empty(), "the reply clears our pending request");
    assert!(!alice.followers.contains(&"bob".to_string()), "they didn't follow us back");
    assert!(!alice.following.contains(&"bob".to_string()));
}

#[tokio::test]
async fn unfollow_is_not_blocking() {
    let net = Net::new();
    net.sign_up("a").await;
    net.sign_up("b").await;
    net.friends("a", "b").await;
    net.login("a").await.unfollow("b").await.unwrap();

    let a = net.login("a").await.social_state().await.unwrap();
    assert!(a.unfollowed.contains(&"b".to_string()));
    assert!(!a.blocked.contains(&"b".to_string()));
    assert!(!a.following.contains(&"b".to_string()));
    assert!(a.followers.contains(&"b".to_string()), "unfollowing is local, they still follow us");
    assert!(net.following("b").await.contains(&"a".to_string()));

    net.login("a").await.follow_again("b").await.unwrap();
    let again = net.login("a").await.social_state().await.unwrap();
    assert!(!again.unfollowed.contains(&"b".to_string()));
    assert!(again.friend_names().contains(&"b".to_string()));
}

#[tokio::test]
async fn blocking_removes_them_as_follower() {
    let net = Net::new();
    net.sign_up("a").await;
    net.sign_up("b").await;
    net.friends("a", "b").await;
    net.login("a").await.block("b").await.unwrap();

    let ctx = net.login("a").await;
    let a = ctx.social_state().await.unwrap();
    assert!(a.blocked.contains(&"b".to_string()));
    assert!(a.unfollowed.contains(&"b".to_string()), "a block is also an unfollow, for older clients");
    assert!(!a.following.contains(&"b".to_string()));
    assert!(!a.followers.contains(&"b".to_string()));
    for name in [peergos_fs::FOLLOWERS_GROUP, peergos_fs::FRIENDS_GROUP] {
        let uid = a.group_uid(name).unwrap();
        assert!(!ctx.get_group_members(&uid).await.unwrap().contains("b"), "{name} group");
    }
    assert!(!net.following("b").await.contains(&"a".to_string()), "they can no longer see us");
}

#[tokio::test]
async fn unblocking_leaves_them_unfollowed() {
    let net = Net::new();
    net.sign_up("a").await;
    net.sign_up("b").await;
    net.friends("a", "b").await;
    let a = net.login("a").await;
    a.block("b").await.unwrap();
    assert!(a.follow_again("b").await.is_err(), "following a blocked user again should fail");

    a.unblock("b").await.unwrap();
    let state = net.login("a").await.social_state().await.unwrap();
    assert!(!state.blocked.contains(&"b".to_string()));
    assert!(state.unfollowed.contains(&"b".to_string()));

    // they still let us follow them, so we can see them again
    net.login("a").await.follow_again("b").await.unwrap();
    assert!(net.following("a").await.contains(&"b".to_string()));
}

#[tokio::test]
async fn requests_from_blocked_users_are_removed() {
    let net = Net::new();
    net.sign_up("a").await;
    net.sign_up("b").await;
    net.login("a").await.block("b").await.unwrap();
    net.send_request("b", "a").await.unwrap();

    let a = net.login("a").await;
    let user = a.user().unwrap();
    assert!(peergos_fs::process_follow_requests(user, net.poster.as_ref(), net.store.clone(), net.mutable.as_ref())
        .await
        .unwrap()
        .is_empty());
    assert!(peergos_fs::get_follow_requests(user, net.poster.as_ref()).await.unwrap().is_empty(), "removed from the server");
    // and they were denied rather than left waiting
    let b = net.login("b").await.social_state().await.unwrap();
    assert!(b.pending_outgoing.is_empty());
}

#[tokio::test]
async fn cannot_request_to_follow_blocked_user() {
    let net = Net::new();
    net.sign_up("a").await;
    net.sign_up("b").await;
    net.login("a").await.block("b").await.unwrap();
    assert!(net.send_request("a", "b").await.is_err());
    assert!(net.login("b").await.social_state().await.unwrap().pending_incoming_requests.is_empty());
}

#[tokio::test]
async fn interrupted_follower_removal_is_completed() {
    let net = Net::new();
    net.sign_up("a").await;
    net.sign_up("b").await;
    net.friends("a", "b").await;

    // an interrupted removal: their sharing dir was hidden but nothing else happened
    let a = net.login("a").await;
    a.get_home().await.unwrap().child("shared").await.unwrap().unwrap().rename_child("b", ".removing-b").await.unwrap();

    let ctx = net.login("a").await;
    let state = ctx.social_state().await.unwrap();
    assert!(!state.followers.contains(&"b".to_string()));
    let shared = ctx.get_home().await.unwrap().child("shared").await.unwrap().unwrap();
    assert!(shared.child(".removing-b").await.unwrap().is_none(), "the hidden dir is deleted");
    for name in [peergos_fs::FOLLOWERS_GROUP, peergos_fs::FRIENDS_GROUP] {
        let uid = state.group_uid(name).unwrap();
        assert!(!ctx.get_group_members(&uid).await.unwrap().contains("b"), "{name} group");
    }
}

#[tokio::test]
async fn custom_groups() {
    let net = Net::new();
    for u in ["a", "b", "c"] {
        net.sign_up(u).await;
    }
    net.friends("a", "b").await;
    net.friends("a", "c").await;
    let a = net.login("a").await;

    assert!(a.create_group("friends", &[]).await.is_err(), "built-in names are reserved");
    assert!(a.create_group("x", &["nobody".to_string()]).await.is_err(), "only followers can be members");

    let uid = a.create_group("climbing", &["b".to_string()]).await.unwrap();
    let state = a.social_state().await.unwrap();
    assert_eq!(state.groups.get(&uid).map(String::as_str), Some("climbing"));
    assert_eq!(state.group_uids().len(), 3);
    assert_eq!(state.group_uids()[2], uid, "custom groups come after the built-in ones");

    a.add_group_members(&uid, &["c".to_string()]).await.unwrap();
    assert_eq!(a.get_group_members(&uid).await.unwrap().into_iter().collect::<Vec<_>>(), vec!["b", "c"]);
    a.rename_group(&uid, "bouldering").await.unwrap();
    assert_eq!(a.social_state().await.unwrap().groups.get(&uid).map(String::as_str), Some("bouldering"));

    // share a file with the group, then revoke it by deleting the group
    a.get_home().await.unwrap().upload("plan.txt", b"tuesday").await.unwrap();
    let file = a.get_by_path("plan.txt").await.unwrap().unwrap();
    peergos_fs::share_read_access(a.user().unwrap(), "plan.txt", file.capability(), &uid, net.store.clone(), net.mutable.as_ref())
        .await
        .unwrap();
    assert_eq!(a.count_shared_with_group(&uid).await.unwrap(), 1);

    a.remove_group_member(&uid, "c", false).await.unwrap();
    assert_eq!(a.get_group_members(&uid).await.unwrap().into_iter().collect::<Vec<_>>(), vec!["b"]);

    let builtin = state.group_uid(peergos_fs::FRIENDS_GROUP).unwrap();
    assert!(a.delete_group(&builtin, false, || {}).await.is_err(), "built-in groups cannot be deleted");
    let mut revoked = 0;
    a.delete_group(&uid, true, || revoked += 1).await.unwrap();
    assert_eq!(revoked, 1);
    assert!(!a.social_state().await.unwrap().groups.contains_key(&uid));
    assert_eq!(a.count_shared_with_group(&uid).await.unwrap(), 0);
    assert_ne!(a.get_by_path("plan.txt").await.unwrap().unwrap().capability(), file.capability(), "its keys were rotated");
}

#[tokio::test]
async fn publishing_goes_through_a_secret_link() {
    let net = Net::new();
    let alice = net.sign_up("alice").await;
    alice.get_home().await.unwrap().upload("site.txt", b"hello").await.unwrap();
    alice.make_public("site.txt").await.unwrap();

    let link = alice.get_published_link("/alice/site.txt").await.unwrap();
    let cap = peergos_fs::retrieve_secret_link_capability(&link.to_link(), net.store.as_ref(), None).await.unwrap();
    let public = alice.get_public_capability("/alice/site.txt").await.unwrap();
    assert_eq!(cap.map_key, public.map_key, "the link opens the published file");

    // republishing the same file keeps its link
    alice.make_public("site.txt").await.unwrap();
    assert_eq!(alice.get_published_link("/alice/site.txt").await.unwrap(), link);
    assert_eq!(alice.get_all_secret_links().await.unwrap().len(), 1);

    alice.unpublish("site.txt").await.unwrap();
    assert!(alice.get_public_capability("/alice/site.txt").await.is_err());
    assert!(
        peergos_fs::retrieve_secret_link_capability(&link.to_link(), net.store.as_ref(), None).await.is_err(),
        "the link is deleted with the publication"
    );
    assert!(alice.get_all_secret_links().await.unwrap().is_empty());
}
