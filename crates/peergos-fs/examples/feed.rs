//! Social profile + posts + feed, end to end (single user):
//!  - set and read back a profile (bio/status/name — one file per field),
//!  - open the social feed, create two text posts,
//!  - the posts appear in the feed; read each post back from its capability.
//!
//!   cargo run -p peergos-fs --example feed -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{Content, Profile, Resharing, SocialFeed, SocialPost, UserContext};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster, store.clone(), mutable.clone()).await?,
    };
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // --- Profile: set some fields, read them back ------------------------------
    let bio = format!("just a test user ({n})");
    ctx.set_bio(&bio).await?;
    ctx.set_first_name("Wendy").await?;
    ctx.set_status("hacking on peergos").await?;
    ctx.set_profile(&Profile { email: Some("w2@example.com".into()), ..Default::default() }).await?;

    let profile = ctx.get_own_profile().await?;
    println!(
        "profile: first_name={:?} bio={:?} status={:?} email={:?}",
        profile.first_name, profile.bio, profile.status, profile.email
    );
    assert_eq!(profile.bio.as_deref(), Some(bio.as_str()));
    assert_eq!(profile.first_name.as_deref(), Some("Wendy"));
    assert_eq!(profile.email.as_deref(), Some("w2@example.com"));

    // --- Feed: create posts, read them back ------------------------------------
    let mut feed = SocialFeed::create(&ctx).await?;
    let size_before = feed.feed_size();
    println!("\nfeed opened; size={size_before}");

    let p1 = SocialPost::text("w2", format!("hello world #{n}"), Resharing::Public);
    let p2 = SocialPost::text("w2", format!("second post #{n}"), Resharing::Friends);
    let path1 = feed.create_new_post(&p1).await?;
    let path2 = feed.create_new_post(&p2).await?;
    println!("created two posts:\n  {path1}\n  {path2}");

    assert_eq!(feed.feed_size(), size_before + 2, "feed should have grown by 2");
    assert!(feed.has_unseen());

    // The two newest items in the feed are our posts; read them back.
    let recent = feed.get_shared(feed.feed_size() - 2, feed.feed_size()).await?;
    println!("\nnewest {} feed item(s):", recent.len());
    let mut texts = Vec::new();
    for item in &recent {
        let post = feed.read_post(item).await?;
        println!("  [{}] {:?} -> {:?} (share_to {:?})", item.sharer, item.path, post.text_body(), post.share_to);
        texts.push(post.text_body());
    }
    assert!(texts.contains(&format!("hello world #{n}")));
    assert!(texts.contains(&format!("second post #{n}")));

    // --- Feed index: seek to an arbitrary range via feed-index.cbor ------------
    let first = feed.get_shared(0, 1).await?;
    assert_eq!(first.len(), 1);
    let last = feed.get_shared(feed.feed_size() - 1, feed.feed_size()).await?;
    assert_eq!(last.len(), 1);
    assert_eq!(last[0].path, path2, "index-seeked last record should be the 2nd post");
    println!("\nfeed-index seek: get_shared(0,1) and get_shared(last) resolve correctly");

    // --- Comment merging: a comment on our post is merged into the parent ------
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let parent_ref = feed.file_ref(&path1).await?;
    let comment = SocialPost::text_comment(parent_ref, Resharing::Public, "w2", format!("nice post! #{n}"));
    let comment_path = feed.create_new_post(&comment).await?;
    let updated_parent = feed.read_post_at(&path1).await?;
    println!("\nafter commenting, parent post has {} comment(s)", updated_parent.comments.len());
    assert_eq!(updated_parent.comments.len(), 1, "comment should be merged into the parent");
    assert_eq!(updated_parent.comments[0].path, comment_path);
    // The parent's cap is unchanged (in-place overwrite): the feed item still reads it.
    let parent_via_feed = feed.read_post(&first[0]).await?;
    assert_eq!(parent_via_feed.comments.len(), 1, "feed item cap should see the merged comment");

    // --- Media attachment: upload media, reference it in a post ----------------
    let media = vec![0xABu8; 4096];
    let media_ref = feed.upload_media(&media, now).await?;
    println!("\nuploaded media -> {} (content-hash {} bytes)", media_ref.path, media_ref.content_hash.len());
    assert_eq!(media_ref.content_hash.len(), 34, "content hash is a sha2-256 multihash (0x12,0x20,+32)");
    let media_post = SocialPost::create_initial(
        "w2",
        vec![Content::Text("check this out".into()), Content::Reference(media_ref.clone())],
        Resharing::Public,
    );
    let mpath = feed.create_new_post(&media_post).await?;
    let reread = feed.read_post_at(&mpath).await?;
    let has_ref = reread.body.iter().any(|c| matches!(c, Content::Reference(r) if r.path == media_ref.path));
    assert!(has_ref, "the media reference should round-trip in the post body");
    let (_p, mdata) = peergos_fs::read_file(&media_ref.cap, store.clone(), mutable.as_ref()).await?;
    assert_eq!(mdata, media, "media read back via its FileRef cap should match");
    println!("media reference round-trips in the post + reads back via its cap");

    // A reload sees the same feed size (state persisted).
    let reloaded = SocialFeed::create(&ctx).await?;
    assert_eq!(reloaded.feed_size(), feed.feed_size());
    println!("\nreloaded feed size matches: {}", reloaded.feed_size());

    println!("\nProfile + feed OK: profile, posts, feed, index seek, comment merge (in-place), media attachments.");
    Ok(())
}
