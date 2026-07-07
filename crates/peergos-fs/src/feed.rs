//! Social posts + feed, ported from Java's `SocialPost` / `SocialFeed`.
//!
//! A post is a [`SocialPost`] stored at `/username/.posts/<year>/<month>/<uuid>.cbor`.
//! Your feed lives in `/username/.feed/`:
//!   - `feed.cbor`       — an append-only stream of serialized [`SharedItem`]s,
//!   - `feed-state.cbor` — a [`FeedState`]: how far each friend's cap stream has
//!     been processed (reusing [`crate::ProcessedCaps`]) + the feed size.
//!
//! [`SocialFeed::create_new_post`] writes a post and adds it to your own feed;
//! [`SocialFeed::update`] pulls capabilities friends have shared with you (direct
//! and via groups) into the feed as new items.

use crate::capability::AbsoluteCapability;
use crate::context::UserContext;
use crate::filewrapper::FileWrapper;
use crate::incoming::ProcessedCaps;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

const POSTS_DIR: &str = ".posts";
const FEED_DIR: &str = ".feed";
const FEED_FILE: &str = "feed.cbor";
const FEED_INDEX: &str = "feed-index.cbor";
const FEED_STATE: &str = "feed-state.cbor";

/// `MimeTypes.CBOR_PEERGOS_POST_INT` — the tag that leads a serialized post.
const CBOR_PEERGOS_POST_INT: i64 = 17;

// ---------------------------------------------------------------------------
// Content / FileRef / Resharing
// ---------------------------------------------------------------------------

/// A reference to a file (an attachment, parent post or comment) (`FileRef`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRef {
    pub path: String,
    pub cap: AbsoluteCapability,
    /// The content's multihash bytes (a merkle link in cbor).
    pub content_hash: Vec<u8>,
}

impl FileRef {
    pub fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("p", CborObject::Str(self.path.clone()))
            .put("c", self.cap.to_cbor())
            .put("h", CborObject::MerkleLink(self.content_hash.clone()))
            .build()
    }
    pub fn from_cbor(cbor: &CborObject) -> Result<FileRef> {
        Ok(FileRef {
            path: cbor.get("p").and_then(|c| c.as_string()).ok_or_else(|| Error::Cbor("FileRef missing 'p'".into()))?.to_string(),
            cap: AbsoluteCapability::from_cbor(cbor.get("c").ok_or_else(|| Error::Cbor("FileRef missing 'c'".into()))?)?,
            content_hash: cbor.get("h").and_then(|c| c.as_link()).ok_or_else(|| Error::Cbor("FileRef missing 'h'".into()))?.to_vec(),
        })
    }
}

/// A piece of a post's body (`Content`): inline text or a file reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Text(String),
    Reference(FileRef),
}

impl Content {
    pub fn to_cbor(&self) -> CborObject {
        match self {
            Content::Text(s) => CborObject::Str(s.clone()),
            Content::Reference(r) => CborObject::map().put("t", CborObject::Str("Ref".into())).put("r", r.to_cbor()).build(),
        }
    }
    pub fn from_cbor(cbor: &CborObject) -> Result<Content> {
        match cbor {
            CborObject::Str(s) => Ok(Content::Text(s.clone())),
            CborObject::Map(_) => {
                let t = cbor.get("t").and_then(|c| c.as_string()).unwrap_or("");
                if t == "Ref" {
                    Ok(Content::Reference(FileRef::from_cbor(cbor.get("r").ok_or_else(|| Error::Cbor("Ref missing 'r'".into()))?)?))
                } else {
                    Err(Error::Cbor(format!("unknown content type: {t}")))
                }
            }
            _ => Err(Error::Cbor("invalid Content cbor".into())),
        }
    }
    pub fn inline_text(&self) -> Option<&str> {
        match self {
            Content::Text(s) => Some(s),
            Content::Reference(_) => None,
        }
    }
}

/// The audience a post may be reshared with (`SocialPost.Resharing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resharing {
    Author,
    Friends,
    Followers,
    Public,
}

impl Resharing {
    fn name(&self) -> &'static str {
        match self {
            Resharing::Author => "Author",
            Resharing::Friends => "Friends",
            Resharing::Followers => "Followers",
            Resharing::Public => "Public",
        }
    }
    fn from_name(s: &str) -> Result<Resharing> {
        Ok(match s {
            "Author" => Resharing::Author,
            "Friends" => Resharing::Friends,
            "Followers" => Resharing::Followers,
            "Public" => Resharing::Public,
            other => return Err(Error::Cbor(format!("unknown Resharing: {other}"))),
        })
    }
}

// ---------------------------------------------------------------------------
// SocialPost
// ---------------------------------------------------------------------------

/// A social post (`SocialPost`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocialPost {
    pub author: String,
    pub body: Vec<Content>,
    /// Post time in epoch seconds (UTC).
    pub post_time: i64,
    pub share_to: Resharing,
    pub parent: Option<FileRef>,
    pub previous_versions: Vec<SocialPost>,
    pub comments: Vec<FileRef>,
}

impl SocialPost {
    /// A new top-level text post (`createInitialPost` with a single `Text`).
    pub fn text(author: impl Into<String>, text: impl Into<String>, share_to: Resharing) -> SocialPost {
        SocialPost::create_initial(author, vec![Content::Text(text.into())], share_to)
    }

    pub fn create_initial(author: impl Into<String>, body: Vec<Content>, share_to: Resharing) -> SocialPost {
        SocialPost {
            author: author.into(),
            body,
            post_time: now_epoch_secs(),
            share_to,
            parent: None,
            previous_versions: Vec::new(),
            comments: Vec::new(),
        }
    }

    /// A comment on `parent` (`createComment`): a post whose `parent` points at the
    /// commented-on post and which inherits its resharing audience.
    pub fn create_comment(
        parent: FileRef,
        from_parent: Resharing,
        author: impl Into<String>,
        body: Vec<Content>,
    ) -> SocialPost {
        SocialPost {
            author: author.into(),
            body,
            post_time: now_epoch_secs(),
            share_to: from_parent,
            parent: Some(parent),
            previous_versions: Vec::new(),
            comments: Vec::new(),
        }
    }

    /// A text comment on `parent`.
    pub fn text_comment(parent: FileRef, from_parent: Resharing, author: impl Into<String>, text: impl Into<String>) -> SocialPost {
        SocialPost::create_comment(parent, from_parent, author, vec![Content::Text(text.into())])
    }

    /// Add comment references (`addComments`), ignoring ones already present.
    pub fn add_comments(&mut self, refs: impl IntoIterator<Item = FileRef>) -> bool {
        let mut changed = false;
        for r in refs {
            if !self.comments.contains(&r) {
                self.comments.push(r);
                changed = true;
            }
        }
        changed
    }

    /// All the text content of this post, concatenated.
    pub fn text_body(&self) -> String {
        self.body.iter().filter_map(Content::inline_text).collect::<Vec<_>>().join("")
    }

    pub fn to_cbor(&self) -> CborObject {
        let mut m = CborObject::map()
            .put("a", CborObject::Str(self.author.clone()))
            .put("b", CborObject::List(self.body.iter().map(Content::to_cbor).collect()))
            .put("t", CborObject::Long(self.post_time))
            .put("s", CborObject::Str(self.share_to.name().to_string()));
        if let Some(p) = &self.parent {
            m = m.put("p", p.to_cbor());
        }
        if !self.previous_versions.is_empty() {
            m = m.put("v", CborObject::List(self.previous_versions.iter().map(SocialPost::to_cbor).collect()));
        }
        if !self.comments.is_empty() {
            m = m.put("d", CborObject::List(self.comments.iter().map(FileRef::to_cbor).collect()));
        }
        CborObject::List(vec![CborObject::Long(CBOR_PEERGOS_POST_INT), m.build()])
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<SocialPost> {
        let list = cbor.as_list().ok_or_else(|| Error::Cbor("SocialPost not a list".into()))?;
        if list.first().and_then(|c| c.as_long()) != Some(CBOR_PEERGOS_POST_INT) {
            return Err(Error::Cbor("bad SocialPost mime tag".into()));
        }
        let m = list.get(1).ok_or_else(|| Error::Cbor("SocialPost missing body map".into()))?;
        Ok(SocialPost {
            author: m.get("a").and_then(|c| c.as_string()).ok_or_else(|| Error::Cbor("post missing 'a'".into()))?.to_string(),
            body: m.get("b").and_then(|c| c.as_list()).unwrap_or(&[]).iter().map(Content::from_cbor).collect::<Result<Vec<_>>>()?,
            post_time: m.get("t").and_then(|c| c.as_long()).unwrap_or(0),
            share_to: Resharing::from_name(m.get("s").and_then(|c| c.as_string()).unwrap_or("Author"))?,
            parent: m.get("p").map(FileRef::from_cbor).transpose()?,
            previous_versions: m.get("v").and_then(|c| c.as_list()).unwrap_or(&[]).iter().map(SocialPost::from_cbor).collect::<Result<Vec<_>>>()?,
            comments: m.get("d").and_then(|c| c.as_list()).unwrap_or(&[]).iter().map(FileRef::from_cbor).collect::<Result<Vec<_>>>()?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.to_cbor().to_bytes()
    }
}

// ---------------------------------------------------------------------------
// SharedItem / FeedState
// ---------------------------------------------------------------------------

/// One entry in the feed: a capability plus who owns/shared it and its path
/// (`SharedItem`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedItem {
    pub cap: AbsoluteCapability,
    pub owner: String,
    pub sharer: String,
    pub path: String,
}

impl SharedItem {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("c", self.cap.to_cbor())
            .put("o", CborObject::Str(self.owner.clone()))
            .put("s", CborObject::Str(self.sharer.clone()))
            .put("p", CborObject::Str(self.path.clone()))
            .build()
    }
    fn from_cbor(cbor: &CborObject) -> Result<SharedItem> {
        Ok(SharedItem {
            cap: AbsoluteCapability::from_cbor(cbor.get("c").ok_or_else(|| Error::Cbor("SharedItem missing 'c'".into()))?)?,
            owner: cbor.get("o").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            sharer: cbor.get("s").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            path: cbor.get("p").and_then(|c| c.as_string()).unwrap_or("").to_string(),
        })
    }
}

/// The persisted feed cursor (`SocialFeed.FeedState`).
#[derive(Debug, Clone, Default)]
struct FeedState {
    last_seen_index: u64,
    feed_size_records: u64,
    feed_size_bytes: u64,
    processed: BTreeMap<String, ProcessedCaps>,
}

impl FeedState {
    fn to_cbor(&self) -> CborObject {
        let mut p = CborObject::map();
        for (friend, pc) in &self.processed {
            p = p.put(friend, pc.to_cbor());
        }
        CborObject::map()
            .put("s", CborObject::Long(self.last_seen_index as i64))
            .put("r", CborObject::Long(self.feed_size_records as i64))
            .put("b", CborObject::Long(self.feed_size_bytes as i64))
            .put("p", p.build())
            .build()
    }
    fn from_cbor(cbor: &CborObject) -> Result<FeedState> {
        let get = |k: &str| cbor.get(k).and_then(|c| c.as_long()).unwrap_or(0).max(0) as u64;
        let mut processed = BTreeMap::new();
        if let Some(m) = cbor.get("p").and_then(|c| c.as_map()) {
            for (k, v) in m {
                processed.insert(k.as_str().to_string(), ProcessedCaps::from_cbor(v)?);
            }
        }
        Ok(FeedState {
            last_seen_index: get("s"),
            feed_size_records: get("r"),
            feed_size_bytes: get("b"),
            processed,
        })
    }
}

// ---------------------------------------------------------------------------
// SocialFeed
// ---------------------------------------------------------------------------

/// Your social feed (`SocialFeed`).
pub struct SocialFeed {
    ctx: UserContext,
    state: FeedState,
}

impl SocialFeed {
    /// Open the feed, creating `/username/.feed/` and pulling any new caps on first
    /// use (`SocialFeed.create` / `load`).
    pub async fn create(ctx: &UserContext) -> Result<SocialFeed> {
        let home = ctx.get_home().await?;
        let feed_dir = match home.child(FEED_DIR).await? {
            Some(d) => d,
            None => home.mkdir(FEED_DIR).await?,
        };
        let state = match feed_dir.child(FEED_STATE).await? {
            Some(f) => FeedState::from_cbor(&CborObject::from_bytes(&f.read().await?)?)?,
            None => {
                let empty = FeedState::default();
                feed_dir.upload(FEED_STATE, &empty.to_cbor().to_bytes()).await?;
                empty
            }
        };
        let mut feed = SocialFeed { ctx: ctx.clone(), state };
        feed.update().await?;
        Ok(feed)
    }

    /// Records currently in the feed.
    pub fn feed_size(&self) -> u64 {
        self.state.feed_size_records
    }

    /// Whether there are records past the last-seen index.
    pub fn has_unseen(&self) -> bool {
        self.state.last_seen_index < self.state.feed_size_records
    }

    pub fn last_seen_index(&self) -> u64 {
        self.state.last_seen_index
    }

    /// Mark the feed as seen up to `index` (`setLastSeenIndex`).
    pub async fn set_last_seen_index(&mut self, index: u64) -> Result<()> {
        self.state.last_seen_index = index;
        self.write_state().await
    }

    async fn feed_dir(&self) -> Result<FileWrapper> {
        let home = self.ctx.get_home().await?;
        match home.child(FEED_DIR).await? {
            Some(d) => Ok(d),
            None => home.mkdir(FEED_DIR).await,
        }
    }

    async fn write_state(&self) -> Result<()> {
        self.feed_dir().await?.upload(FEED_STATE, &self.state.to_cbor().to_bytes()).await?;
        Ok(())
    }

    /// The byte offset of every feed record (`feed-index.cbor`).
    async fn read_index(&self, dir: &FileWrapper) -> Result<Vec<u64>> {
        match dir.child(FEED_INDEX).await? {
            Some(f) => {
                let cbor = CborObject::from_bytes(&f.read().await?)?;
                Ok(cbor
                    .as_list()
                    .map(|l| l.iter().filter_map(|c| c.as_long()).map(|v| v.max(0) as u64).collect())
                    .unwrap_or_default())
            }
            None => Ok(Vec::new()),
        }
    }

    /// The byte offset of a prior record boundary at or before `index`
    /// (`getPriorByteOffset`): the exact offset of record `index` from the index
    /// file, else 0 (parse from the start).
    async fn prior_byte_offset(&self, dir: &FileWrapper, index: u64) -> Result<(u64, u64)> {
        let idx = self.read_index(dir).await?;
        match idx.get(index as usize) {
            Some(&off) => Ok((off, index)),
            None => Ok((0, 0)),
        }
    }

    /// Read feed records `[from, to)` (`getShared`), seeking via `feed-index.cbor`.
    pub async fn get_shared(&self, from: u64, to: u64) -> Result<Vec<SharedItem>> {
        let dir = self.feed_dir().await?;
        let bytes = match dir.child(FEED_FILE).await? {
            Some(f) => f.read().await?,
            None => return Ok(Vec::new()),
        };
        let (start_byte, start_index) = self.prior_byte_offset(&dir, from).await?;
        let want = self.state.feed_size_records.min(to).saturating_sub(from);
        let mut out = Vec::new();
        let mut offset = (start_byte as usize).min(bytes.len());
        let mut record = start_index;
        while offset < bytes.len() && out.len() < want as usize {
            let (cbor, consumed) = CborObject::from_bytes_consumed(&bytes[offset..])?;
            if consumed == 0 {
                break;
            }
            if record >= from {
                out.push(SharedItem::from_cbor(&cbor)?);
            }
            offset += consumed;
            record += 1;
        }
        Ok(out)
    }

    /// Append items to `feed.cbor`, updating `feed-index.cbor` and committing the
    /// state. First merges any comments on our own posts into their parents.
    async fn add_to_feed(&mut self, items: &[SharedItem]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        self.merge_in_comments(items).await?;

        let dir = self.feed_dir().await?;
        let mut data = match dir.child(FEED_FILE).await? {
            Some(f) => f.read().await?,
            None => Vec::new(),
        };
        let mut index = self.read_index(&dir).await?;
        for item in items {
            index.push(data.len() as u64); // byte offset of this record
            data.extend_from_slice(&item.to_cbor().to_bytes());
        }
        dir.upload(FEED_FILE, &data).await?;
        dir.upload(FEED_INDEX, &CborObject::List(index.iter().map(|o| CborObject::Long(*o as i64)).collect()).to_bytes())
            .await?;
        self.state.feed_size_records += items.len() as u64;
        self.state.feed_size_bytes = data.len() as u64;
        self.write_state().await
    }

    /// Merge comments (posts whose parent is one of *our* posts) into their parent
    /// post files in place (`mergeCommentReferences` / `mergeCommentsIntoParent`).
    async fn merge_in_comments(&self, items: &[SharedItem]) -> Result<()> {
        let username = match self.ctx.username() {
            Some(u) => u.to_string(),
            None => return Ok(()),
        };
        let mine = format!("/{username}/");
        let mut by_parent: BTreeMap<String, Vec<FileRef>> = BTreeMap::new();
        for item in items {
            let bytes = match crate::read_file(&item.cap, self.ctx.store(), self.ctx.mutable().as_ref()).await {
                Ok((_p, b)) => b,
                Err(_) => continue,
            };
            let post = match CborObject::from_bytes(&bytes).ok().as_ref().and_then(|c| SocialPost::from_cbor(c).ok()) {
                Some(p) => p,
                None => continue, // not a social post
            };
            if let Some(parent) = &post.parent {
                if parent.path.starts_with(&mine) {
                    let content_hash = sha256_multihash(&bytes);
                    by_parent
                        .entry(parent.path.clone())
                        .or_default()
                        .push(FileRef { path: item.path.clone(), cap: item.cap.clone(), content_hash });
                }
            }
        }
        for (parent_path, refs) in by_parent {
            self.add_comments_to_parent(&parent_path, refs).await?;
        }
        Ok(())
    }

    async fn add_comments_to_parent(&self, parent_path: &str, refs: Vec<FileRef>) -> Result<()> {
        let file = match self.ctx.get_by_path(parent_path).await? {
            Some(f) => f,
            None => return Ok(()),
        };
        let bytes = file.read().await?;
        let mut parent = match SocialPost::from_cbor(&CborObject::from_bytes(&bytes)?) {
            Ok(p) => p,
            Err(_) => return Ok(()), // not a social post
        };
        if !parent.add_comments(refs) {
            return Ok(()); // nothing new
        }
        let home = self.ctx.get_home().await?;
        let signer = crate::recover_signer(home.capability(), self.ctx.store(), self.ctx.mutable().as_ref()).await?;
        // Overwrite the parent post in place so its capability (and any share) stays valid.
        crate::overwrite_file(file.capability(), &parent.serialize(), &signer, self.ctx.mirror_bat_id().as_ref(), self.ctx.store(), self.ctx.mutable().as_ref())
            .await
    }

    /// Create a new post, store it at `/username/.posts/<year>/<month>/<uuid>.cbor`,
    /// and add it to your feed (`createNewPost`). Returns the post's home-relative
    /// path.
    pub async fn create_new_post(&mut self, post: &SocialPost) -> Result<String> {
        let username = self.ctx.username().ok_or_else(|| Error::Protocol("not signed in".into()))?.to_string();
        if post.author != username {
            return Err(Error::Protocol("you can only post as yourself".into()));
        }
        let (year, month) = year_month(post.post_time);
        let rel_dir = format!("{POSTS_DIR}/{year}/{month}");
        let post_dir = self.get_or_mkdirs(&rel_dir).await?;
        let filename = format!("{}.cbor", uuid());
        let file = post_dir.upload(&filename, &post.serialize()).await?;
        let path = format!("/{username}/{rel_dir}/{filename}");
        let item = SharedItem { cap: file.capability().read_only(), owner: username.clone(), sharer: username, path: path.clone() };
        self.add_to_feed(&[item]).await?;
        Ok(path)
    }

    /// Read a post from the feed item's capability.
    pub async fn read_post(&self, item: &SharedItem) -> Result<SocialPost> {
        let bytes = crate::read_file(&item.cap, self.ctx.store(), self.ctx.mutable().as_ref()).await?.1;
        SocialPost::from_cbor(&CborObject::from_bytes(&bytes)?)
    }

    /// Read the post stored at a home-relative or absolute path.
    pub async fn read_post_at(&self, path: &str) -> Result<SocialPost> {
        let file = self.ctx.get_by_path(path).await?.ok_or_else(|| Error::Protocol(format!("no post at {path}")))?;
        SocialPost::from_cbor(&CborObject::from_bytes(&file.read().await?)?)
    }

    /// A [`FileRef`] (path + cap + content hash) for the post/file at `path` — use
    /// it as the `parent` of a comment, or as a `Content::Reference` in a post body.
    pub async fn file_ref(&self, path: &str) -> Result<FileRef> {
        let file = self.ctx.get_by_path(path).await?.ok_or_else(|| Error::Protocol(format!("no file at {path}")))?;
        let bytes = file.read().await?;
        Ok(FileRef { path: path.to_string(), cap: file.capability().read_only(), content_hash: sha256_multihash(&bytes) })
    }

    /// Upload media for a post, storing it under `/username/.posts/<year>/media/`,
    /// and return a [`FileRef`] to it (`uploadMediaForPost`). Wrap it in a
    /// [`Content::Reference`] to attach it to a post body.
    pub async fn upload_media(&self, media: &[u8], post_time: i64) -> Result<FileRef> {
        let username = self.ctx.username().ok_or_else(|| Error::Protocol("not signed in".into()))?.to_string();
        let (year, _month) = year_month(post_time);
        let rel_dir = format!("{POSTS_DIR}/{year}/media");
        let dir = self.get_or_mkdirs(&rel_dir).await?;
        let filename = uuid();
        let file = dir.upload(&filename, media).await?;
        let path = format!("/{username}/{rel_dir}/{filename}");
        Ok(FileRef { path, cap: file.capability().read_only(), content_hash: sha256_multihash(media) })
    }

    /// Get-or-make a nested directory under home, returning its wrapper.
    async fn get_or_mkdirs(&self, rel_path: &str) -> Result<FileWrapper> {
        let mut current = self.ctx.get_home().await?;
        for comp in rel_path.split('/').filter(|s| !s.is_empty()) {
            current = match current.child(comp).await? {
                Some(d) => d,
                None => current.mkdir(comp).await?,
            };
        }
        Ok(current)
    }

    /// Pull the capabilities friends have newly shared with you (direct + via the
    /// friends/followers groups) into the feed as new items (`SocialFeed.update`).
    pub async fn update(&mut self) -> Result<()> {
        let user = self.ctx.user().ok_or_else(|| Error::Protocol("not signed in".into()))?.clone();
        let store = self.ctx.store();
        let mutable = self.ctx.mutable();
        let friends = crate::get_friends(&user, store.clone(), mutable.as_ref()).await?;

        for friend in friends {
            let name = friend.owner_name.clone();
            let mut current = self.state.processed.get(&name).cloned().unwrap_or_default();
            let mut items = Vec::new();

            // Direct shares; a `/owner/shared/<.uid>` cap is a group sharing dir.
            let mut group_dirs: BTreeMap<String, AbsoluteCapability> = BTreeMap::new();
            let (r_bytes, w_bytes, direct) =
                load_new(&friend.pointer, current.read_cap_bytes, current.write_cap_bytes, &store, mutable.as_ref()).await?;
            current.read_cap_bytes = r_bytes;
            current.write_cap_bytes = w_bytes;
            for cwp in direct {
                if let Some(uid) = group_uid_from_path(&cwp.path) {
                    group_dirs.insert(uid, cwp.cap);
                } else {
                    items.push(SharedItem { owner: extract_owner(&cwp.path), sharer: name.clone(), path: cwp.path, cap: cwp.cap });
                }
            }

            // Group shares.
            for (uid, dir) in &group_dirs {
                let g = current.groups.entry(uid.clone()).or_default();
                let (gr, gw, gcaps) = load_new(dir, g.read_cap_bytes, g.write_cap_bytes, &store, mutable.as_ref()).await?;
                g.read_cap_bytes = gr;
                g.write_cap_bytes = gw;
                for cwp in gcaps {
                    items.push(SharedItem { owner: extract_owner(&cwp.path), sharer: name.clone(), path: cwp.path, cap: cwp.cap });
                }
            }

            self.state.processed.insert(name, current);
            self.add_to_feed(&items).await?;
        }
        Ok(())
    }
}

/// Load new read + write caps from one sharing dir since the given offsets.
async fn load_new(
    dir: &AbsoluteCapability,
    read_offset: u64,
    write_offset: u64,
    store: &std::sync::Arc<dyn peergos_core::storage::ContentAddressedStorage>,
    mutable: &dyn peergos_core::mutable::MutablePointers,
) -> Result<(u64, u64, Vec<crate::CapabilityWithPath>)> {
    let r = crate::load_read_access_sharing_links(dir, read_offset, store.clone(), mutable).await?;
    let w = crate::load_write_access_sharing_links(dir, write_offset, store.clone(), mutable).await?;
    let mut caps = r.capabilities;
    caps.extend(w.capabilities);
    Ok((r.bytes_read, w.bytes_read, caps))
}

fn extract_owner(path: &str) -> String {
    path.trim_start_matches('/').split('/').next().unwrap_or("").to_string()
}

/// A `/owner/shared/<.uid>` group sharing dir path → its uid.
fn group_uid_from_path(path: &str) -> Option<String> {
    let comps: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    if comps.len() == 3 && comps[1] == "shared" && comps[2].starts_with('.') {
        Some(comps[2].to_string())
    } else {
        None
    }
}

fn now_epoch_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The bare sha2-256 multihash of `data` (`[0x12, 0x20] ++ sha256`), as stored in a
/// `FileRef` merkle link (`Hasher.bareHash`).
fn sha256_multihash(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&peergos_crypto::hash::sha256(data));
    out
}

/// A random UUID-v4-shaped string for post filenames.
fn uuid() -> String {
    let b = peergos_crypto::random_bytes(16);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Civil year + month (1-12) for an epoch-second timestamp (Howard Hinnant's
/// days-from-civil, inverted).
fn year_month(epoch_secs: i64) -> (i64, u32) {
    let days = epoch_secs.div_euclid(86400);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn social_post_roundtrip() {
        let post = SocialPost::text("alice", "hello world", Resharing::Friends);
        let reparsed = SocialPost::from_cbor(&post.to_cbor()).unwrap();
        assert_eq!(reparsed, post);
        assert_eq!(reparsed.text_body(), "hello world");
        assert_eq!(reparsed.share_to, Resharing::Friends);
    }

    #[test]
    fn year_month_epoch() {
        // 2021-01-01T00:00:00Z = 1609459200
        assert_eq!(year_month(1609459200), (2021, 1));
        // 2023-07-15 ~ 1689379200
        assert_eq!(year_month(1689379200), (2023, 7));
        assert_eq!(year_month(0), (1970, 1));
    }
}
