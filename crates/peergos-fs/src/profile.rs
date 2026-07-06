//! User profiles, ported from Java's `Profile` / `ProfilePaths`.
//!
//! A profile is stored as one file per field under `/username/.profile/`, so each
//! field can be shared or made public individually. String fields are raw UTF-8;
//! the photos are raw image bytes.

use crate::context::UserContext;
use crate::filewrapper::FileWrapper;
use peergos_core::error::{Error, Result};

/// The `.profile` directory name.
pub const PROFILE_DIR: &str = ".profile";

// Field file names (`ProfilePaths`).
const FIRSTNAME: &str = "firstname";
const LASTNAME: &str = "lastname";
const BIO: &str = "bio";
const STATUS: &str = "status";
const PHONE: &str = "phone";
const EMAIL: &str = "email";
const WEBROOT: &str = "webroot";
const PHOTO: &str = "photo";
const HIGHRES: &str = "highres";

/// A user's profile (`Profile`). All fields are optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub bio: Option<String>,
    pub status: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub web_root: Option<String>,
    pub profile_photo: Option<Vec<u8>>,
    pub high_res_photo: Option<Vec<u8>>,
}

impl UserContext {
    /// The `.profile` directory in our home, creating it if needed.
    async fn profile_dir(&self) -> Result<FileWrapper> {
        let home = self.get_home().await?;
        match home.child(PROFILE_DIR).await? {
            Some(dir) => Ok(dir),
            None => home.mkdir(PROFILE_DIR).await,
        }
    }

    /// Write one profile field file (`ProfilePaths.serializeAndSet`).
    async fn set_profile_field(&self, field: &str, value: &[u8]) -> Result<()> {
        self.profile_dir().await?.upload(field, value).await?;
        Ok(())
    }

    /// Read our own profile field, or `None` if unset.
    async fn get_profile_field(&self, field: &str) -> Result<Option<Vec<u8>>> {
        match self.profile_dir().await?.child(field).await? {
            Some(f) => Ok(Some(f.read().await?)),
            None => Ok(None),
        }
    }

    // ---- setters (each is a separate file, individually shareable) ---------
    pub async fn set_first_name(&self, v: &str) -> Result<()> {
        self.set_profile_field(FIRSTNAME, v.as_bytes()).await
    }
    pub async fn set_last_name(&self, v: &str) -> Result<()> {
        self.set_profile_field(LASTNAME, v.as_bytes()).await
    }
    pub async fn set_bio(&self, v: &str) -> Result<()> {
        self.set_profile_field(BIO, v.as_bytes()).await
    }
    pub async fn set_status(&self, v: &str) -> Result<()> {
        self.set_profile_field(STATUS, v.as_bytes()).await
    }
    pub async fn set_phone(&self, v: &str) -> Result<()> {
        self.set_profile_field(PHONE, v.as_bytes()).await
    }
    pub async fn set_email(&self, v: &str) -> Result<()> {
        self.set_profile_field(EMAIL, v.as_bytes()).await
    }
    pub async fn set_web_root(&self, v: &str) -> Result<()> {
        self.set_profile_field(WEBROOT, v.as_bytes()).await
    }
    pub async fn set_profile_photo(&self, image: &[u8]) -> Result<()> {
        self.set_profile_field(PHOTO, image).await
    }
    pub async fn set_high_res_profile_photo(&self, image: &[u8]) -> Result<()> {
        self.set_profile_field(HIGHRES, image).await
    }

    /// Write every present field of `profile`.
    pub async fn set_profile(&self, profile: &Profile) -> Result<()> {
        if let Some(v) = &profile.first_name {
            self.set_first_name(v).await?;
        }
        if let Some(v) = &profile.last_name {
            self.set_last_name(v).await?;
        }
        if let Some(v) = &profile.bio {
            self.set_bio(v).await?;
        }
        if let Some(v) = &profile.status {
            self.set_status(v).await?;
        }
        if let Some(v) = &profile.phone {
            self.set_phone(v).await?;
        }
        if let Some(v) = &profile.email {
            self.set_email(v).await?;
        }
        if let Some(v) = &profile.web_root {
            self.set_web_root(v).await?;
        }
        if let Some(v) = &profile.profile_photo {
            self.set_profile_photo(v).await?;
        }
        if let Some(v) = &profile.high_res_photo {
            self.set_high_res_profile_photo(v).await?;
        }
        Ok(())
    }

    /// Our own profile (`getProfile` for `username == self`).
    pub async fn get_own_profile(&self) -> Result<Profile> {
        let dir = self.profile_dir().await?;
        Ok(Profile {
            first_name: read_string(&dir, FIRSTNAME).await?,
            last_name: read_string(&dir, LASTNAME).await?,
            bio: read_string(&dir, BIO).await?,
            status: read_string(&dir, STATUS).await?,
            phone: read_string(&dir, PHONE).await?,
            email: read_string(&dir, EMAIL).await?,
            web_root: read_string(&dir, WEBROOT).await?,
            profile_photo: read_bytes(&dir, PHOTO).await?,
            high_res_photo: read_bytes(&dir, HIGHRES).await?,
        })
    }

    /// Read a named profile field from our own profile (`None` if unset).
    pub async fn get_profile_string(&self, field: &str) -> Result<Option<String>> {
        match self.get_profile_field(field).await? {
            Some(b) => Ok(Some(String::from_utf8(b).map_err(|_| Error::Protocol("profile field not UTF-8".into()))?)),
            None => Ok(None),
        }
    }

    /// The profile of another user at `username`, resolving `<username>/.profile/*`
    /// through whatever is reachable (shared/public fields). Fields not shared with
    /// us are `None`. `getProfile(username, context)`.
    pub async fn get_profile(&self, username: &str) -> Result<Profile> {
        if self.username() == Some(username) {
            return self.get_own_profile().await;
        }
        let base = format!("/{username}/{PROFILE_DIR}");
        let read = |field: &str| {
            let path = format!("{base}/{field}");
            async move {
                match self.get_by_path(&path).await {
                    Ok(Some(f)) => f.read().await.ok(),
                    _ => None,
                }
            }
        };
        let s = |b: Option<Vec<u8>>| b.and_then(|b| String::from_utf8(b).ok());
        Ok(Profile {
            first_name: s(read(FIRSTNAME).await),
            last_name: s(read(LASTNAME).await),
            bio: s(read(BIO).await),
            status: s(read(STATUS).await),
            phone: s(read(PHONE).await),
            email: s(read(EMAIL).await),
            web_root: s(read(WEBROOT).await),
            profile_photo: read(PHOTO).await,
            high_res_photo: read(HIGHRES).await,
        })
    }
}

async fn read_string(dir: &FileWrapper, field: &str) -> Result<Option<String>> {
    match read_bytes(dir, field).await? {
        Some(b) => Ok(Some(String::from_utf8(b).map_err(|_| Error::Protocol("profile field not UTF-8".into()))?)),
        None => Ok(None),
    }
}

async fn read_bytes(dir: &FileWrapper, field: &str) -> Result<Option<Vec<u8>>> {
    match dir.child(field).await? {
        Some(f) => Ok(Some(f.read().await?)),
        None => Ok(None),
    }
}
