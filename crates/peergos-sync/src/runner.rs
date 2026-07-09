use std::path::PathBuf;

use peergos_core::error::Result;

/// Configuration for a single local ↔ remote sync pair.
pub struct SyncPairConfig {
    pub local_dir: PathBuf,
    pub link: String,
    pub sync_local_deletes: bool,
    pub sync_remote_deletes: bool,
}

/// Top-level sync runner, matching `DirectorySync.syncDirs`.
pub struct SyncRunner {
    pairs: Vec<SyncPairConfig>,
    interval_secs: u64,
    one_run: bool,
}

impl SyncRunner {
    pub fn new(pairs: Vec<SyncPairConfig>, interval_secs: u64, one_run: bool) -> Self {
        SyncRunner { pairs, interval_secs, one_run }
    }

    /// Run the sync loop.
    pub async fn run(&self) -> Result<()> {
        loop {
            for pair in &self.pairs {
                log::info!(
                    "Syncing {} <-> {}",
                    pair.local_dir.display(),
                    pair.link
                );
            }
            if self.one_run {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(self.interval_secs));
        }
        Ok(())
    }
}
