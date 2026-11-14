//! Optional real-file persistence for the existing external-peer scenarios.
use super::*;
use rsipstack::dialog::persistence::{
    DialogCheckpoint, DialogPersistence, DialogPersistenceConfig,
};
use std::collections::BTreeMap;

struct Journal {
    file: File,
    revisions: BTreeMap<String, u64>,
}

struct Storage(Mutex<Journal>);

#[async_trait::async_trait]
impl DialogPersistence for Storage {
    async fn save(&self, checkpoint: DialogCheckpoint) -> rsipstack::Result<()> {
        // These tiny loopback fixtures deliberately use a synchronous file.
        // Production handlers should use async storage or a blocking executor.
        let mut journal = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let id = checkpoint.snapshot.id.to_string();
        let revision = checkpoint.snapshot.runtime.revision;
        if journal
            .revisions
            .get(&id)
            .is_some_and(|previous| *previous > revision)
        {
            return Err(rsipstack::Error::Error(
                "checkpoint revision moved backwards".into(),
            ));
        }
        writeln!(journal.file, "{checkpoint:?}")?;
        journal.file.sync_all()?;
        journal.revisions.insert(id, revision);
        Ok(())
    }
}

pub(super) fn configure(layer: &DialogLayer, dir: &Path) -> TestResult {
    if std::env::var_os("RSIPSTACK_INTEROP_CHECKPOINTS").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        layer
            .set_persistence(Some(DialogPersistenceConfig::new(Arc::new(Storage(
                Mutex::new(Journal {
                    file: File::create(dir.join("checkpoints.log")).required()?,
                    revisions: BTreeMap::new(),
                }),
            )))))
            .required()?;
    }
    Ok(())
}
