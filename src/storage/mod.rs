//! Durable daemon state. Byte prefixes here are private database schema, never wire encoding.
//!
//! Writers are serialized across clones. Do not acquire another writer while holding one.
//! A failed commit has an indeterminate outcome; callers must recover from committed state.
use fjall::{
    KeyspaceCreateOptions, PersistMode, Readable, SingleWriterTxDatabase, SingleWriterTxKeyspace,
};
use std::{fmt, fs, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Namespace {
    Replicated = 0,
    Local = 1,
    Agreement = 2,
    Outbox = 3,
    ClientBackup = 4,
}

pub enum StoreError {
    Database(fjall::Error),
    Io(std::io::Error),
    KeyTooLong,
    ValueTooLong,
    CorruptAgreement,
    SequenceExhausted,
    UnsupportedPermissions,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not include database keys, values, or private paths in diagnostics.
        f.write_str(match self {
            Self::Database(_) => "database operation failed",
            Self::Io(_) => "storage filesystem operation failed",
            Self::KeyTooLong => "storage key too long",
            Self::ValueTooLong => "storage value too long",
            Self::CorruptAgreement => "invalid agreement storage record",
            Self::SequenceExhausted => "agreement sequence exhausted",
            Self::UnsupportedPermissions => {
                "private storage permissions unsupported on this platform"
            }
        })
    }
}
impl fmt::Debug for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for StoreError {}
impl From<fjall::Error> for StoreError {
    fn from(e: fjall::Error) -> Self {
        Self::Database(e)
    }
}
impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Clone)]
pub struct Store {
    db: SingleWriterTxDatabase,
    data: SingleWriterTxKeyspace,
}
/// Owned key-value rows returned in lexicographic key order.
pub type KeyValueRows = Vec<(Vec<u8>, Vec<u8>)>;
pub struct Snapshot {
    inner: fjall::Snapshot,
    data: SingleWriterTxKeyspace,
}
pub struct WriteTransaction<'a> {
    inner: fjall::SingleWriterWriteTx<'a>,
    data: &'a SingleWriterTxKeyspace,
}

impl Store {
    /// The database directory must be dedicated to this store. It is restricted to its owner.
    /// A separate open of a live database fails with the engine's exclusive file lock.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        private_directory(path)?;
        let db = SingleWriterTxDatabase::builder(path).open()?;
        let data = db.keyspace("daemon", KeyspaceCreateOptions::default)?;
        db.persist(PersistMode::SyncAll)?;
        // Persist the directory entry as well as the engine's database files.
        fs::File::open(path)?.sync_all()?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::File::open(parent)?.sync_all()?;
        } else {
            fs::File::open(".")?.sync_all()?;
        }
        Ok(Self { db, data })
    }
    pub fn snapshot(&self) -> Result<Snapshot, StoreError> {
        Ok(Snapshot {
            inner: self.db.read_tx(),
            data: self.data.clone(),
        })
    }
    pub fn transaction(&self) -> Result<WriteTransaction<'_>, StoreError> {
        Ok(WriteTransaction {
            inner: self.db.write_tx().durability(Some(PersistMode::SyncAll)),
            data: &self.data,
        })
    }
    pub fn append_agreement(&self, session: u64, bytes: &[u8]) -> Result<(), StoreError> {
        validate_value(bytes)?;
        let mut tx = self.transaction()?;
        let prefix = agreement_prefix(session);
        let next = match tx.inner.prefix(tx.data, &prefix).next_back() {
            None => 0,
            Some(item) => {
                let key = item.key()?;
                let suffix: [u8; 8] = key
                    .get(prefix.len()..)
                    .ok_or(StoreError::CorruptAgreement)?
                    .try_into()
                    .map_err(|_| StoreError::CorruptAgreement)?;
                u64::from_be_bytes(suffix)
                    .checked_add(1)
                    .ok_or(StoreError::SequenceExhausted)?
            }
        };
        let mut key = prefix;
        key.extend_from_slice(&next.to_be_bytes());
        tx.inner.insert(tx.data, key, bytes);
        tx.commit()
    }
    pub fn read_agreement(&self, session: u64) -> Result<Vec<u8>, StoreError> {
        let snap = self.snapshot()?;
        let prefix = agreement_prefix(session);
        let mut bytes = Vec::new();
        for (expected, item) in snap.inner.prefix(&snap.data, &prefix).enumerate() {
            let (key, value) = item.into_inner()?;
            if key.get(prefix.len()..) != Some((expected as u64).to_be_bytes().as_slice()) {
                return Err(StoreError::CorruptAgreement);
            }
            bytes.extend_from_slice(&value);
        }
        Ok(bytes)
    }
}
impl Snapshot {
    pub fn get(&self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .inner
            .get(&self.data, user_key(namespace, key)?)?
            .map(|v| v.to_vec()))
    }
    pub fn scan_prefix(
        &self,
        namespace: Namespace,
        prefix: &[u8],
    ) -> Result<KeyValueRows, StoreError> {
        scan(&self.inner, &self.data, namespace, prefix)
    }
}
impl WriteTransaction<'_> {
    pub fn get(&self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .inner
            .get(self.data, user_key(namespace, key)?)?
            .map(|v| v.to_vec()))
    }
    pub fn scan_prefix(
        &self,
        namespace: Namespace,
        prefix: &[u8],
    ) -> Result<KeyValueRows, StoreError> {
        scan(&self.inner, self.data, namespace, prefix)
    }
    pub fn put(
        &mut self,
        namespace: Namespace,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StoreError> {
        validate_value(value)?;
        self.inner
            .insert(self.data, user_key(namespace, key)?, value);
        Ok(())
    }
    pub fn delete(&mut self, namespace: Namespace, key: &[u8]) -> Result<(), StoreError> {
        self.inner.remove(self.data, user_key(namespace, key)?);
        Ok(())
    }
    pub fn clear_agreement(&mut self, session: u64) -> Result<(), StoreError> {
        let keys = self
            .inner
            .prefix(self.data, agreement_prefix(session))
            .map(|item| item.key())
            .collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            self.inner.remove(self.data, key);
        }
        Ok(())
    }
    pub fn commit(self) -> Result<(), StoreError> {
        Ok(self.inner.commit()?)
    }
}
fn scan(
    reader: &impl Readable,
    data: &SingleWriterTxKeyspace,
    namespace: Namespace,
    prefix: &[u8],
) -> Result<KeyValueRows, StoreError> {
    reader
        .prefix(data, user_key(namespace, prefix)?)
        .map(|item| {
            let (key, value) = item.into_inner()?;
            Ok((key[2..].to_vec(), value.to_vec()))
        })
        .collect()
}
fn user_key(namespace: Namespace, key: &[u8]) -> Result<Vec<u8>, StoreError> {
    // fjall's encoded keys use u16 lengths; leave room for our namespace and scope.
    if key.len() > u16::MAX as usize - 2 {
        return Err(StoreError::KeyTooLong);
    }
    let mut encoded = Vec::with_capacity(key.len() + 2);
    encoded.extend_from_slice(&[namespace as u8, 0]);
    encoded.extend_from_slice(key);
    Ok(encoded)
}
fn validate_value(value: &[u8]) -> Result<(), StoreError> {
    if value.len() > u32::MAX as usize {
        return Err(StoreError::ValueTooLong);
    }
    Ok(())
}
fn agreement_prefix(session: u64) -> Vec<u8> {
    let mut key = vec![Namespace::Agreement as u8, 1];
    key.extend_from_slice(&session.to_be_bytes());
    key
}
#[cfg(unix)]
fn private_directory(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let missing: Vec<_> = path
        .ancestors()
        .take_while(|p| !p.as_os_str().is_empty() && !p.exists())
        .map(Path::to_path_buf)
        .collect();
    // Do not change the process umask: other daemon threads may be creating files.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Err(std::io::Error::other("database path must be a directory").into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    // A recursively created ancestor must survive a crash too. Sync every newly
    // created directory entry, not just the immediate database parent.
    for created in missing {
        let parent = created
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::File::open(parent)?.sync_all()?;
    }
    // All engine files, including files created by background compaction, are protected
    // by this enclosing directory. Encryption and protection from the same uid are not claimed.
    Ok(())
}
#[cfg(not(unix))]
fn private_directory(_: &Path) -> Result<(), StoreError> {
    Err(StoreError::UnsupportedPermissions)
}
