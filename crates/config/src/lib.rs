//! Identity persistence and the SeedNet state directory.
//!
//! On first run, SeedNet generates a fresh [`DeviceKeys`] and writes its
//! compact envelope to `<state_dir>/identity.bin`. On subsequent runs the
//! identity is loaded so that a device keeps the same [`PeerId`] and overlay
//! address forever.
//!
//! The state directory is, by default, `~/.seednet/`, but is overridable for
//! tests and for running multiple instances on one host.

use std::fs;
use std::path::{Path, PathBuf};

use seednet_common::{Error, Result};
use seednet_crypto::{DeviceKeys, DeviceKeysBytes};

/// The filename (relative to the state dir) holding the persisted identity.
pub const IDENTITY_FILENAME: &str = "identity.bin";

/// The filename holding the PID of a running `seednet up` daemon, used by
/// `seednet down` and `seednet status`.
pub const PID_FILENAME: &str = "seednet.pid";

/// The filename holding a small JSON-ish status snapshot for `seednet status`.
pub const STATUS_FILENAME: &str = "status.json";

/// Default per-user SeedNet state directory: `~/.seednet`.
pub fn default_state_dir() -> Result<PathBuf> {
    let base = dirs::home_dir().ok_or_else(|| Error::IdentityMissing(PathBuf::from("$HOME")))?;
    Ok(base.join(".seednet"))
}

/// Handle to the SeedNet state directory.
///
/// Cheap to construct; ensures the directory exists with `0700` permissions on
/// first use so that the persisted identity seed stays private.
#[derive(Clone, Debug)]
pub struct StateDir {
    path: PathBuf,
}

impl StateDir {
    /// Construct from an explicit path, creating it (mode `0700`) if missing.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            fs::create_dir_all(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mut perms = fs::metadata(&path)?.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(&path, perms)?;
            }
        }
        Ok(Self { path })
    }

    /// Resolve and create the default per-user state directory.
    pub fn default_user() -> Result<Self> {
        Self::new(default_state_dir()?)
    }

    /// The absolute path of the state directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Path to the identity file.
    pub fn identity_path(&self) -> PathBuf {
        self.path.join(IDENTITY_FILENAME)
    }

    /// Path to the PID file.
    pub fn pid_path(&self) -> PathBuf {
        self.path.join(PID_FILENAME)
    }

    /// Path to the status snapshot.
    pub fn status_path(&self) -> PathBuf {
        self.path.join(STATUS_FILENAME)
    }

    /// Load the persisted identity, generating and persisting a fresh one on
    /// first run.
    pub fn load_or_create_identity(&self) -> Result<DeviceKeys> {
        match self.load_identity()? {
            Some(keys) => Ok(keys),
            None => {
                let keys = DeviceKeys::generate();
                self.save_identity(&keys)?;
                Ok(keys)
            }
        }
    }

    /// Load an existing identity, returning `None` if absent.
    pub fn load_identity(&self) -> Result<Option<DeviceKeys>> {
        let path = self.identity_path();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let envelope = DeviceKeysBytes::from_bytes(&bytes)
            .map_err(|e| Error::IdentityCorrupt(e.to_string()))?;
        let seed = envelope.into_seed()?;
        Ok(Some(DeviceKeys::from_seed(seed)))
    }

    /// Persist an identity, atomically replacing any previous file.
    pub fn save_identity(&self, keys: &DeviceKeys) -> Result<()> {
        let envelope = DeviceKeysBytes::from_keys(keys);
        let bytes = envelope.to_bytes()?;
        atomic_write(&self.identity_path(), &bytes, 0o600)
    }

    /// Write the current PID to the PID file.
    pub fn write_pid(&self, pid: u32) -> Result<()> {
        atomic_write(&self.pid_path(), pid.to_string().as_bytes(), 0o644)
    }

    /// Read the PID from the PID file, if present.
    pub fn read_pid(&self) -> Result<Option<u32>> {
        match fs::read_to_string(self.pid_path()) {
            Ok(s) => s
                .trim()
                .parse::<u32>()
                .map(Some)
                .map_err(|e| Error::IdentityCorrupt(format!("bad pid file: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove the PID file (e.g. on shutdown).
    pub fn clear_pid(&self) -> Result<()> {
        match fs::remove_file(self.pid_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Atomically write `data` to `path` via a temp file + rename, with the given
/// unix permissions. Atomicity avoids leaving a corrupt identity on a crash
/// mid-write.
fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::IdentityCorrupt("path has no parent".into()))?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("seednet")
    ));
    fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = fs::metadata(&tmp)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(&tmp, perms)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_dir() -> StateDir {
        let dir = std::env::temp_dir().join(format!(
            "seednet-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        StateDir::new(&dir).expect("create temp state dir")
    }

    #[test]
    fn first_run_generates_then_load_is_stable() {
        let sd = temp_state_dir();
        let k1 = sd.load_or_create_identity().expect("generate");
        assert!(sd.identity_path().exists());
        let k2 = sd.load_identity().expect("load").expect("some");
        assert_eq!(k1.public_key(), k2.public_key());
    }

    #[test]
    fn load_returns_none_when_absent() {
        let sd = temp_state_dir();
        assert!(sd.load_identity().expect("ok").is_none());
    }

    #[test]
    fn save_and_reload_round_trip() {
        let sd = temp_state_dir();
        let keys = DeviceKeys::generate();
        sd.save_identity(&keys).expect("save");
        let loaded = sd.load_identity().expect("load").expect("some");
        assert_eq!(keys.public_key(), loaded.public_key());
    }

    #[test]
    fn pid_round_trip() {
        let sd = temp_state_dir();
        assert!(sd.read_pid().expect("ok").is_none());
        sd.write_pid(4242).expect("write");
        assert_eq!(sd.read_pid().expect("ok"), Some(4242));
        sd.clear_pid().expect("clear");
        assert!(sd.read_pid().expect("ok").is_none());
    }

    #[test]
    fn corrupt_identity_errors() {
        let sd = temp_state_dir();
        fs::write(sd.identity_path(), b"not valid postcard").expect("write junk");
        let res = sd.load_identity();
        assert!(matches!(res, Err(Error::IdentityCorrupt(_))));
    }
}
