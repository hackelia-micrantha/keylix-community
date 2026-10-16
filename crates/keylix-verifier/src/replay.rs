use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{ErrorKind, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    sync::Mutex,
};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use keylix_dpop::{Clock, DpopPortError, ReplayKey, ReplayStatus, ReplayStore};

use crate::secure_fs::SecureDir;

const PENDING_PREFIX: &str = ".pending-";
const PENDING_RANDOM_BYTES: usize = 16;
const INSTANCE_LOCK_NAME: &str = ".replay-store.lock";

/// Persistent, owner-only replay state for a single host.
///
/// Each accepted replay key is represented by one atomically created file whose
/// contents are the acceptance expiry time. The directory is opened once as a
/// capability and all replay operations remain descriptor-relative, so pathname
/// replacement cannot redirect state after admission.
pub struct FileReplayStore<C> {
    clock: C,
    directory: SecureDir,
    capacity: usize,
    _instance_lock: File,
    operation_lock: Mutex<()>,
}

impl<C> FileReplayStore<C>
where
    C: Clock,
{
    /// Opens an existing service-owned replay directory.
    ///
    /// # Errors
    ///
    /// Fails when the path is not an absolute, symlink-free, trusted-owner
    /// directory chain, when the final directory is not private and owned by
    /// the trusted verifier UID supplied by the caller, when another live store
    /// already owns this replay directory, or when capacity is zero.
    pub fn new(
        clock: C,
        directory: impl AsRef<std::path::Path>,
        trusted_uid: u32,
        capacity: usize,
    ) -> Result<Self, DpopPortError> {
        if capacity == 0 {
            return Err(DpopPortError);
        }
        let directory = SecureDir::open_service_owned(directory.as_ref(), Some(trusted_uid))
            .map_err(|_| DpopPortError)?;
        let instance_lock = Self::acquire_instance_lock(&directory)?;
        let store = Self {
            clock,
            directory,
            capacity,
            _instance_lock: instance_lock,
            operation_lock: Mutex::new(()),
        };
        store.cleanup_startup_pending()?;
        Ok(store)
    }

    fn acquire_instance_lock(directory: &SecureDir) -> Result<File, DpopPortError> {
        let name = OsStr::new(INSTANCE_LOCK_NAME);
        let file = match directory.new_file(name, 0o600) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                Self::validate_instance_lock(directory)?;
                directory.open_file(name).map_err(|_| DpopPortError)?
            }
            Err(_) => return Err(DpopPortError),
        };

        let metadata = file.metadata().map_err(|_| DpopPortError)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != directory.owner_uid()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() != 0
        {
            return Err(DpopPortError);
        }

        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| DpopPortError)?;
        Ok(file)
    }

    fn validate_instance_lock(directory: &SecureDir) -> Result<(), DpopPortError> {
        let metadata = directory
            .metadata(OsStr::new(INSTANCE_LOCK_NAME))
            .map_err(|_| DpopPortError)?;
        let stat = metadata.stat();
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != directory.owner_uid()
            || stat.st_mode & 0o077 != 0
            || stat.st_size != 0
        {
            return Err(DpopPortError);
        }
        Ok(())
    }

    fn name_for(key: &ReplayKey) -> OsString {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(64);
        for byte in key.as_bytes() {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        OsString::from(name)
    }

    fn pending_name() -> Result<OsString, DpopPortError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut random = [0_u8; PENDING_RANDOM_BYTES];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| DpopPortError)?;

        let mut name = String::with_capacity(PENDING_PREFIX.len() + PENDING_RANDOM_BYTES * 2);
        name.push_str(PENDING_PREFIX);
        for byte in random {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(OsString::from(name))
    }

    fn is_pending_name(name: &str) -> bool {
        let Some(suffix) = name.strip_prefix(PENDING_PREFIX) else {
            return false;
        };
        suffix.len() == PENDING_RANDOM_BYTES * 2
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn cleanup_pending(&self, name: &OsStr) -> Result<(), DpopPortError> {
        let metadata = self.directory.metadata(name).map_err(|_| DpopPortError)?;
        let stat = metadata.stat();
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != self.directory.owner_uid()
            || stat.st_mode & 0o077 != 0
            || stat.st_size < 0
            || stat.st_size > 32
        {
            return Err(DpopPortError);
        }
        self.directory.remove_file(name).map_err(|_| DpopPortError)
    }

    fn cleanup_startup_pending(&self) -> Result<(), DpopPortError> {
        let mut removed_any = false;
        for name in self.directory.list_names().map_err(|_| DpopPortError)? {
            let name_text = name.to_str().ok_or(DpopPortError)?;
            if Self::is_pending_name(name_text) {
                self.cleanup_pending(&name)?;
                removed_any = true;
            }
        }
        if removed_any {
            self.directory.sync_all().map_err(|_| DpopPortError)?;
        }
        Ok(())
    }

    fn read_expiry(&self, name: &OsStr) -> Result<i64, DpopPortError> {
        let entry = self.directory.metadata(name).map_err(|_| DpopPortError)?;
        let stat = entry.stat();
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != self.directory.owner_uid()
            || stat.st_mode & 0o077 != 0
            || stat.st_size <= 0
            || stat.st_size > 32
        {
            return Err(DpopPortError);
        }

        let file = self.directory.open_file(name).map_err(|_| DpopPortError)?;
        let metadata = file.metadata().map_err(|_| DpopPortError)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != self.directory.owner_uid()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() == 0
            || metadata.len() > 32
        {
            return Err(DpopPortError);
        }

        let mut value = String::new();
        file.take(33)
            .read_to_string(&mut value)
            .map_err(|_| DpopPortError)?;
        let trimmed = value.strip_suffix('\n').unwrap_or(&value);
        if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DpopPortError);
        }
        trimmed.parse::<i64>().map_err(|_| DpopPortError)
    }

    fn cleanup_and_count(&self, now: i64) -> Result<usize, DpopPortError> {
        let mut active = 0usize;
        for name in self.directory.list_names().map_err(|_| DpopPortError)? {
            let name_text = name.to_str().ok_or(DpopPortError)?;
            if Self::is_pending_name(name_text) {
                // Pending files are created by in-flight publications. They are
                // scavenged only while holding the directory's exclusive
                // instance lock during store initialization.
                continue;
            }
            if name_text == INSTANCE_LOCK_NAME {
                Self::validate_instance_lock(&self.directory)?;
                continue;
            }
            if name_text.len() != 64
                || !name_text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(DpopPortError);
            }

            let expiry = self.read_expiry(&name)?;
            if expiry < now {
                self.directory
                    .remove_file(&name)
                    .map_err(|_| DpopPortError)?;
            } else {
                active = active.checked_add(1).ok_or(DpopPortError)?;
            }
        }
        Ok(active)
    }
}

impl<C> ReplayStore for FileReplayStore<C>
where
    C: Clock,
{
    fn check_and_record(
        &self,
        key: &ReplayKey,
        expires_at_unix: i64,
    ) -> Result<ReplayStatus, DpopPortError> {
        let _operation = self.operation_lock.lock().map_err(|_| DpopPortError)?;
        let now = self.clock.unix_seconds()?;
        if expires_at_unix < now {
            return Err(DpopPortError);
        }
        let name = Self::name_for(key);

        for attempt in 0..=1 {
            let active = self.cleanup_and_count(now)?;
            match self.read_expiry(&name) {
                Ok(expiry) if expiry >= now => return Ok(ReplayStatus::Replay),
                Ok(_) => {
                    self.directory
                        .remove_file(&name)
                        .map_err(|_| DpopPortError)?;
                }
                Err(_) => match self.directory.metadata(&name) {
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    _ => return Err(DpopPortError),
                },
            }

            if active >= self.capacity {
                return Err(DpopPortError);
            }

            let pending = Self::pending_name()?;
            let mut file = match self.directory.new_file(&pending, 0o600) {
                Ok(file) => file,
                Err(error) if error.kind() == ErrorKind::AlreadyExists && attempt == 0 => continue,
                Err(_) => return Err(DpopPortError),
            };

            let initialize = (|| -> Result<(), DpopPortError> {
                writeln!(file, "{expires_at_unix}").map_err(|_| DpopPortError)?;
                file.sync_all().map_err(|_| DpopPortError)?;
                drop(file);

                self.directory
                    .hard_link(&pending, &name)
                    .map_err(|_| DpopPortError)?;
                self.directory.sync_all().map_err(|_| DpopPortError)?;
                self.directory
                    .remove_file(&pending)
                    .map_err(|_| DpopPortError)?;
                self.directory.sync_all().map_err(|_| DpopPortError)?;
                Ok(())
            })();

            if initialize.is_ok() {
                return Ok(ReplayStatus::Fresh);
            }

            let final_exists = self.directory.metadata(&name).is_ok();
            let _ = self.directory.remove_file(&pending);
            let _ = self.directory.sync_all();
            if final_exists && attempt == 0 {
                continue;
            }
            return Err(DpopPortError);
        }

        Err(DpopPortError)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        ffi::{OsStr, OsString},
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use keylix_dpop::{Clock, DpopPortError};

    use super::FileReplayStore;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy)]
    struct FixedClock(i64);

    impl Clock for FixedClock {
        fn unix_seconds(&self) -> Result<i64, DpopPortError> {
            Ok(self.0)
        }
    }

    fn temp_replay_dir(label: &str) -> Result<PathBuf, DpopPortError> {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let directory = env::current_dir().map_err(|_| DpopPortError)?.join(format!(
            ".keylix-replay-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).map_err(|_| DpopPortError)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| DpopPortError)?;
        Ok(directory)
    }

    fn replay_dir_uid(directory: &Path) -> Result<u32, DpopPortError> {
        fs::metadata(directory)
            .map(|metadata| metadata.uid())
            .map_err(|_| DpopPortError)
    }

    fn replay_dir_names(directory: &Path) -> Result<Vec<OsString>, DpopPortError> {
        let mut names = fs::read_dir(directory)
            .map_err(|_| DpopPortError)?
            .map(|entry| {
                entry
                    .map(|value| value.file_name())
                    .map_err(|_| DpopPortError)
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }

    #[test]
    fn replay_directory_rejects_a_second_live_store() -> Result<(), DpopPortError> {
        let directory = temp_replay_dir("single-writer")?;
        let clock = FixedClock(1_700_000_000);
        let trusted_uid = replay_dir_uid(&directory)?;
        let first = FileReplayStore::new(clock, &directory, trusted_uid, 8)?;
        let before = replay_dir_names(&directory)?;
        assert!(FileReplayStore::new(clock, &directory, trusted_uid, 8).is_err());
        assert_eq!(replay_dir_names(&directory)?, before);

        drop(first);
        let replacement = FileReplayStore::new(clock, &directory, trusted_uid, 8)?;
        drop(replacement);

        fs::remove_dir_all(directory).map_err(|_| DpopPortError)?;
        Ok(())
    }

    #[test]
    fn crash_left_pending_marker_is_scavenged_on_store_initialization() -> Result<(), DpopPortError>
    {
        let directory = temp_replay_dir("pending")?;
        let pending = OsStr::new(".pending-00000000000000000000000000000000");
        let pending_path = directory.join(pending);
        fs::write(&pending_path, b"").map_err(|_| DpopPortError)?;
        fs::set_permissions(&pending_path, fs::Permissions::from_mode(0o600))
            .map_err(|_| DpopPortError)?;

        let clock = FixedClock(1_700_000_000);
        let store = FileReplayStore::new(clock, &directory, replay_dir_uid(&directory)?, 8)?;
        assert!(store.directory.metadata(pending).is_err());

        drop(store);
        fs::remove_dir_all(directory).map_err(|_| DpopPortError)?;
        Ok(())
    }

    #[test]
    fn runtime_pending_marker_is_not_scavenged_by_other_replay_checks() -> Result<(), DpopPortError>
    {
        let directory = temp_replay_dir("live-pending")?;
        let clock = FixedClock(1_700_000_000);
        let store = FileReplayStore::new(clock, &directory, replay_dir_uid(&directory)?, 8)?;
        let pending = OsStr::new(".pending-11111111111111111111111111111111");
        let file = store
            .directory
            .new_file(pending, 0o600)
            .map_err(|_| DpopPortError)?;
        drop(file);

        assert_eq!(store.cleanup_and_count(clock.0)?, 0);
        assert!(store.directory.metadata(pending).is_ok());

        drop(store);
        fs::remove_dir_all(directory).map_err(|_| DpopPortError)?;
        Ok(())
    }
}
