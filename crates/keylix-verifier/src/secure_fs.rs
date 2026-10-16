//! Descriptor-anchored filesystem capabilities for the verifier host.

use std::{
    ffi::{OsStr, OsString},
    fs::{File, Metadata},
    io::{self, ErrorKind, Read as _},
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Component, Path},
};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use openat::{Dir, Metadata as DirMetadata};
#[cfg(target_os = "linux")]
use xattr::FileExt as _;

const OWNER_PROBE_BYTES: usize = 16;

pub(crate) struct SecureDir {
    dir: Dir,
    owner_uid: u32,
}

impl SecureDir {
    #[allow(dead_code)]
    pub(crate) fn open_service_owned(path: &Path, expected_uid: Option<u32>) -> io::Result<Self> {
        let (dirs, final_dir) = open_absolute_directory(path)?;
        let owner_uid = match expected_uid {
            Some(uid) => uid,
            None => probe_directory_owner_uid(&final_dir)?,
        };

        validate_directory_chain(&dirs, owner_uid)?;
        validate_service_leaf(&final_dir, owner_uid)?;

        Ok(Self {
            dir: final_dir,
            owner_uid,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn open_socket_parent(path: &Path, trusted_gid: Option<u32>) -> io::Result<Self> {
        let (dirs, final_dir) = open_absolute_directory(path)?;
        let owner_uid = probe_directory_owner_uid(&final_dir)?;
        validate_directory_chain(&dirs, owner_uid)?;

        match trusted_gid {
            Some(gid) => {
                validate_socket_leaf(&final_dir, owner_uid, gid)?;
                reject_posix_acl(&final_dir)?;
            }
            None => validate_service_leaf(&final_dir, owner_uid)?,
        }

        Ok(Self {
            dir: final_dir,
            owner_uid,
        })
    }

    pub(crate) const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[allow(dead_code)]
    pub(crate) fn list_names(&self) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        for entry in self.dir.list_dir(".")? {
            let entry = entry?;
            let name = entry.file_name().to_owned();
            validate_single_component(&name)?;
            names.push(name);
        }
        Ok(names)
    }

    pub(crate) fn metadata(&self, name: &OsStr) -> io::Result<DirMetadata> {
        validate_single_component(name)?;
        self.dir.metadata(name)
    }

    #[allow(dead_code)]
    pub(crate) fn open_file(&self, name: &OsStr) -> io::Result<File> {
        validate_single_component(name)?;
        self.dir.open_file(name)
    }

    #[allow(dead_code)]
    pub(crate) fn new_file(&self, name: &OsStr, mode: libc::mode_t) -> io::Result<File> {
        validate_single_component(name)?;
        self.dir.new_file(name, mode)
    }

    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        validate_single_component(name)?;
        self.dir.remove_file(name)
    }

    #[allow(dead_code)]
    pub(crate) fn acquire_exclusive_lock(&self, name: &OsStr) -> io::Result<File> {
        validate_single_component(name)?;
        let file = match self.dir.new_file(name, 0o600) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => self.dir.open_file(name)?,
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != self.owner_uid
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() != 0
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "instance lock metadata violates the service directory contract",
            ));
        }
        fs2::FileExt::try_lock_exclusive(&file)?;
        Ok(file)
    }

    #[allow(dead_code)]
    pub(crate) fn hard_link(&self, existing: &OsStr, new: &OsStr) -> io::Result<()> {
        validate_single_component(existing)?;
        validate_single_component(new)?;
        openat::hardlink(&self.dir, existing, &self.dir, new)
    }

    #[allow(dead_code)]
    pub(crate) fn sync_all(&self) -> io::Result<()> {
        let directory = self.dir.open_file(OsStr::new("."))?;
        directory.sync_all()
    }
}

#[allow(dead_code)]
pub(crate) fn read_trusted_file(
    path: &Path,
    trusted_uid: u32,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let parent = path.parent().ok_or_else(invalid_path)?;
    let name = path.file_name().ok_or_else(invalid_path)?;
    validate_single_component(name)?;

    let (dirs, final_dir) = open_absolute_directory(parent)?;
    validate_directory_chain(&dirs, trusted_uid)?;

    let file = final_dir.open_file(name)?;
    let metadata = file.metadata()?;
    validate_trusted_file_metadata(&metadata, trusted_uid, max_bytes)?;

    let mut bytes = Vec::new();
    file.take((max_bytes + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "trusted file size is outside the configured bound",
        ));
    }
    Ok(bytes)
}

fn open_absolute_directory(path: &Path) -> io::Result<(Vec<Dir>, Dir)> {
    let components = normalized_absolute_components(path)?;
    let root = Dir::open("/")?;
    let mut ancestors = vec![root.try_clone()?];
    let mut current = root;

    for component in components {
        let next = current.sub_dir(component.as_os_str())?;
        ancestors.push(next.try_clone()?);
        current = next;
    }

    Ok((ancestors, current))
}

fn normalized_absolute_components(path: &Path) -> io::Result<Vec<OsString>> {
    if !path.is_absolute() {
        return Err(invalid_path());
    }

    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => components.push(value.to_owned()),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid_path());
            }
        }
    }
    Ok(components)
}

fn validate_directory_chain(dirs: &[Dir], trusted_uid: u32) -> io::Result<()> {
    for dir in dirs {
        let metadata = dir.self_metadata()?;
        let stat = metadata.stat();
        if stat.st_uid != 0 && stat.st_uid != trusted_uid {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "directory owner is outside the trusted owner set",
            ));
        }
        if stat.st_mode & 0o022 != 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "directory is writable by group or other",
            ));
        }
    }
    Ok(())
}

fn validate_service_leaf(dir: &Dir, owner_uid: u32) -> io::Result<()> {
    let metadata = dir.self_metadata()?;
    let stat = metadata.stat();
    if stat.st_uid != owner_uid || stat.st_mode & 0o077 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "service directory must be private and owned by the verifier uid",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_socket_leaf(dir: &Dir, owner_uid: u32, trusted_gid: u32) -> io::Result<()> {
    let metadata = dir.self_metadata()?;
    let stat = metadata.stat();
    validate_socket_leaf_metadata(
        owner_uid,
        trusted_gid,
        stat.st_uid,
        stat.st_gid,
        stat.st_mode,
    )
}

fn validate_socket_leaf_metadata(
    owner_uid: u32,
    trusted_gid: u32,
    file_owner_uid: u32,
    transport_group_gid: u32,
    mode: libc::mode_t,
) -> io::Result<()> {
    let ordinary = mode & 0o777;
    let special = mode & 0o7000;
    if file_owner_uid != owner_uid
        || transport_group_gid != trusted_gid
        || ordinary != 0o710
        || special != 0o2000
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "socket directory must be pre-provisioned setgid and traversal-only for the configured transport gid",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn validate_group_transport_process(trusted_gid: u32) -> io::Result<()> {
    const MAX_STATUS_BYTES: usize = 64 * 1024;
    let status = std::fs::read("/proc/self/status")?;
    if status.len() > MAX_STATUS_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "process status exceeds transport-group validation bound",
        ));
    }
    let status = std::str::from_utf8(&status)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "process status is not valid UTF-8"))?;
    if !process_status_contains_gid(status, trusted_gid)? {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "verifier process is not a member of the configured transport gid",
        ));
    }
    if process_status_umask(status)? != 0o117 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "group socket transport requires process umask 0117",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn process_status_contains_gid(status: &str, trusted_gid: u32) -> io::Result<bool> {
    let mut filesystem_gid = None;
    let mut supplementary = None;

    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Gid:") {
            let gids = value
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid process gid data"))?;
            if gids.len() != 4 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "process gid data has unexpected shape",
                ));
            }
            filesystem_gid = Some(gids[3]);
        } else if let Some(value) = line.strip_prefix("Groups:") {
            let groups = value
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    io::Error::new(ErrorKind::InvalidData, "invalid supplementary group data")
                })?;
            supplementary = Some(groups);
        }
    }

    let filesystem_gid = filesystem_gid.ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "process status is missing filesystem gid",
        )
    })?;
    let supplementary = supplementary.ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "process status is missing supplementary groups",
        )
    })?;

    Ok(filesystem_gid == trusted_gid || supplementary.contains(&trusted_gid))
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn process_status_umask(status: &str) -> io::Result<u32> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "process status is missing umask"))?
        .trim();
    u32::from_str_radix(value, 8)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid process umask data"))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn validate_group_transport_process(_trusted_gid: u32) -> io::Result<()> {
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "socket group transport profile requires Linux group introspection",
    ))
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn reject_posix_acl(dir: &Dir) -> io::Result<()> {
    let directory = dir.open_file(OsStr::new("."))?;
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        if directory.get_xattr(name)?.is_some() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "socket directory must not carry POSIX ACLs",
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn reject_posix_acl(_dir: &Dir) -> io::Result<()> {
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "socket group transport profile requires Linux ACL inspection",
    ))
}

fn probe_directory_owner_uid(dir: &Dir) -> io::Result<u32> {
    let name = random_probe_name()?;
    let file = dir.new_file(name.as_os_str(), 0o600)?;
    let owner_uid = file.metadata()?.uid();
    drop(file);
    dir.remove_file(name.as_os_str())?;
    Ok(owner_uid)
}

fn random_probe_name() -> io::Result<OsString> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut random = [0_u8; OWNER_PROBE_BYTES];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("secure randomness unavailable"))?;
    let mut name = String::from(".keylix-owner-probe-");
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(OsString::from(name))
}

fn validate_trusted_file_metadata(
    metadata: &Metadata,
    trusted_uid: u32,
    max_bytes: usize,
) -> io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_type().is_socket()
        || (metadata.uid() != 0 && metadata.uid() != trusted_uid)
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > max_bytes as u64
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "trusted file metadata violates the verifier filesystem contract",
        ));
    }
    Ok(())
}

fn validate_single_component(name: &OsStr) -> io::Result<()> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(invalid_path()),
    }
}

fn invalid_path() -> io::Error {
    io::Error::new(
        ErrorKind::InvalidInput,
        "verifier filesystem paths must be absolute and component-normalized",
    )
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn create_group_socket_parent(path: &Path) -> io::Result<bool> {
        // Test fixture models a privileged supervisor such as systemd/PID1:
        // the verifier itself never mutates SGID on the transport directory.
        // Nix derivation sandboxes may explicitly forbid setting SGID; ordinary
        // CI and publication-preview cargo tests still exercise the real path.
        fs::create_dir(path)?;
        if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o2710)) {
            if error.kind() == ErrorKind::PermissionDenied {
                fs::remove_dir(path)?;
                return Ok(false);
            }
            return Err(error);
        }
        let mode = fs::metadata(path)?.permissions().mode() & 0o7777;
        if mode != 0o2710 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("socket parent creation yielded mode {mode:o}, expected 2710"),
            ));
        }
        Ok(true)
    }

    fn temp_root(label: &str) -> io::Result<PathBuf> {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = env::current_dir()?.join(format!(
            ".keylix-secure-fs-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(root)
    }

    #[test]
    fn service_directory_rejects_symlinked_component() -> io::Result<()> {
        let root = temp_root("symlink")?;
        let target = root.join("target");
        let child = target.join("child");
        let switch = root.join("switch");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(&child)?;
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700))?;
        symlink(&target, &switch)?;

        assert!(SecureDir::open_service_owned(&switch.join("child"), None).is_err());

        fs::remove_file(&switch)?;
        fs::remove_dir(&child)?;
        fs::remove_dir(&target)?;
        fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_status_transport_gid_parser_is_exact() -> io::Result<()> {
        let status = "Name:\tkeylix\nGid:\t1000\t1001\t1002\t1003\nGroups:\t20 30 40\n";
        assert!(!process_status_contains_gid(status, 1001)?);
        assert!(process_status_contains_gid(status, 1003)?);
        assert!(process_status_contains_gid(status, 30)?);
        assert!(!process_status_contains_gid(status, 31)?);
        assert!(!process_status_contains_gid(
            "Gid:\t1\t2\t3\t4\nGroups:\n",
            2
        )?);
        assert!(process_status_contains_gid(
            "Gid:\t1\t2\t3\t4\nGroups:\n",
            4
        )?);
        assert!(!process_status_contains_gid(
            "Gid:\t1\t2\t3\t4\nGroups:\n",
            5
        )?);
        assert!(process_status_contains_gid("Groups:\t2\n", 2).is_err());
        assert_eq!(
            process_status_umask("Name:\tkeylix\nUmask:\t0117\n")?,
            0o117
        );
        assert_eq!(
            process_status_umask("Name:\tkeylix\nUmask:\t0022\n")?,
            0o022
        );
        assert!(process_status_umask("Name:\tkeylix\n").is_err());
        assert!(process_status_umask("Umask:\tnope\n").is_err());
        Ok(())
    }

    #[test]
    fn socket_parent_exclusive_lock_rejects_a_live_contender() -> io::Result<()> {
        let root = temp_root("socket-lock")?;
        let socket_parent = root.join("run");
        if !create_group_socket_parent(&socket_parent)? {
            fs::remove_dir(&root)?;
            return Ok(());
        }
        let trusted_gid = fs::metadata(&socket_parent)?.gid();

        let first = SecureDir::open_socket_parent(&socket_parent, Some(trusted_gid))?;
        let lock_name = OsStr::new(".keylix-verifier.lock");
        let first_lock = first.acquire_exclusive_lock(lock_name)?;

        let contender = SecureDir::open_socket_parent(&socket_parent, Some(trusted_gid))?;
        assert!(contender.acquire_exclusive_lock(lock_name).is_err());

        drop(first_lock);
        let replacement = contender.acquire_exclusive_lock(lock_name)?;
        drop(replacement);

        fs::remove_file(socket_parent.join(lock_name))?;
        fs::remove_dir(&socket_parent)?;
        fs::remove_dir(&root)?;
        Ok(())
    }

    #[test]
    fn socket_parent_requires_explicit_group_and_bounded_modes() -> io::Result<()> {
        let root = temp_root("socket-group")?;
        let socket_parent = root.join("run");
        if !create_group_socket_parent(&socket_parent)? {
            fs::remove_dir(&root)?;
            return Ok(());
        }
        let metadata = fs::metadata(&socket_parent)?;
        let trusted_gid = metadata.gid();

        let admitted = SecureDir::open_socket_parent(&socket_parent, Some(trusted_gid))?;
        assert_eq!(admitted.owner_uid(), metadata.uid());
        assert_eq!(metadata.gid(), trusted_gid);

        assert!(SecureDir::open_socket_parent(&socket_parent, Some(trusted_gid + 1)).is_err());

        let owner_uid = metadata.uid();
        assert!(
            validate_socket_leaf_metadata(owner_uid, trusted_gid, owner_uid, trusted_gid, 0o2710,)
                .is_ok()
        );
        for mode in [0o2700, 0o2730, 0o2711, 0o6710, 0o3710] {
            assert!(
                validate_socket_leaf_metadata(
                    owner_uid,
                    trusted_gid,
                    owner_uid,
                    trusted_gid,
                    mode,
                )
                .is_err(),
                "mode {mode:o} should fail",
            );
        }
        assert!(
            validate_socket_leaf_metadata(
                owner_uid,
                trusted_gid,
                owner_uid + 1,
                trusted_gid,
                0o2710,
            )
            .is_err()
        );
        assert!(
            validate_socket_leaf_metadata(
                owner_uid,
                trusted_gid,
                owner_uid,
                trusted_gid + 1,
                0o2710,
            )
            .is_err()
        );

        fs::remove_dir(&socket_parent)?;
        fs::remove_dir(&root)?;
        Ok(())
    }

    #[test]
    fn secure_dir_stays_anchored_after_path_replacement() -> io::Result<()> {
        let root = temp_root("anchor")?;
        let state = root.join("state");
        let old = root.join("old-state");
        fs::create_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;

        let anchored = SecureDir::open_service_owned(&state, None)?;
        fs::rename(&state, &old)?;
        fs::create_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;

        let marker = OsStr::new("marker");
        anchored.new_file(marker, 0o600)?;
        assert!(old.join(marker).is_file());
        assert!(!state.join(marker).exists());

        anchored.remove_file(marker)?;
        fs::remove_dir(&state)?;
        fs::remove_dir(&old)?;
        fs::remove_dir(&root)?;
        Ok(())
    }
}
