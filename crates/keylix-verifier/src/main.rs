//! Bounded Unix-socket reference host for the Keylix verifier application.

#![forbid(unsafe_code)]

#[path = "secure_fs.rs"]
mod secure_fs;

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{ErrorKind, Read as _, Write as _},
    os::unix::{
        fs::PermissionsExt as _,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant},
};

use keylix_dpop::{
    InMemoryServerNonceStore, NonceContext, NonceNamespace, RandomNonceGenerator, SystemClock,
    VerificationPolicy,
};
use keylix_verifier::{
    FailureClass, FileReplayStore, IpcFailure, MAX_VERIFIER_PAYLOAD_BYTES, NoncePolicy,
    PeerCredentialSet, VERIFIER_PROTOCOL_VERSION, VerifierApplication, VerifierRequest,
    VerifierResult,
};

use secure_fs::{SecureDir, read_trusted_file, validate_group_transport_process};

const MAX_FRAME_BYTES: usize = MAX_VERIFIER_PAYLOAD_BYTES * 2;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_REPLAY_CAPACITY: usize = 4_096;
const DEFAULT_NONCE_CAPACITY: usize = 64;

struct Config {
    socket: PathBuf,
    peer_credentials: PathBuf,
    replay_dir: PathBuf,
    nonce_context: Option<String>,
    socket_group_gid: Option<u32>,
    replay_capacity: usize,
    nonce_capacity: usize,
}

fn main() -> ExitCode {
    if run().is_err() {
        eprintln!("keylix-verifier: reference host failed closed");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> Result<(), ()> {
    match parse_args()? {
        ParsedArgs::Help => {
            print_help();
            Ok(())
        }
        ParsedArgs::Version => {
            println!("keylix-verifier {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        ParsedArgs::Serve(config) => serve(config),
    }
}

enum ParsedArgs {
    Help,
    Version,
    Serve(Config),
}

fn parse_args() -> Result<ParsedArgs, ()> {
    let mut socket = None;
    let mut peer_credentials = None;
    let mut replay_dir = None;
    let mut nonce_context = None;
    let mut socket_group_gid = None;
    let mut replay_capacity = DEFAULT_REPLAY_CAPACITY;
    let mut nonce_capacity = DEFAULT_NONCE_CAPACITY;
    let mut args = env::args().skip(1);

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(ParsedArgs::Help),
            "--version" | "-V" => return Ok(ParsedArgs::Version),
            "--socket" => socket = Some(PathBuf::from(args.next().ok_or(())?)),
            "--peer-credentials" => {
                peer_credentials = Some(PathBuf::from(args.next().ok_or(())?));
            }
            "--replay-dir" => replay_dir = Some(PathBuf::from(args.next().ok_or(())?)),
            "--require-nonce-context" => nonce_context = Some(args.next().ok_or(())?),
            "--socket-group-gid" => {
                socket_group_gid = Some(parse_positive_u32(&args.next().ok_or(())?)?);
            }
            "--replay-capacity" => {
                replay_capacity = parse_positive_usize(&args.next().ok_or(())?)?;
            }
            "--nonce-capacity" => {
                nonce_capacity = parse_positive_usize(&args.next().ok_or(())?)?;
            }
            _ => return Err(()),
        }
    }

    Ok(ParsedArgs::Serve(Config {
        socket: socket.ok_or(())?,
        peer_credentials: peer_credentials.ok_or(())?,
        replay_dir: replay_dir.ok_or(())?,
        nonce_context,
        socket_group_gid,
        replay_capacity,
        nonce_capacity,
    }))
}

fn parse_positive_usize(value: &str) -> Result<usize, ()> {
    let parsed = value.parse::<usize>().map_err(|_| ())?;
    (parsed > 0).then_some(parsed).ok_or(())
}

fn parse_positive_u32(value: &str) -> Result<u32, ()> {
    let parsed = value.parse::<u32>().map_err(|_| ())?;
    (parsed > 0).then_some(parsed).ok_or(())
}

fn print_help() {
    println!(
        "keylix-verifier\n\
         Bounded local sender-binding verifier reference host.\n\n\
         Usage:\n\
           keylix-verifier --socket PATH --peer-credentials PATH --replay-dir PATH [options]\n\n\
         Required:\n\
           --socket PATH                 absolute socket path in private runtime directory\n\
           --peer-credentials PATH       absolute credential path under trusted owners\n\
           --replay-dir PATH             absolute persistent replay directory\n\n\
         Options:\n\
           --require-nonce-context ID    require server-owned nonce for this RS context\n\
           --socket-group-gid GID        use one pre-provisioned trusted local socket group\n\
           --replay-capacity N           maximum active replay records (default 4096)\n\
           --nonce-capacity N            process-local nonce contexts (default 64)\n\
           -h, --help                    print this help\n\
           -V, --version                 print version\n\n\
         Runtime, credential, and replay paths are traversed descriptor-relative;\n\
         every directory owner must be root or the verifier uid, and untrusted\n\
         writable/symlinked path components fail closed. The reference deployment\n\
         is single-instance. Replay state is durable; nonce state is process-local."
    );
}

fn serve(config: Config) -> Result<(), ()> {
    let socket_parent_path = config.socket.parent().ok_or(())?;
    let socket_name = config.socket.file_name().ok_or(())?.to_owned();
    if let Some(trusted_gid) = config.socket_group_gid {
        validate_group_transport_process(trusted_gid).map_err(|_| ())?;
    }
    let socket_parent = SecureDir::open_socket_parent(socket_parent_path, config.socket_group_gid)
        .map_err(|_| ())?;
    let _socket_parent_lock = socket_parent
        .acquire_exclusive_lock(OsStr::new(".keylix-verifier.lock"))
        .map_err(|_| ())?;
    let trusted_uid = socket_parent.owner_uid();

    let credential_bytes =
        read_trusted_file(&config.peer_credentials, trusted_uid, 16 * 1024).map_err(|_| ())?;
    let peers = PeerCredentialSet::from_json(&credential_bytes).map_err(|_| ())?;

    let clock = SystemClock;
    let replay = FileReplayStore::new(
        SystemClock,
        &config.replay_dir,
        trusted_uid,
        config.replay_capacity,
    )
    .map_err(|_| ())?;
    let nonces = InMemoryServerNonceStore::new(RandomNonceGenerator, config.nonce_capacity)
        .map_err(|_| ())?;
    let nonce_policy = match config.nonce_context {
        Some(context) => NoncePolicy::Required(
            NonceContext::new(NonceNamespace::ResourceServer, context).map_err(|_| ())?,
        ),
        None => NoncePolicy::Optional,
    };
    let app = VerifierApplication::new(
        &clock,
        &replay,
        &nonces,
        &nonce_policy,
        VerificationPolicy::default(),
    );

    let socket_mode = if config.socket_group_gid.is_some() {
        0o660
    } else {
        0o600
    };
    prepare_socket_path(
        &socket_parent,
        &socket_name,
        &config.socket,
        config.socket_group_gid,
    )?;
    let listener = UnixListener::bind(&config.socket).map_err(|_| ())?;
    let socket_guard = SocketPathGuard::new(&socket_parent, &socket_name);
    if config.socket_group_gid.is_none() {
        // The private profile is not externally reachable through its 0700
        // parent, so harden the socket to 0600 after bind as before.
        fs::set_permissions(&config.socket, fs::Permissions::from_mode(socket_mode))
            .map_err(|_| ())?;
    }
    validate_socket_metadata(
        &socket_parent,
        &socket_name,
        socket_mode,
        config.socket_group_gid,
    )?;

    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else {
            continue;
        };
        // Client-controlled malformed input, deadline expiry, or write failure is
        // scoped to this connection and never terminates the long-lived verifier.
        let _ = handle_connection(&mut stream, &peers, &app);
    }

    drop(socket_guard);
    Ok(())
}

fn prepare_socket_path(
    parent: &SecureDir,
    name: &OsStr,
    full_path: &std::path::Path,
    trusted_gid: Option<u32>,
) -> Result<(), ()> {
    match parent.metadata(name) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(()),
        Ok(_) => {
            validate_socket_identity(parent, name, trusted_gid)?;

            match UnixStream::connect(full_path) {
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                    parent.remove_file(name).map_err(|_| ())
                }
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                Ok(_) | Err(_) => Err(()),
            }
        }
    }
}

fn validate_socket_identity(
    parent: &SecureDir,
    name: &OsStr,
    trusted_gid: Option<u32>,
) -> Result<(), ()> {
    let metadata = parent.metadata(name).map_err(|_| ())?;
    let stat = metadata.stat();
    if stat.st_uid != parent.owner_uid()
        || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || trusted_gid.is_some_and(|gid| stat.st_gid != gid)
    {
        return Err(());
    }
    Ok(())
}

fn validate_socket_metadata(
    parent: &SecureDir,
    name: &OsStr,
    socket_mode: u32,
    trusted_gid: Option<u32>,
) -> Result<(), ()> {
    validate_socket_identity(parent, name, trusted_gid)?;
    let metadata = parent.metadata(name).map_err(|_| ())?;
    let stat = metadata.stat();
    if stat.st_mode & 0o7777 != socket_mode {
        return Err(());
    }
    Ok(())
}

struct SocketPathGuard<'a> {
    parent: &'a SecureDir,
    name: &'a OsStr,
}

impl<'a> SocketPathGuard<'a> {
    fn new(parent: &'a SecureDir, name: &'a OsStr) -> Self {
        Self { parent, name }
    }
}

impl Drop for SocketPathGuard<'_> {
    fn drop(&mut self) {
        let _ = self.parent.remove_file(self.name);
    }
}

fn handle_connection<C, R, N>(
    stream: &mut UnixStream,
    peers: &PeerCredentialSet,
    app: &VerifierApplication<'_, C, R, N>,
) -> Result<(), ()>
where
    C: keylix_dpop::Clock,
    R: keylix_dpop::ReplayStore,
    N: keylix_dpop::ServerNonceStore,
{
    let frame = read_frame(stream)?;
    let authenticated = match peers.open_request(&frame) {
        Ok(value) => value,
        Err(IpcFailure::UnauthorizedPeer | IpcFailure::MalformedEnvelope) => {
            write_unsealed_rejection(stream, FailureClass::MalformedRequest)?;
            return Ok(());
        }
        Err(_) => {
            write_unsealed_rejection(stream, FailureClass::InternalFailure)?;
            return Ok(());
        }
    };

    let Ok(request) = serde_json::from_slice::<VerifierRequest>(authenticated.payload()) else {
        let payload = serde_json::to_vec(&VerifierResult::rejected(FailureClass::MalformedRequest))
            .map_err(|_| ())?;
        let sealed = peers
            .seal_response(&authenticated, &payload)
            .map_err(|_| ())?;
        write_frame(stream, &sealed)?;
        return Ok(());
    };

    let result = app.verify(&request);
    let payload = serde_json::to_vec(&result).map_err(|_| ())?;
    let sealed = peers
        .seal_response(&authenticated, &payload)
        .map_err(|_| ())?;
    write_frame(stream, &sealed)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ()> {
    read_frame_with_timeout(stream, IO_TIMEOUT)
}

fn read_frame_with_timeout(stream: &mut UnixStream, timeout: Duration) -> Result<Vec<u8>, ()> {
    let deadline = Instant::now().checked_add(timeout).ok_or(())?;
    let mut frame = Vec::new();
    let mut chunk = [0_u8; 4096];

    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
        if remaining.is_zero() {
            return Err(());
        }
        stream.set_read_timeout(Some(remaining)).map_err(|_| ())?;

        let budget = MAX_FRAME_BYTES.checked_sub(frame.len()).ok_or(())?;
        if budget == 0 {
            return Err(());
        }
        let chunk_len = chunk.len().min(budget);
        let read = stream.read(&mut chunk[..chunk_len]).map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }

        if let Some(newline) = chunk[..read].iter().position(|byte| *byte == b'\n') {
            if newline + 1 != read {
                return Err(());
            }
            frame.extend_from_slice(&chunk[..newline]);
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return (!frame.is_empty()).then_some(frame).ok_or(());
        }

        frame.extend_from_slice(&chunk[..read]);
    }
}

fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), ()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(());
    }

    let deadline = Instant::now().checked_add(IO_TIMEOUT).ok_or(())?;
    write_before_deadline(stream, frame, deadline)?;
    write_before_deadline(stream, b"\n", deadline)?;
    stream.flush().map_err(|_| ())
}

fn write_before_deadline(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), ()> {
    while !bytes.is_empty() {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
        if remaining.is_zero() {
            return Err(());
        }
        stream.set_write_timeout(Some(remaining)).map_err(|_| ())?;
        let written = stream.write(bytes).map_err(|_| ())?;
        if written == 0 {
            return Err(());
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

fn write_unsealed_rejection(stream: &mut UnixStream, failure: FailureClass) -> Result<(), ()> {
    let response = serde_json::to_vec(&VerifierResult::rejected(failure)).map_err(|_| ())?;
    write_frame(stream, &response)
}

#[allow(dead_code)]
const _: u16 = VERIFIER_PROTOCOL_VERSION;

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    #[test]
    fn frame_deadline_is_absolute_across_partial_reads() -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut writer) = UnixStream::pair()?;
        let sender = thread::spawn(move || {
            let _ = writer.write_all(b"x");
            thread::sleep(Duration::from_millis(40));
            let _ = writer.write_all(b"y\n");
        });

        assert!(read_frame_with_timeout(&mut reader, Duration::from_millis(20)).is_err());
        sender.join().map_err(|_| "writer thread panicked")?;
        Ok(())
    }
}
