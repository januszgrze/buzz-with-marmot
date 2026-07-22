//! Native lifecycle and secret-storage boundary for the Marmot MDK sidecar.
//!
//! React can request only a sanitized readiness snapshot. Binary paths,
//! database paths, SQLCipher keys, and the Nostr account secret are derived or
//! loaded entirely inside the native process.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use buzz_marmot_ipc::{
    decode_payload, encode_frame, ActionCompletion, Command as IpcCommand, ConversationSummary,
    IngestOutcome, MessageSummary, NativeAction, NativeSubscriptionRoute, RelayPublishOutcome,
    RelayPublishReport, Request, Response, ResponseOutcome, ResponseResult, RuntimeStatus,
    SecretBytes32, SignedNostrEvent, MAX_FRAME_SIZE,
};
use buzz_ws_client_pkg::NostrWsConnection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex, OwnedMutexGuard},
    time::timeout,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{app_state::AppState, relay, secret_store::SecretStore};

const SIDECAR_NAME: &str = "buzz-marmot-sidecar";
const DATABASE_FILE_NAME: &str = "mdk.sqlite3";
const DATABASE_KEY_PREFIX: &str = "marmot.database-key.v1";
const RPC_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_RPC_TIMEOUT: Duration = Duration::from_secs(1);
const EXIT_TIMEOUT: Duration = Duration::from_secs(2);
const ACTION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACTION_PUBLISH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RATE_LIMIT_RETRIES: usize = 3;
const MAX_ACTIONS_PER_DRAIN: usize = 64;

/// Sanitized native Marmot state returned across the React boundary.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MarmotRuntimeStatus {
    /// The encrypted account-device runtime is open and has no startup work.
    Ready {
        /// Lowercase hexadecimal Nostr account public key.
        account_public_key: String,
    },
    /// The runtime is open, but startup effects must be integrated before use.
    RecoveryRequired {
        /// Lowercase hexadecimal Nostr account public key.
        account_public_key: String,
    },
}

/// Native-only result of a message enqueue. This type is never registered as
/// a Tauri command result; its opaque id remains inside the native bridge.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NativeMessageQueued {
    pub(crate) message: MessageSummary,
    pub(crate) queued_behind_transition: bool,
}

/// Native-only result of forwarding one verified relay event to MDK.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NativeIngestResult {
    pub(crate) outcome: IngestOutcome,
    pub(crate) delivered_messages: u16,
    pub(crate) rejected_messages: u16,
    pub(crate) joined_conversations: Vec<ConversationSummary>,
    pub(crate) changed_conversation_ids: Vec<String>,
    pub(crate) changed_message_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeScope {
    app_data_dir: PathBuf,
    account_public_key: String,
    relay_hash: String,
    database_path: PathBuf,
    database_key_name: String,
}

impl RuntimeScope {
    fn derive(
        app_data_dir: PathBuf,
        account_public_key: &str,
        relay_url: &str,
    ) -> Result<Self, String> {
        if !app_data_dir.is_absolute() {
            return Err("Marmot app-data path is not absolute".to_string());
        }
        if !is_lower_hex_32(account_public_key) {
            return Err("active identity is not valid for Marmot".to_string());
        }

        let normalized_relay = normalize_relay_url(relay_url)?;
        let relay_hash = hex::encode(Sha256::digest(normalized_relay.as_bytes()));
        let database_path = app_data_dir
            .join("marmot")
            .join(account_public_key)
            .join(&relay_hash)
            .join(DATABASE_FILE_NAME);
        let database_key_name = format!("{DATABASE_KEY_PREFIX}.{account_public_key}.{relay_hash}");

        Ok(Self {
            app_data_dir,
            account_public_key: account_public_key.to_string(),
            relay_hash,
            database_path,
            database_key_name,
        })
    }
}

fn normalize_relay_url(relay_url: &str) -> Result<String, String> {
    let mut parsed = url::Url::parse(relay_url.trim())
        .map_err(|_| "active relay URL is not valid for Marmot".to_string())?;
    if !matches!(parsed.scheme(), "ws" | "wss") {
        return Err("active relay URL is not valid for Marmot".to_string());
    }
    if parsed.host_str().is_none() {
        return Err("active relay URL is not valid for Marmot".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("active relay URL must not contain credentials".to_string());
    }
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

trait DatabaseKeyStore {
    fn load(&self, name: &str) -> Result<Option<String>, String>;
    fn load_or_store(&self, name: &str, candidate: &str) -> Result<String, String>;
    fn verify_stored_raw(&self, name: &str, expected: &str) -> Result<bool, String>;
}

struct OsDatabaseKeyStore(&'static SecretStore);

impl DatabaseKeyStore for OsDatabaseKeyStore {
    fn load(&self, name: &str) -> Result<Option<String>, String> {
        self.0.load(name)
    }

    fn load_or_store(&self, name: &str, candidate: &str) -> Result<String, String> {
        self.0.load_or_store(name, candidate)
    }

    fn verify_stored_raw(&self, name: &str, expected: &str) -> Result<bool, String> {
        self.0.verify_stored_raw(name, expected)
    }
}

fn load_or_create_database_key<S, F>(
    store: &S,
    key_name: &str,
    database_exists: bool,
    mut fill_random: F,
) -> Result<Zeroizing<[u8; 32]>, String>
where
    S: DatabaseKeyStore,
    F: FnMut(&mut [u8; 32]) -> Result<(), String>,
{
    if let Some(encoded) = store.load(key_name)? {
        let encoded = Zeroizing::new(encoded);
        let decoded = Zeroizing::new(
            hex::decode(encoded.trim())
                .map_err(|_| "stored Marmot database key is invalid".to_string())?,
        );
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| "stored Marmot database key is invalid".to_string())?;
        return Ok(Zeroizing::new(bytes));
    }

    if database_exists {
        return Err(
            "encrypted Marmot storage exists, but its database key is unavailable".to_string(),
        );
    }

    let mut bytes = Zeroizing::new([0_u8; 32]);
    fill_random(&mut bytes)?;
    let candidate = Zeroizing::new(hex::encode(bytes.as_ref()));
    let winner = Zeroizing::new(store.load_or_store(key_name, candidate.as_str())?);
    let decoded = Zeroizing::new(
        hex::decode(winner.trim())
            .map_err(|_| "stored Marmot database key is invalid".to_string())?,
    );
    let winner_bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| "stored Marmot database key is invalid".to_string())?;
    if !store.verify_stored_raw(key_name, winner.as_str())? {
        return Err("Marmot database key could not be verified after storage".to_string());
    }
    Ok(Zeroizing::new(winner_bytes))
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("Marmot storage path is not a trusted directory".to_string());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| "could not create private Marmot storage".to_string())?;
        }
        Err(_) => return Err("could not inspect Marmot storage".to_string()),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "could not protect Marmot storage".to_string())?;
    }
    Ok(())
}

fn prepare_storage(scope: &RuntimeScope) -> Result<Zeroizing<[u8; 32]>, String> {
    let app_data_metadata = fs::symlink_metadata(&scope.app_data_dir)
        .map_err(|_| "could not inspect app-data storage".to_string())?;
    if app_data_metadata.file_type().is_symlink() || !app_data_metadata.is_dir() {
        return Err("app-data storage is not a trusted directory".to_string());
    }

    let marmot_dir = scope.app_data_dir.join("marmot");
    let account_dir = marmot_dir.join(&scope.account_public_key);
    let relay_dir = account_dir.join(&scope.relay_hash);
    for directory in [&marmot_dir, &account_dir, &relay_dir] {
        ensure_private_directory(directory)?;
    }

    let database_exists = match fs::symlink_metadata(&scope.database_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("Marmot database path is not a trusted file".to_string());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err("could not inspect Marmot database".to_string()),
    };

    let store = OsDatabaseKeyStore(SecretStore::shared(crate::app_state::keyring_service()));
    load_or_create_database_key(&store, &scope.database_key_name, database_exists, |bytes| {
        getrandom::fill(bytes).map_err(|_| "secure random generation failed".to_string())
    })
}

fn harden_database_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "Marmot sidecar did not create its encrypted database".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("Marmot database path is not a trusted file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "could not protect the Marmot database".to_string())?;
    }
    Ok(())
}

fn sidecar_file_name() -> &'static str {
    #[cfg(windows)]
    {
        "buzz-marmot-sidecar.exe"
    }
    #[cfg(not(windows))]
    {
        SIDECAR_NAME
    }
}

fn validate_sidecar_binary(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("Marmot sidecar path is not absolute".to_string());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "Marmot sidecar binary is unavailable".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err("Marmot sidecar binary is not a trusted executable".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("Marmot sidecar binary is not executable".to_string());
        }
    }
    fs::canonicalize(path).map_err(|_| "Marmot sidecar binary is unavailable".to_string())
}

fn resolve_sidecar_path_from(
    current_exe: &Path,
    manifest_dir: &Path,
    allow_debug_fallback: bool,
) -> Result<PathBuf, String> {
    let bundled = current_exe
        .parent()
        .ok_or_else(|| "could not locate the desktop executable directory".to_string())?
        .join(sidecar_file_name());
    match validate_sidecar_binary(&bundled) {
        Ok(path) => return Ok(path),
        Err(error) if !allow_debug_fallback => return Err(error),
        Err(_) => {}
    }

    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "could not locate the debug Marmot sidecar".to_string())?;
    validate_sidecar_binary(
        &workspace_root
            .join("target")
            .join("debug")
            .join(sidecar_file_name()),
    )
}

fn resolve_sidecar_path() -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe()
        .map_err(|_| "could not locate the desktop executable".to_string())?;
    resolve_sidecar_path_from(
        &current_exe,
        Path::new(env!("CARGO_MANIFEST_DIR")),
        cfg!(debug_assertions),
    )
}

async fn execute_publish_action(
    action: &NativeAction,
    state: &AppState,
) -> Result<ActionCompletion, String> {
    let NativeAction::PublishExactEvent {
        event,
        relay_endpoints,
        ..
    } = action;
    let event = event
        .to_verified_nostr_event()
        .map_err(|_| "Marmot sidecar returned an invalid signed event".to_string())?;
    let keys = state.signing_keys()?;
    let mut endpoint_reports = Vec::with_capacity(relay_endpoints.len());

    for endpoint in relay_endpoints {
        let connection = timeout(
            ACTION_CONNECT_TIMEOUT,
            NostrWsConnection::connect_authenticated(endpoint, &keys, None),
        )
        .await;
        let mut connection = match connection {
            Ok(Ok(connection)) => connection,
            Ok(Err(_)) | Err(_) => {
                endpoint_reports.push(RelayPublishReport {
                    relay_endpoint: endpoint.clone(),
                    outcome: RelayPublishOutcome::Failed { detail: None },
                });
                continue;
            }
        };

        let mut rate_limit_retries = 0;
        let outcome = loop {
            crate::relay_admission::wait_for_rate_limit().await;
            let published =
                timeout(ACTION_PUBLISH_TIMEOUT, connection.send_event(event.clone())).await;
            match published {
                Ok(Ok(report)) if report.event_id == event.id.to_hex() && report.accepted => {
                    break RelayPublishOutcome::Accepted;
                }
                Ok(Ok(report)) if report.event_id == event.id.to_hex() => {
                    eprintln!(
                        "buzz-desktop: Marmot relay rejected kind {} publication: {}",
                        event.kind.as_u16(),
                        report.message
                    );
                    break RelayPublishOutcome::Rejected { detail: None };
                }
                Ok(Err(buzz_ws_client_pkg::WsClientError::EventRejected(message)))
                    if message.starts_with("rate-limited:")
                        && rate_limit_retries < MAX_RATE_LIMIT_RETRIES =>
                {
                    rate_limit_retries += 1;
                    crate::relay_admission::activate_rate_limit(
                        crate::relay::extract_retry_in_hint(&message),
                    );
                }
                Ok(Ok(_)) | Ok(Err(_)) | Err(_) => return Ok(ActionCompletion::Ambiguous),
            }
        };
        endpoint_reports.push(RelayPublishReport {
            relay_endpoint: endpoint.clone(),
            outcome,
        });
        let _ = timeout(Duration::from_millis(250), connection.disconnect()).await;
    }

    let completion = ActionCompletion::Definite { endpoint_reports };
    completion
        .validate()
        .map_err(|_| "Marmot relay result was invalid".to_string())?;
    Ok(completion)
}

struct SidecarProcess {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    scope: RuntimeScope,
}

impl SidecarProcess {
    async fn spawn(path: &Path, scope: RuntimeScope) -> Result<Self, String> {
        let mut command = Command::new(path);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .kill_on_drop(true);
        if let Some(parent) = path.parent() {
            command.current_dir(parent);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = command
            .spawn()
            .map_err(|_| "could not start the Marmot sidecar".to_string())?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| "Marmot sidecar input pipe is unavailable".to_string())?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| "Marmot sidecar output pipe is unavailable".to_string())?;
        Ok(Self {
            child,
            input,
            output,
            scope,
        })
    }

    async fn rpc(&mut self, request: Request) -> Result<ResponseResult, String> {
        self.rpc_with_timeout(request, RPC_TIMEOUT).await
    }

    async fn rpc_with_timeout(
        &mut self,
        request: Request,
        deadline: Duration,
    ) -> Result<ResponseResult, String> {
        timeout(deadline, self.rpc_inner(request))
            .await
            .map_err(|_| "Marmot sidecar request timed out".to_string())?
    }

    async fn rpc_inner(&mut self, request: Request) -> Result<ResponseResult, String> {
        let request_id = request.request_id;
        let frame = encode_frame(&request)
            .map_err(|_| "could not encode a Marmot sidecar request".to_string())?;
        self.input
            .write_all(frame.as_ref())
            .await
            .map_err(|_| "Marmot sidecar input pipe failed".to_string())?;
        self.input
            .flush()
            .await
            .map_err(|_| "Marmot sidecar input pipe failed".to_string())?;

        let mut header = [0_u8; 4];
        self.output
            .read_exact(&mut header)
            .await
            .map_err(|_| "Marmot sidecar output pipe failed".to_string())?;
        let payload_len = u32::from_be_bytes(header) as usize;
        header.zeroize();
        if payload_len > MAX_FRAME_SIZE {
            return Err("Marmot sidecar returned an oversized response".to_string());
        }
        let mut payload = Zeroizing::new(vec![0_u8; payload_len]);
        self.output
            .read_exact(payload.as_mut_slice())
            .await
            .map_err(|_| "Marmot sidecar output pipe failed".to_string())?;
        let response: Response = decode_payload(payload.as_slice())
            .map_err(|_| "Marmot sidecar returned an invalid response".to_string())?;
        response
            .validate()
            .map_err(|_| "Marmot sidecar returned an invalid response".to_string())?;
        if response.request_id != request_id {
            return Err("Marmot sidecar response did not match its request".to_string());
        }

        match response.outcome {
            ResponseOutcome::Success { result } => Ok(result),
            ResponseOutcome::Failure { error } => Err(format!(
                "Marmot sidecar rejected the request ({:?})",
                error.code
            )),
        }
    }

    async fn drain_actions(
        &mut self,
        state: &AppState,
        request_ids: &AtomicU64,
    ) -> Result<(), String> {
        let mut result = self
            .rpc(Request::new(
                next_request_id(request_ids)?,
                IpcCommand::NextAction,
            ))
            .await?;

        for _ in 0..MAX_ACTIONS_PER_DRAIN {
            let ResponseResult::Action { action } = result else {
                return Err("Marmot sidecar returned an unexpected action response".to_string());
            };
            let Some(action) = action else {
                return Ok(());
            };
            let completion = execute_publish_action(&action, state).await?;
            let ambiguous = matches!(completion, ActionCompletion::Ambiguous);
            let accepted = matches!(
                &completion,
                ActionCompletion::Definite { endpoint_reports }
                    if endpoint_reports.iter().any(|report| {
                        matches!(report.outcome, RelayPublishOutcome::Accepted)
                    })
            );
            result = self
                .rpc(Request::new(
                    next_request_id(request_ids)?,
                    IpcCommand::CompleteAction {
                        action_id: action.action_id().to_string(),
                        completion,
                    },
                ))
                .await?;
            if ambiguous {
                return Ok(());
            }
            if !accepted {
                return Err("no relay accepted the Marmot publication".to_string());
            }
        }

        Err("Marmot sidecar action drain exceeded its bounded step limit".to_string())
    }

    async fn kill_and_reap(&mut self) -> Result<(), String> {
        if self
            .child
            .try_wait()
            .map_err(|_| "could not inspect the Marmot sidecar".to_string())?
            .is_some()
        {
            return Ok(());
        }
        self.child
            .start_kill()
            .map_err(|_| "could not stop the Marmot sidecar".to_string())?;
        timeout(EXIT_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| "timed out reaping the Marmot sidecar".to_string())?
            .map_err(|_| "could not reap the Marmot sidecar".to_string())?;
        Ok(())
    }

    async fn shut_down(&mut self, request_id: u64) -> Result<(), String> {
        let graceful = matches!(
            self.rpc_with_timeout(
                Request::new(request_id, IpcCommand::Shutdown),
                SHUTDOWN_RPC_TIMEOUT,
            )
            .await,
            Ok(ResponseResult::ShuttingDown)
        );
        if graceful {
            if let Ok(Ok(_)) = timeout(EXIT_TIMEOUT, self.child.wait()).await {
                return Ok(());
            }
        }
        self.kill_and_reap().await
    }
}

fn next_request_id(counter: &AtomicU64) -> Result<u64, String> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| "Marmot sidecar request identifiers are exhausted".to_string())
}

/// Owns at most one MDK sidecar for the active identity/community generation.
pub(crate) struct MarmotSidecarManager {
    process: Arc<Mutex<Option<SidecarProcess>>>,
    next_request_id: AtomicU64,
}

impl Default for MarmotSidecarManager {
    fn default() -> Self {
        Self {
            process: Arc::new(Mutex::new(None)),
            next_request_id: AtomicU64::new(1),
        }
    }
}

impl MarmotSidecarManager {
    fn request_id(&self) -> Result<u64, String> {
        next_request_id(&self.next_request_id)
    }

    async fn terminate_locked(
        &self,
        process: &mut OwnedMutexGuard<Option<SidecarProcess>>,
    ) -> Result<(), String> {
        if let Some(mut child) = process.take() {
            child.shut_down(self.request_id()?).await?;
        }
        Ok(())
    }

    /// Stop the current process and hold its generation lock across a native
    /// identity/workspace mutation.
    pub(crate) async fn stop_for_transition(&self) -> Result<MarmotTransitionGuard, String> {
        let mut process = Arc::clone(&self.process).lock_owned().await;
        self.terminate_locked(&mut process).await?;
        Ok(MarmotTransitionGuard { _process: process })
    }

    /// Stop the current sidecar, using a kill-and-reap fallback if needed.
    pub(crate) async fn stop(&self) -> Result<(), String> {
        let mut process = Arc::clone(&self.process).lock_owned().await;
        self.terminate_locked(&mut process).await
    }

    pub(crate) async fn status(&self, app: &AppHandle) -> Result<MarmotRuntimeStatus, String> {
        let mut process_guard = Arc::clone(&self.process).lock_owned().await;
        let state = app.state::<AppState>();
        if state.shutdown_started.load(Ordering::Acquire) {
            return Err("Marmot runtime is unavailable during shutdown".to_string());
        }

        let keys = state.signing_keys()?;
        let account_public_key = keys.public_key().to_hex();
        let account_secret: Zeroizing<[u8; 32]> = Zeroizing::new(
            keys.secret_key()
                .as_secret_bytes()
                .try_into()
                .map_err(|_| "active identity secret is not valid for Marmot".to_string())?,
        );
        let relay_url = relay::relay_ws_url_with_override(&state);
        let app_data_dir = app
            .path()
            .app_data_dir()
            .map_err(|_| "could not resolve Marmot app-data storage".to_string())?;
        let scope = RuntimeScope::derive(app_data_dir, &account_public_key, &relay_url)?;

        if process_guard
            .as_ref()
            .is_some_and(|process| process.scope != scope)
        {
            self.terminate_locked(&mut process_guard).await?;
        }

        if process_guard.is_none() {
            let storage_scope = scope.clone();
            let database_key =
                tauri::async_runtime::spawn_blocking(move || prepare_storage(&storage_scope))
                    .await
                    .map_err(|_| "Marmot storage setup did not complete".to_string())??;
            let binary_path = resolve_sidecar_path()?;
            let mut child = SidecarProcess::spawn(&binary_path, scope.clone()).await?;

            let initialized = async {
                match child
                    .rpc(Request::new(
                        self.request_id()?,
                        IpcCommand::Handshake {
                            client_name: format!("buzz-desktop/{}", env!("CARGO_PKG_VERSION")),
                        },
                    ))
                    .await?
                {
                    ResponseResult::Handshake { capabilities, .. }
                        if [
                            "initialize",
                            "status",
                            "next_action",
                            "complete_action",
                            "experimental_preview_v1",
                            "shutdown",
                        ]
                        .iter()
                        .all(|required| capabilities.iter().any(|value| value == required)) => {}
                    _ => return Err("Marmot sidecar handshake was incompatible".to_string()),
                }

                let database_path = scope
                    .database_path
                    .to_str()
                    .ok_or_else(|| "Marmot database path is not valid UTF-8".to_string())?
                    .to_string();
                let result = child
                    .rpc(Request::new(
                        self.request_id()?,
                        IpcCommand::Initialize {
                            database_path,
                            database_key: SecretBytes32::new(*database_key),
                            account_secret_key: SecretBytes32::new(*account_secret),
                            relay_endpoint: relay_url.clone(),
                        },
                    ))
                    .await?;
                match result {
                    ResponseResult::Initialized {
                        account_public_key: returned,
                        ..
                    } if returned == account_public_key => {}
                    ResponseResult::Initialized { .. } => {
                        return Err("Marmot sidecar initialized the wrong identity".to_string())
                    }
                    _ => return Err("Marmot sidecar initialization was incompatible".to_string()),
                }
                harden_database_file(&scope.database_path)?;
                child.drain_actions(&state, &self.next_request_id).await?;
                Ok::<(), String>(())
            }
            .await;

            if let Err(error) = initialized {
                let _ = child.kill_and_reap().await;
                return Err(error);
            }
            *process_guard = Some(child);
        }

        let status_result = match process_guard.as_mut() {
            Some(process) => match process.drain_actions(&state, &self.next_request_id).await {
                Ok(()) => {
                    process
                        .rpc(Request::new(self.request_id()?, IpcCommand::Status))
                        .await
                }
                Err(error) => Err(error),
            },
            None => Err("Marmot sidecar is unavailable".to_string()),
        };

        let result = match status_result {
            Ok(result) => result,
            Err(error) => {
                if let Some(mut failed) = process_guard.take() {
                    let _ = failed.kill_and_reap().await;
                }
                return Err(error);
            }
        };
        let expected_account_public_key = process_guard
            .as_ref()
            .map(|process| process.scope.account_public_key.clone())
            .ok_or_else(|| "Marmot sidecar is unavailable".to_string())?;
        let status = match result {
            ResponseResult::Status {
                state: RuntimeStatus::Ready { account_public_key },
            } if account_public_key == expected_account_public_key => {
                Some(MarmotRuntimeStatus::Ready { account_public_key })
            }
            ResponseResult::Status {
                state: RuntimeStatus::RecoveryRequired { account_public_key },
            } if account_public_key == expected_account_public_key => {
                Some(MarmotRuntimeStatus::RecoveryRequired { account_public_key })
            }
            _ => None,
        };
        if let Some(status) = status {
            return Ok(status);
        }

        if let Some(mut invalid) = process_guard.take() {
            let _ = invalid.kill_and_reap().await;
        }
        Err("Marmot sidecar returned an unexpected runtime state".to_string())
    }

    /// Send one bounded domain command to the current native runtime and drain
    /// every exact publication action it produced before returning.
    ///
    /// The active scope is captured before lazy initialization, then checked
    /// again while holding the process mutex used by the RPC. If an identity or
    /// workspace transition installed a replacement in between, the command is
    /// rejected as stale rather than crossing into the new account/community.
    #[allow(dead_code)]
    async fn domain_request(
        &self,
        app: &AppHandle,
        command: IpcCommand,
    ) -> Result<ResponseResult, String> {
        let expected_scope = {
            let state = app.state::<AppState>();
            if state.shutdown_started.load(Ordering::Acquire) {
                return Err("Marmot runtime is unavailable during shutdown".to_string());
            }
            let account_public_key = state.signing_keys()?.public_key().to_hex();
            let relay_url = relay::relay_ws_url_with_override(&state);
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|_| "could not resolve Marmot app-data storage".to_string())?;
            RuntimeScope::derive(app_data_dir, &account_public_key, &relay_url)?
        };
        let _ = self.status(app).await?;
        let state = app.state::<AppState>();
        if state.shutdown_started.load(Ordering::Acquire) {
            return Err("Marmot runtime is unavailable during shutdown".to_string());
        }

        let mut process_guard = Arc::clone(&self.process).lock_owned().await;
        let process = process_guard
            .as_mut()
            .ok_or_else(|| "Marmot sidecar is unavailable".to_string())?;
        validate_domain_scope(&process.scope, &expected_scope)?;
        let result = process.rpc(Request::new(self.request_id()?, command)).await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if let Some(mut failed) = process_guard.take() {
                    let _ = failed.kill_and_reap().await;
                }
                return Err(error);
            }
        };

        let drain_result = match process_guard.as_mut() {
            Some(process) => process.drain_actions(&state, &self.next_request_id).await,
            None => Err("Marmot sidecar is unavailable".to_string()),
        };
        if let Err(error) = drain_result {
            if let Some(mut failed) = process_guard.take() {
                let _ = failed.kill_and_reap().await;
            }
            return Err(error);
        }
        Ok(result)
    }

    /// Queue publication of this account's current KeyPackage.
    #[allow(dead_code)]
    pub(crate) async fn publish_native_key_package(&self, app: &AppHandle) -> Result<(), String> {
        decode_key_package_queued(
            self.domain_request(app, IpcCommand::PublishKeyPackage)
                .await?,
        )
    }

    /// Create a group from exact signed KeyPackage events fetched and verified
    /// by native code. Member pubkeys alone are deliberately insufficient.
    #[allow(dead_code)]
    pub(crate) async fn create_native_conversation(
        &self,
        app: &AppHandle,
        name: String,
        description: String,
        invitee_key_packages: Vec<SignedNostrEvent>,
    ) -> Result<ConversationSummary, String> {
        decode_conversation_created(
            self.domain_request(
                app,
                IpcCommand::CreateConversation {
                    name,
                    description,
                    invitee_key_packages,
                },
            )
            .await?,
        )
    }

    /// Queue one encrypted text message by opaque sidecar conversation id.
    #[allow(dead_code)]
    pub(crate) async fn send_native_message(
        &self,
        app: &AppHandle,
        conversation_id: String,
        created_at: u64,
        content: String,
    ) -> Result<NativeMessageQueued, String> {
        let expected_conversation_id = conversation_id.clone();
        decode_message_queued(
            self.domain_request(
                app,
                IpcCommand::SendMessage {
                    conversation_id,
                    created_at,
                    content,
                },
            )
            .await?,
            &expected_conversation_id,
        )
    }

    /// Forward one exact, verified group envelope or Welcome from the native
    /// relay bridge into MDK and drain resulting publication actions.
    #[allow(dead_code)]
    pub(crate) async fn ingest_native_event(
        &self,
        app: &AppHandle,
        event: SignedNostrEvent,
    ) -> Result<NativeIngestResult, String> {
        decode_event_ingested(
            self.domain_request(app, IpcCommand::IngestEvent { event })
                .await?,
        )
    }

    /// Query bounded sanitized conversation projections from the sidecar.
    #[allow(dead_code)]
    pub(crate) async fn list_native_conversations(
        &self,
        app: &AppHandle,
        limit: u16,
    ) -> Result<Vec<ConversationSummary>, String> {
        decode_conversations(
            self.domain_request(app, IpcCommand::ListConversations { limit })
                .await?,
        )
    }

    /// Query bounded sanitized local message projections by opaque id.
    #[allow(dead_code)]
    pub(crate) async fn list_native_messages(
        &self,
        app: &AppHandle,
        conversation_id: String,
        limit: u16,
    ) -> Result<Vec<MessageSummary>, String> {
        let expected_conversation_id = conversation_id.clone();
        decode_messages(
            self.domain_request(
                app,
                IpcCommand::ListMessages {
                    conversation_id,
                    limit,
                },
            )
            .await?,
            &expected_conversation_id,
        )
    }

    /// Return the bounded native-only exact route plan for active groups.
    pub(crate) async fn native_subscription_routes(
        &self,
        app: &AppHandle,
    ) -> Result<Vec<NativeSubscriptionRoute>, String> {
        decode_subscription_plan(
            self.domain_request(app, IpcCommand::GetSubscriptionPlan)
                .await?,
        )
    }
}

fn validate_domain_scope(current: &RuntimeScope, expected: &RuntimeScope) -> Result<(), String> {
    if current != expected {
        return Err("Marmot runtime scope changed before domain request".to_string());
    }
    Ok(())
}

fn unexpected_domain_response() -> String {
    "Marmot sidecar returned an unexpected domain response".to_string()
}

fn decode_key_package_queued(result: ResponseResult) -> Result<(), String> {
    match result {
        ResponseResult::KeyPackageQueued => Ok(()),
        _ => Err(unexpected_domain_response()),
    }
}

fn decode_conversation_created(result: ResponseResult) -> Result<ConversationSummary, String> {
    match result {
        ResponseResult::ConversationCreated { conversation } => Ok(conversation),
        _ => Err(unexpected_domain_response()),
    }
}

fn decode_message_queued(
    result: ResponseResult,
    expected_conversation_id: &str,
) -> Result<NativeMessageQueued, String> {
    match result {
        ResponseResult::MessageQueued {
            message,
            queued_behind_transition,
        } if message.conversation_id == expected_conversation_id => Ok(NativeMessageQueued {
            message,
            queued_behind_transition,
        }),
        _ => Err(unexpected_domain_response()),
    }
}

fn decode_event_ingested(result: ResponseResult) -> Result<NativeIngestResult, String> {
    match result {
        ResponseResult::EventIngested {
            outcome,
            delivered_messages,
            rejected_messages,
            joined_conversations,
            changed_conversation_ids,
            changed_message_ids,
        } => Ok(NativeIngestResult {
            outcome,
            delivered_messages,
            rejected_messages,
            joined_conversations,
            changed_conversation_ids,
            changed_message_ids,
        }),
        _ => Err(unexpected_domain_response()),
    }
}

fn decode_conversations(result: ResponseResult) -> Result<Vec<ConversationSummary>, String> {
    match result {
        ResponseResult::Conversations { conversations } => Ok(conversations),
        _ => Err(unexpected_domain_response()),
    }
}

fn decode_messages(
    result: ResponseResult,
    expected_conversation_id: &str,
) -> Result<Vec<MessageSummary>, String> {
    match result {
        ResponseResult::Messages {
            conversation_id,
            messages,
        } if conversation_id == expected_conversation_id
            && messages
                .iter()
                .all(|message| message.conversation_id == expected_conversation_id) =>
        {
            Ok(messages)
        }
        _ => Err(unexpected_domain_response()),
    }
}

fn decode_subscription_plan(
    result: ResponseResult,
) -> Result<Vec<NativeSubscriptionRoute>, String> {
    match result {
        ResponseResult::SubscriptionPlan { routes } => Ok(routes),
        _ => Err(unexpected_domain_response()),
    }
}

/// Holds the sidecar generation lock while native identity/community state is
/// being changed. React cannot construct or retain this guard.
pub(crate) struct MarmotTransitionGuard {
    _process: OwnedMutexGuard<Option<SidecarProcess>>,
}

/// Lazily initialize the native Marmot runtime and return only public state.
#[tauri::command]
pub async fn get_marmot_runtime_status(
    app: AppHandle,
    manager: State<'_, MarmotSidecarManager>,
) -> Result<MarmotRuntimeStatus, String> {
    manager.status(&app).await
}

/// Stop Marmot as part of the synchronous desktop shutdown coordinator.
pub(crate) fn shutdown_marmot_sidecar(app: &AppHandle) {
    let app = app.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    tauri::async_runtime::spawn(async move {
        let result = app.state::<MarmotSidecarManager>().stop().await;
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(Duration::from_secs(6)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("buzz-desktop: failed to stop Marmot sidecar: {error}"),
        Err(_) => eprintln!("buzz-desktop: timed out stopping Marmot sidecar"),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct FakeStore {
        values: RefCell<HashMap<String, String>>,
        verify: RefCell<bool>,
        hide_load: RefCell<bool>,
    }

    impl FakeStore {
        fn verifying() -> Self {
            Self {
                values: RefCell::new(HashMap::new()),
                verify: RefCell::new(true),
                hide_load: RefCell::new(false),
            }
        }
    }

    impl DatabaseKeyStore for FakeStore {
        fn load(&self, name: &str) -> Result<Option<String>, String> {
            if *self.hide_load.borrow() {
                return Ok(None);
            }
            Ok(self.values.borrow().get(name).cloned())
        }

        fn load_or_store(&self, name: &str, candidate: &str) -> Result<String, String> {
            Ok(self
                .values
                .borrow_mut()
                .entry(name.to_string())
                .or_insert_with(|| candidate.to_string())
                .clone())
        }

        fn verify_stored_raw(&self, name: &str, expected: &str) -> Result<bool, String> {
            Ok(*self.verify.borrow()
                && self
                    .values
                    .borrow()
                    .get(name)
                    .is_some_and(|value| value == expected))
        }
    }

    fn test_scope(root: &Path) -> RuntimeScope {
        RuntimeScope::derive(
            root.to_path_buf(),
            &"ab".repeat(32),
            "wss://relay.example/path#ignored",
        )
        .expect("derive test scope")
    }

    #[test]
    fn scope_is_identity_and_normalized_relay_specific() {
        let temp = TempDir::new().expect("temp dir");
        let first = test_scope(temp.path());
        let second = RuntimeScope::derive(
            temp.path().to_path_buf(),
            &"cd".repeat(32),
            "wss://relay.example/path",
        )
        .expect("second scope");
        assert_ne!(first.database_path, second.database_path);
        assert!(first.database_path.starts_with(temp.path().join("marmot")));
        assert_eq!(first.relay_hash.len(), 64);
        assert!(!first.database_key_name.contains("wss://"));
    }

    #[test]
    fn relay_url_credentials_are_rejected() {
        assert!(normalize_relay_url("wss://user:password@relay.example").is_err());
        assert!(normalize_relay_url("wss://relay.example/path#ignored").is_ok());
    }

    #[test]
    fn existing_database_without_key_fails_closed() {
        let error = load_or_create_database_key(&FakeStore::verifying(), "key", true, |_| {
            panic!("randomness must not be requested")
        })
        .expect_err("missing key must fail");
        assert!(error.contains("key is unavailable"));
    }

    #[test]
    fn new_database_key_is_random_and_raw_read_back_is_required() {
        let store = FakeStore::verifying();
        let key = load_or_create_database_key(&store, "key", false, |bytes| {
            bytes.fill(7);
            Ok(())
        })
        .expect("create key");
        assert_eq!(key.as_ref(), &[7; 32]);

        *store.verify.borrow_mut() = false;
        let empty_store = FakeStore::default();
        let error = load_or_create_database_key(&empty_store, "other", false, |bytes| {
            bytes.fill(9);
            Ok(())
        })
        .expect_err("failed readback must fail");
        assert!(error.contains("verified"));
    }

    #[test]
    fn concurrent_first_run_uses_the_keyring_winner() {
        let store = FakeStore::verifying();
        store
            .values
            .borrow_mut()
            .insert("key".into(), hex::encode([3_u8; 32]));
        *store.hide_load.borrow_mut() = true;

        let key = load_or_create_database_key(&store, "key", false, |bytes| {
            bytes.fill(9);
            Ok(())
        })
        .expect("existing atomic winner is reused");

        assert_eq!(key.as_ref(), &[3; 32]);
        assert_eq!(
            store.values.borrow().get("key"),
            Some(&hex::encode([3_u8; 32]))
        );
    }

    #[test]
    fn malformed_stored_database_key_is_rejected() {
        let store = FakeStore::verifying();
        store
            .values
            .borrow_mut()
            .insert("key".into(), "abcd".into());
        assert!(load_or_create_database_key(&store, "key", true, |_| Ok(())).is_err());
    }

    #[test]
    fn native_domain_response_decoders_are_variant_strict() {
        let conversation_id = format!("mcv1_{}", "a".repeat(64));
        let queued = decode_message_queued(
            ResponseResult::MessageQueued {
                message: MessageSummary {
                    message_id: format!("mmsg1_{}", "c".repeat(64)),
                    conversation_id: conversation_id.clone(),
                    author_public_key: "d".repeat(64),
                    created_at: 1,
                    content: "hello".into(),
                    delivery: buzz_marmot_ipc::MessageDeliveryState::PendingPublication,
                },
                queued_behind_transition: true,
            },
            &conversation_id,
        )
        .expect("decode queued message");
        assert!(queued.queued_behind_transition);
        assert!(queued.message.conversation_id.starts_with("mcv1_"));

        let ingested = decode_event_ingested(ResponseResult::EventIngested {
            outcome: IngestOutcome::Processed,
            delivered_messages: 2,
            rejected_messages: 1,
            joined_conversations: Vec::new(),
            changed_conversation_ids: vec![conversation_id.clone()],
            changed_message_ids: vec![format!("mmsg1_{}", "c".repeat(64))],
        })
        .expect("decode ingest result");
        assert_eq!(ingested.outcome, IngestOutcome::Processed);
        assert_eq!(ingested.delivered_messages, 2);
        assert_eq!(ingested.rejected_messages, 1);

        assert!(decode_key_package_queued(ResponseResult::Conversations {
            conversations: Vec::new(),
        })
        .is_err());
        assert!(decode_conversations(ResponseResult::KeyPackageQueued).is_err());
        assert!(decode_messages(ResponseResult::KeyPackageQueued, &conversation_id).is_err());
        assert!(decode_message_queued(
            ResponseResult::MessageQueued {
                message: MessageSummary {
                    message_id: format!("mmsg1_{}", "c".repeat(64)),
                    conversation_id: format!("mcv1_{}", "b".repeat(64)),
                    author_public_key: "d".repeat(64),
                    created_at: 1,
                    content: "hello".into(),
                    delivery: buzz_marmot_ipc::MessageDeliveryState::PendingPublication,
                },
                queued_behind_transition: false,
            },
            &conversation_id,
        )
        .is_err());
    }

    #[test]
    fn hidden_native_domain_commands_keep_ipc_bounds() {
        let valid = Request::new(
            1,
            IpcCommand::SendMessage {
                conversation_id: format!("mcv1_{}", "a".repeat(64)),
                created_at: 1,
                content: "hello".into(),
            },
        );
        assert!(valid.validate().is_ok());

        let empty_message = Request::new(
            2,
            IpcCommand::SendMessage {
                conversation_id: format!("mcv1_{}", "a".repeat(64)),
                created_at: 1,
                content: String::new(),
            },
        );
        assert!(empty_message.validate().is_err());

        let unbounded_page = Request::new(3, IpcCommand::ListConversations { limit: u16::MAX });
        assert!(unbounded_page.validate().is_err());
    }

    #[test]
    fn native_domain_scope_rejects_identity_or_community_replacement() {
        let temp = TempDir::new().expect("temp dir");
        let expected = test_scope(temp.path());
        assert!(validate_domain_scope(&expected, &expected).is_ok());

        let mut replacement = expected.clone();
        replacement.account_public_key = "22".repeat(32);
        assert!(validate_domain_scope(&replacement, &expected).is_err());

        let mut other_community = expected.clone();
        other_community.relay_hash = "33".repeat(32);
        assert!(validate_domain_scope(&other_community, &expected).is_err());
    }

    #[test]
    fn private_storage_rejects_symlinked_database() {
        let temp = TempDir::new().expect("temp dir");
        let scope = test_scope(temp.path());
        let relay_dir = scope.database_path.parent().expect("relay dir");
        fs::create_dir_all(relay_dir).expect("create relay dir");
        let target = temp.path().join("other.sqlite3");
        fs::write(&target, b"not a database").expect("write target");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &scope.database_path).expect("create symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &scope.database_path).expect("create symlink");

        assert!(prepare_storage(&scope).is_err());
    }

    #[test]
    fn binary_validation_rejects_empty_and_symlinked_files() {
        let temp = TempDir::new().expect("temp dir");
        let empty = temp.path().join(sidecar_file_name());
        fs::write(&empty, []).expect("write empty stub");
        assert!(validate_sidecar_binary(&empty).is_err());

        let target = temp.path().join("target");
        fs::write(&target, b"binary").expect("write target");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &empty).expect_err("existing path cannot be replaced");
        fs::remove_file(&empty).expect("remove empty stub");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &empty).expect("create symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &empty).expect("create symlink");
        assert!(validate_sidecar_binary(&empty).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn debug_resolution_uses_executable_workspace_fallback_only_when_allowed() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("temp dir");
        let manifest = temp.path().join("desktop/src-tauri");
        let current_exe = temp.path().join("installed/Buzz");
        fs::create_dir_all(current_exe.parent().expect("exe parent")).expect("exe parent");
        fs::create_dir_all(temp.path().join("target/debug")).expect("debug target");
        let fallback = temp.path().join("target/debug").join(sidecar_file_name());
        fs::write(&fallback, b"fake executable").expect("write fallback");
        fs::set_permissions(&fallback, fs::Permissions::from_mode(0o700)).expect("make executable");

        assert!(resolve_sidecar_path_from(&current_exe, &manifest, false).is_err());
        assert_eq!(
            resolve_sidecar_path_from(&current_exe, &manifest, true).expect("debug fallback"),
            fs::canonicalize(fallback).expect("canonical fallback")
        );
    }
}
