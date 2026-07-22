//! Debug-only native Marmot preview bridge.
//!
//! The bridge owns relay routing, KeyPackage discovery, exact signed-event
//! ingress, and MDK sidecar IPC. React receives only opaque conversation ids
//! and bounded sanitized projections. Release builds and debug builds without
//! explicit environment opt-in fail closed.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use buzz_marmot_ipc::{
    ConversationState, ConversationSummary, MessageDeliveryState, MessageSummary, SignedNostrEvent,
    MAX_CONVERSATION_LIST_LIMIT, MAX_MESSAGE_CONTENT_BYTES, MAX_MESSAGE_LIST_LIMIT,
    MAX_SUBSCRIPTION_ROUTES,
};
use buzz_ws_client_pkg::{NostrWsConnection, RelayMessage, WsClientError};
use nostr::{Event, JsonUtil, Keys};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tokio::{
    sync::{mpsc, oneshot, Mutex, OwnedMutexGuard},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const BRIDGE_API_VERSION: u16 = 1;
const MARMOT_GROUP_MESSAGE_KIND: u16 = 445;
const MARMOT_WELCOME_KIND: u16 = 1059;
const MARMOT_KEY_PACKAGE_KIND: u16 = 30_443;
const MAX_ACTIVE_ROUTES: usize = MAX_SUBSCRIPTION_ROUTES;
const MAX_INBOUND_EVENT_BYTES: usize = 128 * 1024;
const MIN_MARMOT_PAYLOAD_BYTES: usize = 28;
const MAX_DEDUPLICATED_EVENT_IDS: usize = 4_096;
const MAX_HISTORY_EVENTS_PER_FILTER: u16 = 500;
const MAX_CONVERSATION_NAME_BYTES: usize = 80;
const MAX_CONVERSATION_DESCRIPTION_BYTES: usize = 300;
const MAX_MESSAGE_BYTES: usize = MAX_MESSAGE_CONTENT_BYTES;
const READER_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const READER_POLL_TIMEOUT: Duration = Duration::from_secs(1);
const READER_STOP_TIMEOUT: Duration = Duration::from_secs(8);
const QUERY_TIMEOUT: Duration = Duration::from_secs(20);
const PREVIEW_ENV: &str = "BUZZ_MARMOT_PREVIEW";

/// Event emitted after a sanitized conversation projection changes.
#[allow(dead_code)]
pub(crate) const MARMOT_CONVERSATION_CHANGED_EVENT: &str = "marmot-conversation-changed";
/// Event emitted after a sanitized message projection changes.
#[allow(dead_code)]
pub(crate) const MARMOT_MESSAGE_CHANGED_EVENT: &str = "marmot-message-changed";
/// Event emitted after native catch-up or publication state changes.
pub(crate) const MARMOT_SYNC_CHANGED_EVENT: &str = "marmot-sync-changed";

/// Feature contract returned for the debug-only encrypted-chat preview.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MarmotBridgeStatus {
    /// Contract version for the future sanitized command/event surface.
    api_version: u16,
    /// True only in a debug build with explicit environment opt-in and a ready
    /// native runtime/subscriber.
    enabled: bool,
    /// Stable, non-secret reason suitable for capability gating.
    reason_code: &'static str,
}

fn disabled_bridge_status(reason_code: &'static str) -> MarmotBridgeStatus {
    MarmotBridgeStatus {
        api_version: BRIDGE_API_VERSION,
        enabled: false,
        reason_code,
    }
}

fn preview_gate_enabled() -> bool {
    preview_gate_value(
        cfg!(debug_assertions),
        std::env::var(PREVIEW_ENV).ok().as_deref(),
    )
}

fn preview_gate_value(debug_build: bool, value: Option<&str>) -> bool {
    debug_build
        && value.is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

/// Bounded request to create a two-member encrypted preview conversation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarmotCreateConversationInput {
    name: String,
    #[serde(default)]
    description: String,
    invitee_pubkey: String,
}

impl MarmotCreateConversationInput {
    fn validate(&self) -> Result<(), String> {
        validate_bounded_text(&self.name, MAX_CONVERSATION_NAME_BYTES, false)?;
        validate_bounded_text(&self.description, MAX_CONVERSATION_DESCRIPTION_BYTES, true)?;
        if !is_lower_hex_32(&self.invitee_pubkey) {
            return Err("invalid encrypted-conversation member".to_string());
        }
        Ok(())
    }
}

/// Preview send-message input. The conversation identifier is a sidecar-owned
/// local projection id, never an MLS group id or Nostr `h` route.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarmotSendMessageInput {
    conversation_id: String,
    content: String,
}

impl MarmotSendMessageInput {
    fn validate(&self) -> Result<(), String> {
        validate_opaque_id(&self.conversation_id, "mcv1_")?;
        validate_bounded_text(&self.content, MAX_MESSAGE_BYTES, false)
    }
}

/// Bounded local encrypted-message page input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarmotListMessagesInput {
    conversation_id: String,
    #[serde(default)]
    limit: Option<u16>,
}

impl MarmotListMessagesInput {
    fn validate(&self) -> Result<(), String> {
        validate_opaque_id(&self.conversation_id, "mcv1_")?;
        if self.limit.unwrap_or(MAX_MESSAGE_LIST_LIMIT) == 0
            || self.limit.unwrap_or(MAX_MESSAGE_LIST_LIMIT) > MAX_MESSAGE_LIST_LIMIT
        {
            return Err("invalid encrypted-message page size".to_string());
        }
        Ok(())
    }
}

/// Bounded request for encrypted-conversation summaries.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarmotListConversationsInput {
    #[serde(default)]
    limit: Option<u16>,
}

impl MarmotListConversationsInput {
    fn validate(&self) -> Result<(), String> {
        if self.limit.unwrap_or(MAX_CONVERSATION_LIST_LIMIT) == 0
            || self.limit.unwrap_or(MAX_CONVERSATION_LIST_LIMIT) > MAX_CONVERSATION_LIST_LIMIT
        {
            return Err("invalid encrypted-conversation page size".to_string());
        }
        Ok(())
    }
}

/// Sanitized acknowledgement returned after native MDK accepts a send.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MarmotSendResult {
    conversation_id: String,
    queued_behind_transition: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MarmotChangedPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_id: Option<String>,
}

/// Sanitized encrypted-conversation projection returned to React.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MarmotConversationDto {
    conversation_id: String,
    name: String,
    description: String,
    epoch: u64,
    member_count: u32,
    state: ConversationState,
}

impl From<ConversationSummary> for MarmotConversationDto {
    fn from(value: ConversationSummary) -> Self {
        Self {
            conversation_id: value.conversation_id,
            name: value.name,
            description: value.description,
            epoch: value.epoch,
            member_count: value.member_count,
            state: value.state,
        }
    }
}

/// Sanitized decrypted message projection returned to React.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MarmotMessageDto {
    message_id: String,
    conversation_id: String,
    author_public_key: String,
    created_at: u64,
    content: String,
    delivery: MessageDeliveryState,
}

impl From<MessageSummary> for MarmotMessageDto {
    fn from(value: MessageSummary) -> Self {
        Self {
            message_id: value.message_id,
            conversation_id: value.conversation_id,
            author_public_key: value.author_public_key,
            created_at: value.created_at,
            content: value.content,
            delivery: value.delivery,
        }
    }
}

fn validate_bounded_text(value: &str, max_bytes: usize, empty_allowed: bool) -> Result<(), String> {
    if value.len() > max_bytes || value.as_bytes().contains(&0) {
        return Err("encrypted-message input exceeds its safe bound".to_string());
    }
    if !empty_allowed && value.trim().is_empty() {
        return Err("encrypted-message input cannot be empty".to_string());
    }
    Ok(())
}

fn validate_opaque_id(value: &str, prefix: &str) -> Result<(), String> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or_else(|| "invalid encrypted-conversation identifier".to_string())?;
    if !(32..=96).contains(&suffix.len())
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("invalid encrypted-conversation identifier".to_string());
    }
    Ok(())
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One native-only relay filter. Raw routes never implement `Serialize` on a
/// React-facing result and are never emitted as Tauri event payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeRelayFilter {
    pub(crate) subscription_id: String,
    pub(crate) filter: serde_json::Value,
}

/// Native subscription work for one runtime generation.
#[derive(Debug, Clone)]
pub(crate) struct NativeRelaySubscriptionPlan {
    pub(crate) generation: u64,
    pub(crate) filters: Vec<NativeRelayFilter>,
    pub(crate) cancellation: CancellationToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeConversationRoute {
    pub(crate) conversation_id: String,
    pub(crate) route: String,
}

enum ReaderControl {
    ReplaceRoutes(Vec<NativeConversationRoute>),
}

/// Verified exact envelope accepted from a native authenticated relay stream.
///
/// This type intentionally does not implement `Serialize`: its route and raw
/// signed event may cross only the Tauri-to-sidecar IPC boundary.
#[derive(Debug)]
pub(crate) struct VerifiedMarmotEnvelope {
    pub(crate) event_id: String,
    pub(crate) route: String,
    pub(crate) raw_event_json: String,
}

/// Verified Welcome gift wrap accepted for the active account inbox.
///
/// This type intentionally does not implement `Serialize`; decryption and
/// invitation authentication happen in the sidecar, not React.
#[derive(Debug)]
pub(crate) struct VerifiedMarmotWelcome {
    pub(crate) event_id: String,
    pub(crate) raw_event_json: String,
}

struct BridgeSession {
    generation: u64,
    account_public_key: String,
    relay_url: String,
    active_routes: HashMap<String, String>,
    seen_event_ids: HashSet<String>,
    seen_event_order: VecDeque<String>,
    cancellation: CancellationToken,
    control_tx: mpsc::Sender<ReaderControl>,
    key_package_published: bool,
}

impl BridgeSession {
    fn record_event_id(&mut self, event_id: &str) -> bool {
        if !self.seen_event_ids.insert(event_id.to_string()) {
            return false;
        }
        self.seen_event_order.push_back(event_id.to_string());
        while self.seen_event_order.len() > MAX_DEDUPLICATED_EVENT_IDS {
            if let Some(evicted) = self.seen_event_order.pop_front() {
                self.seen_event_ids.remove(&evicted);
            }
        }
        true
    }
}

/// Generation-scoped state for the native preview relay subscription driver.
pub(crate) struct MarmotBridgeState {
    session: Arc<Mutex<Option<BridgeSession>>>,
    reader_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    lifecycle: Mutex<()>,
    next_generation: AtomicU64,
}

impl Default for MarmotBridgeState {
    fn default() -> Self {
        Self {
            session: Arc::new(Mutex::new(None)),
            reader_task: Arc::new(Mutex::new(None)),
            lifecycle: Mutex::new(()),
            next_generation: AtomicU64::new(1),
        }
    }
}

impl MarmotBridgeState {
    fn generation(&self) -> Result<u64, String> {
        self.next_generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| "Marmot runtime generations are exhausted".to_string())
    }

    /// Install routes returned by the native sidecar and build exact filters.
    /// This is not a Tauri command and therefore cannot receive routes from
    /// React.
    async fn begin_native_session(
        &self,
        account_public_key: &str,
        relay_url: &str,
        routes: Vec<NativeConversationRoute>,
        control_tx: mpsc::Sender<ReaderControl>,
    ) -> Result<NativeRelaySubscriptionPlan, String> {
        if !is_lower_hex_32(account_public_key) || routes.len() > MAX_ACTIVE_ROUTES {
            return Err("invalid native Marmot subscription scope".to_string());
        }
        let active_routes = validate_native_routes(routes)?;
        if url::Url::parse(relay_url)
            .ok()
            .is_none_or(|url| !matches!(url.scheme(), "ws" | "wss") || url.host_str().is_none())
        {
            return Err("invalid native Marmot subscription scope".to_string());
        }

        let generation = self.generation()?;
        let cancellation = CancellationToken::new();
        let filters = build_subscription_filters(
            generation,
            account_public_key,
            &active_routes.keys().cloned().collect(),
        );
        let mut session = self.session.lock().await;
        if let Some(previous) = session.take() {
            previous.cancellation.cancel();
        }
        *session = Some(BridgeSession {
            generation,
            account_public_key: account_public_key.to_string(),
            relay_url: relay_url.to_string(),
            active_routes,
            seen_event_ids: HashSet::new(),
            seen_event_order: VecDeque::new(),
            cancellation: cancellation.clone(),
            control_tx,
            key_package_published: false,
        });

        Ok(NativeRelaySubscriptionPlan {
            generation,
            filters,
            cancellation,
        })
    }

    async fn ensure_reader(
        &self,
        app: &AppHandle,
        account_public_key: &str,
        relay_url: &str,
        keys: Keys,
        routes: Vec<NativeConversationRoute>,
    ) -> Result<(), String> {
        let _lifecycle = self.lifecycle.lock().await;
        let validated_routes = validate_native_routes(routes.clone())?;
        let can_reuse = {
            let session = self.session.lock().await;
            let task_running = self
                .reader_task
                .lock()
                .await
                .as_ref()
                .is_some_and(|task| !task.is_finished());
            session.as_ref().is_some_and(|active| {
                active.account_public_key == account_public_key
                    && active.relay_url == relay_url
                    && task_running
            })
        };

        if can_reuse {
            let control_tx = {
                let mut session = self.session.lock().await;
                let active = session
                    .as_mut()
                    .ok_or_else(|| "Marmot relay subscription is unavailable".to_string())?;
                if active.active_routes == validated_routes {
                    return Ok(());
                }
                active.active_routes = validated_routes;
                active.control_tx.clone()
            };
            control_tx
                .send(ReaderControl::ReplaceRoutes(routes))
                .await
                .map_err(|_| "Marmot relay subscriber is unavailable".to_string())?;
            return Ok(());
        }

        {
            let mut session = self.session.lock().await;
            if let Some(active) = session.take() {
                active.cancellation.cancel();
            }
        }
        self.stop_reader_task().await;

        let (control_tx, control_rx) = mpsc::channel(8);
        let plan = self
            .begin_native_session(account_public_key, relay_url, routes, control_tx)
            .await?;
        let generation = plan.generation;
        let (ready_tx, ready_rx) = oneshot::channel();
        let task_app = app.clone();
        let cancellation = plan.cancellation.clone();
        let task_relay_url = relay_url.to_string();
        let task = tokio::spawn(async move {
            let result = run_relay_reader(
                task_app.clone(),
                generation,
                task_relay_url,
                keys,
                plan.filters,
                cancellation,
                control_rx,
                ready_tx,
            )
            .await;
            if let Err(error) = result {
                eprintln!("buzz-desktop: Marmot preview subscriber stopped: {error}");
                let _ = task_app.emit(
                    MARMOT_SYNC_CHANGED_EVENT,
                    MarmotChangedPayload {
                        conversation_id: None,
                    },
                );
            }
        });
        *self.reader_task.lock().await = Some(task);

        match timeout(READER_CONNECT_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => {
                self.stop().await?;
                Err(error)
            }
            Ok(Err(_)) | Err(_) => {
                self.stop().await?;
                Err("Marmot relay subscriber did not become ready".to_string())
            }
        }
    }

    async fn mark_key_package_published(&self) -> Result<(), String> {
        let mut session = self.session.lock().await;
        let active = session
            .as_mut()
            .ok_or_else(|| "Marmot relay subscription is unavailable".to_string())?;
        active.key_package_published = true;
        Ok(())
    }

    async fn key_package_published(&self) -> bool {
        self.session
            .lock()
            .await
            .as_ref()
            .is_some_and(|active| active.key_package_published)
    }

    async fn conversation_for_route(&self, generation: u64, route: &str) -> Option<String> {
        let session = self.session.lock().await;
        session.as_ref().and_then(|active| {
            (active.generation == generation)
                .then(|| active.active_routes.get(route).cloned())
                .flatten()
        })
    }

    async fn replace_active_routes(
        &self,
        generation: u64,
        routes: Vec<NativeConversationRoute>,
    ) -> Result<(), String> {
        let validated = validate_native_routes(routes.clone())?;
        let control_tx = {
            let mut session = self.session.lock().await;
            let active = session
                .as_mut()
                .ok_or_else(|| "Marmot relay subscription is unavailable".to_string())?;
            if active.generation != generation {
                return Err("stale Marmot relay generation".to_string());
            }
            active.active_routes = validated;
            active.control_tx.clone()
        };
        control_tx
            .send(ReaderControl::ReplaceRoutes(routes))
            .await
            .map_err(|_| "Marmot relay subscriber is unavailable".to_string())
    }

    /// Validate, route-check, and deduplicate an event from the native relay
    /// reader before forwarding it to the sidecar.
    #[allow(dead_code)]
    pub(crate) async fn accept_group_event(
        &self,
        generation: u64,
        raw_event_json: String,
    ) -> Result<Option<VerifiedMarmotEnvelope>, String> {
        let envelope = verify_group_event(raw_event_json)?;
        let mut session = self.session.lock().await;
        let active = session
            .as_mut()
            .ok_or_else(|| "Marmot relay subscription is not active".to_string())?;
        if active.generation != generation {
            return Err("stale Marmot relay generation".to_string());
        }
        if !active.active_routes.contains_key(&envelope.route) {
            return Err("Marmot relay event did not match an active route".to_string());
        }
        if !active.record_event_id(&envelope.event_id) {
            return Ok(None);
        }
        Ok(Some(envelope))
    }

    /// Validate, recipient-check, and deduplicate a Welcome gift wrap from the
    /// native account-inbox subscription before sidecar ingest.
    #[allow(dead_code)]
    pub(crate) async fn accept_welcome_event(
        &self,
        generation: u64,
        raw_event_json: String,
    ) -> Result<Option<VerifiedMarmotWelcome>, String> {
        let (recipient, welcome) = verify_welcome_event(raw_event_json)?;
        let mut session = self.session.lock().await;
        let active = session
            .as_mut()
            .ok_or_else(|| "Marmot relay subscription is not active".to_string())?;
        if active.generation != generation {
            return Err("stale Marmot relay generation".to_string());
        }
        if active.account_public_key != recipient {
            return Err("Marmot Welcome did not match the active account".to_string());
        }
        if !active.record_event_id(&welcome.event_id) {
            return Ok(None);
        }
        Ok(Some(welcome))
    }

    /// Stop routing and hold the bridge lock across an identity/community
    /// mutation so a stale native subscriber cannot re-register mid-switch.
    pub(crate) async fn stop_for_transition(&self) -> Result<MarmotBridgeTransitionGuard, String> {
        let mut session = Arc::clone(&self.session).lock_owned().await;
        if let Some(active) = session.take() {
            active.cancellation.cancel();
        }
        let mut reader_task = Arc::clone(&self.reader_task).lock_owned().await;
        if let Some(task) = reader_task.take() {
            task.abort();
        }
        let _ = self.generation()?;
        Ok(MarmotBridgeTransitionGuard {
            _session: session,
            _reader_task: reader_task,
        })
    }

    async fn stop(&self) -> Result<(), String> {
        let mut session = self.session.lock().await;
        if let Some(active) = session.take() {
            active.cancellation.cancel();
        }
        let _ = self.generation()?;
        drop(session);
        self.stop_reader_task().await;
        Ok(())
    }

    async fn stop_reader_task(&self) {
        let task = self.reader_task.lock().await.take();
        if let Some(mut task) = task {
            if timeout(READER_STOP_TIMEOUT, &mut task).await.is_err() {
                task.abort();
            }
        }
    }
}

/// Holds the bridge generation lock during native context changes.
pub(crate) struct MarmotBridgeTransitionGuard {
    _session: OwnedMutexGuard<Option<BridgeSession>>,
    _reader_task: OwnedMutexGuard<Option<JoinHandle<()>>>,
}

fn build_subscription_filters(
    generation: u64,
    account_public_key: &str,
    active_routes: &HashSet<String>,
) -> Vec<NativeRelayFilter> {
    let mut routes = active_routes.iter().collect::<Vec<_>>();
    routes.sort_unstable();
    let mut filters = Vec::with_capacity(routes.len() + 1);
    filters.push(NativeRelayFilter {
        subscription_id: format!("marmot-{generation}-welcomes"),
        filter: serde_json::json!({
            "kinds": [MARMOT_WELCOME_KIND],
            "#p": [account_public_key],
            "limit": MAX_HISTORY_EVENTS_PER_FILTER,
        }),
    });
    filters.extend(
        routes
            .into_iter()
            .enumerate()
            .map(|(index, route)| NativeRelayFilter {
                subscription_id: format!("marmot-{generation}-group-{index}"),
                filter: serde_json::json!({
                    "kinds": [MARMOT_GROUP_MESSAGE_KIND],
                    "#h": [route],
                    "limit": MAX_HISTORY_EVENTS_PER_FILTER,
                }),
            }),
    );
    filters
}

fn validate_native_routes(
    routes: Vec<NativeConversationRoute>,
) -> Result<HashMap<String, String>, String> {
    if routes.len() > MAX_ACTIVE_ROUTES {
        return Err("invalid native Marmot subscription scope".to_string());
    }
    let mut validated = HashMap::with_capacity(routes.len());
    let mut conversation_ids = HashSet::with_capacity(routes.len());
    for entry in routes {
        validate_opaque_id(&entry.conversation_id, "mcv1_")?;
        if !is_lower_hex_32(&entry.route)
            || !conversation_ids.insert(entry.conversation_id.clone())
            || validated
                .insert(entry.route, entry.conversation_id)
                .is_some()
        {
            return Err("invalid native Marmot subscription scope".to_string());
        }
    }
    Ok(validated)
}

async fn send_filters(
    connection: &mut NostrWsConnection,
    filters: &[NativeRelayFilter],
) -> Result<(), String> {
    for entry in filters {
        connection
            .send_raw(&serde_json::json!([
                "REQ",
                entry.subscription_id,
                entry.filter
            ]))
            .await
            .map_err(|_| "Marmot relay subscription failed".to_string())?;
    }
    Ok(())
}

async fn replace_group_filters(
    connection: &mut NostrWsConnection,
    generation: u64,
    current_group_subscriptions: &mut Vec<String>,
    active_filters: &mut HashMap<String, NativeRelayFilter>,
    expected_close_acknowledgements: &mut HashSet<String>,
    routes: &[NativeConversationRoute],
) -> Result<(), String> {
    let validated = validate_native_routes(routes.to_vec())?;
    for subscription_id in current_group_subscriptions.drain(..) {
        active_filters.remove(&subscription_id);
        expected_close_acknowledgements.insert(subscription_id.clone());
        connection
            .send_raw(&serde_json::json!(["CLOSE", subscription_id]))
            .await
            .map_err(|_| "Marmot relay subscription refresh failed".to_string())?;
    }
    let filters = build_subscription_filters(
        generation,
        &"0".repeat(64),
        &validated.keys().cloned().collect(),
    );
    let group_filters = filters
        .into_iter()
        .filter(|entry| entry.filter["kinds"] == serde_json::json!([MARMOT_GROUP_MESSAGE_KIND]))
        .collect::<Vec<_>>();
    send_filters(connection, &group_filters).await?;
    active_filters.extend(
        group_filters
            .iter()
            .cloned()
            .map(|entry| (entry.subscription_id.clone(), entry)),
    );
    current_group_subscriptions
        .extend(group_filters.into_iter().map(|entry| entry.subscription_id));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_relay_reader(
    app: AppHandle,
    generation: u64,
    relay_url: String,
    keys: Keys,
    initial_filters: Vec<NativeRelayFilter>,
    cancellation: CancellationToken,
    mut control_rx: mpsc::Receiver<ReaderControl>,
    ready_tx: oneshot::Sender<Result<(), String>>,
) -> Result<(), String> {
    let connected = timeout(
        READER_CONNECT_TIMEOUT,
        NostrWsConnection::connect_authenticated(&relay_url, &keys, None),
    )
    .await
    .map_err(|_| "Marmot relay subscriber connection timed out".to_string())?
    .map_err(|_| "Marmot relay subscriber authentication failed".to_string());
    let mut connection = match connected {
        Ok(connection) => connection,
        Err(error) => {
            let _ = ready_tx.send(Err(error.clone()));
            return Err(error);
        }
    };
    if let Err(error) = send_filters(&mut connection, &initial_filters).await {
        let _ = ready_tx.send(Err(error.clone()));
        return Err(error);
    }
    eprintln!(
        "buzz-desktop: Marmot preview subscriber ready with {} filter(s)",
        initial_filters.len()
    );
    let mut current_group_subscriptions = initial_filters
        .iter()
        .filter(|entry| entry.filter["kinds"] == serde_json::json!([MARMOT_GROUP_MESSAGE_KIND]))
        .map(|entry| entry.subscription_id.clone())
        .collect::<Vec<_>>();
    let mut active_filters = initial_filters
        .into_iter()
        .map(|entry| (entry.subscription_id.clone(), entry))
        .collect::<HashMap<_, _>>();
    let mut expected_close_acknowledgements = HashSet::new();
    if ready_tx.send(Ok(())).is_err() {
        return Ok(());
    }

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            control = control_rx.recv() => {
                match control {
                    Some(ReaderControl::ReplaceRoutes(routes)) => {
                        replace_group_filters(
                            &mut connection,
                            generation,
                            &mut current_group_subscriptions,
                            &mut active_filters,
                            &mut expected_close_acknowledgements,
                            &routes,
                        ).await?;
                    }
                    None => return Ok(()),
                }
            }
            relay_message = connection.next_event(READER_POLL_TIMEOUT) => {
                match relay_message {
                    Ok(RelayMessage::Event {
                        subscription_id,
                        event,
                    }) => {
                        eprintln!(
                            "buzz-desktop: Marmot subscriber received kind {} event {} on {}",
                            event.kind.as_u16(),
                            event.id.to_hex(),
                            subscription_id
                        );
                        process_inbound_event(&app, generation, *event).await?;
                    }
                    Ok(RelayMessage::Eose { subscription_id }) => eprintln!(
                        "buzz-desktop: Marmot subscriber reached end of stored events on {}",
                        subscription_id
                    ),
                    Ok(RelayMessage::Closed {
                        subscription_id,
                        message,
                    }) => {
                        if expected_close_acknowledgements.remove(&subscription_id)
                            && message.is_empty()
                        {
                            continue;
                        }
                        if message.starts_with("rate-limited:") {
                            let filter = active_filters
                                .get(&subscription_id)
                                .cloned()
                                .ok_or_else(|| {
                                    "Marmot relay rate-limited an unknown subscription".to_string()
                                })?;
                            crate::relay_admission::activate_rate_limit(
                                crate::relay::extract_retry_in_hint(&message),
                            );
                            tokio::select! {
                                _ = cancellation.cancelled() => return Ok(()),
                                _ = crate::relay_admission::wait_for_rate_limit() => {}
                            }
                            send_filters(&mut connection, &[filter]).await?;
                            continue;
                        }
                        return Err(format!(
                            "Marmot relay closed native subscription {subscription_id}: {message}"
                        ));
                    }
                    Ok(_) | Err(WsClientError::Timeout) => {}
                    Err(_) => return Err("Marmot relay subscriber disconnected".to_string()),
                }
            }
        }
    }
}

async fn process_inbound_event(
    app: &AppHandle,
    generation: u64,
    event: Event,
) -> Result<(), String> {
    let bridge = app.state::<MarmotBridgeState>();
    let raw = event.as_json();
    let (signed_event, conversation_id) = match event.kind.as_u16() {
        MARMOT_GROUP_MESSAGE_KIND => {
            let Some(envelope) = bridge.accept_group_event(generation, raw).await? else {
                return Ok(());
            };
            let conversation_id = bridge
                .conversation_for_route(generation, &envelope.route)
                .await;
            let verified = Event::from_json(&envelope.raw_event_json)
                .map_err(|_| "Marmot relay event could not be forwarded".to_string())?;
            (
                SignedNostrEvent::from_nostr_event(&verified),
                conversation_id,
            )
        }
        MARMOT_WELCOME_KIND => {
            let Some(welcome) = bridge.accept_welcome_event(generation, raw).await? else {
                return Ok(());
            };
            let verified = Event::from_json(&welcome.raw_event_json)
                .map_err(|_| "Marmot Welcome could not be forwarded".to_string())?;
            (SignedNostrEvent::from_nostr_event(&verified), None)
        }
        _ => return Ok(()),
    };

    let ingest = app
        .state::<crate::marmot_sidecar::MarmotSidecarManager>()
        .ingest_native_event(app, signed_event)
        .await?;
    eprintln!(
        "buzz-desktop: Marmot ingested kind {} event: outcome={:?}, joined={}, delivered={}, rejected={}",
        event.kind.as_u16(),
        ingest.outcome,
        ingest.joined_conversations.len(),
        ingest.delivered_messages,
        ingest.rejected_messages
    );
    let mut changed_conversations = ingest
        .changed_conversation_ids
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    changed_conversations.extend(
        ingest
            .joined_conversations
            .iter()
            .map(|conversation| conversation.conversation_id.clone()),
    );
    for conversation_id in changed_conversations {
        let _ = app.emit(
            MARMOT_CONVERSATION_CHANGED_EVENT,
            MarmotChangedPayload {
                conversation_id: Some(conversation_id),
            },
        );
    }
    if ingest.delivered_messages > 0 || !ingest.changed_message_ids.is_empty() {
        let _ = app.emit(
            MARMOT_MESSAGE_CHANGED_EVENT,
            MarmotChangedPayload { conversation_id },
        );
    }
    if !ingest.joined_conversations.is_empty() {
        refresh_active_reader_routes(app, generation).await?;
    }
    Ok(())
}

async fn fetch_latest_key_package(
    relay_url: &str,
    keys: &Keys,
    invitee_pubkey: &str,
) -> Result<SignedNostrEvent, String> {
    if !is_lower_hex_32(invitee_pubkey) {
        return Err("invalid encrypted-conversation member".to_string());
    }
    let query = async {
        let mut connection = NostrWsConnection::connect_authenticated(relay_url, keys, None)
            .await
            .map_err(|_| "could not authenticate KeyPackage query".to_string())?;
        let subscription_id = "marmot-preview-key-package";
        connection
            .send_raw(&serde_json::json!([
                "REQ",
                subscription_id,
                {
                    "kinds": [MARMOT_KEY_PACKAGE_KIND],
                    "authors": [invitee_pubkey],
                    "limit": 8,
                }
            ]))
            .await
            .map_err(|_| "could not query the invitee KeyPackage".to_string())?;

        let mut latest: Option<Event> = None;
        loop {
            match connection.next_event(QUERY_TIMEOUT).await {
                Ok(RelayMessage::Event {
                    subscription_id: returned,
                    event,
                }) if returned == subscription_id => {
                    if event.kind.as_u16() != MARMOT_KEY_PACKAGE_KIND
                        || event.pubkey.to_hex() != invitee_pubkey
                        || event.verify().is_err()
                    {
                        return Err("relay returned an invalid invitee KeyPackage".to_string());
                    }
                    let candidate = SignedNostrEvent::from_nostr_event(&event);
                    candidate
                        .validate()
                        .map_err(|_| "relay returned an invalid invitee KeyPackage".to_string())?;
                    if latest
                        .as_ref()
                        .is_none_or(|current| event.created_at > current.created_at)
                    {
                        latest = Some(*event);
                    }
                }
                Ok(RelayMessage::Eose {
                    subscription_id: returned,
                }) if returned == subscription_id => break,
                Ok(RelayMessage::Closed {
                    subscription_id: returned,
                    ..
                }) if returned == subscription_id => {
                    return Err("relay rejected the invitee KeyPackage query".to_string());
                }
                Ok(_) => {}
                Err(_) => return Err("invitee KeyPackage query did not complete".to_string()),
            }
        }
        let _ = connection
            .send_raw(&serde_json::json!(["CLOSE", subscription_id]))
            .await;
        latest
            .map(|event| SignedNostrEvent::from_nostr_event(&event))
            .ok_or_else(|| "invitee has not published a Marmot KeyPackage".to_string())
    };
    timeout(QUERY_TIMEOUT, query)
        .await
        .map_err(|_| "invitee KeyPackage query timed out".to_string())?
}

fn active_native_context(app: &AppHandle) -> Result<(String, String, Keys), String> {
    let state = app.state::<crate::app_state::AppState>();
    if state.shutdown_started.load(Ordering::Acquire) {
        return Err("Marmot preview is unavailable during shutdown".to_string());
    }
    let keys = state.signing_keys()?;
    let account_public_key = keys.public_key().to_hex();
    let relay_url = crate::relay::relay_ws_url_with_override(&state);
    Ok((account_public_key, relay_url, keys))
}

async fn refresh_native_routes(app: &AppHandle) -> Result<(), String> {
    let (account_public_key, relay_url, keys) = active_native_context(app)?;
    let routes = app
        .state::<crate::marmot_sidecar::MarmotSidecarManager>()
        .native_subscription_routes(app)
        .await?
        .into_iter()
        .map(|route| NativeConversationRoute {
            conversation_id: route.conversation_id,
            route: route.route,
        })
        .collect();
    app.state::<MarmotBridgeState>()
        .ensure_reader(app, &account_public_key, &relay_url, keys, routes)
        .await
}

async fn refresh_active_reader_routes(app: &AppHandle, generation: u64) -> Result<(), String> {
    let routes = app
        .state::<crate::marmot_sidecar::MarmotSidecarManager>()
        .native_subscription_routes(app)
        .await?
        .into_iter()
        .map(|route| NativeConversationRoute {
            conversation_id: route.conversation_id,
            route: route.route,
        })
        .collect();
    app.state::<MarmotBridgeState>()
        .replace_active_routes(generation, routes)
        .await
}

async fn ensure_preview_ready(app: &AppHandle) -> Result<String, String> {
    if !preview_gate_enabled() {
        return Err("Marmot preview is disabled".to_string());
    }
    let manager = app.state::<crate::marmot_sidecar::MarmotSidecarManager>();
    let status = manager.status(app).await?;
    let account_public_key = match status {
        crate::marmot_sidecar::MarmotRuntimeStatus::Ready { account_public_key } => {
            account_public_key
        }
        crate::marmot_sidecar::MarmotRuntimeStatus::RecoveryRequired { .. } => {
            return Err("Marmot preview requires native recovery".to_string())
        }
    };
    refresh_native_routes(app).await?;
    let bridge = app.state::<MarmotBridgeState>();
    if !bridge.key_package_published().await {
        manager.publish_native_key_package(app).await?;
        bridge.mark_key_package_published().await?;
    }
    Ok(account_public_key)
}

/// Return whether the explicitly enabled debug preview is ready for React.
#[tauri::command]
pub async fn get_marmot_bridge_status(app: AppHandle) -> MarmotBridgeStatus {
    if !preview_gate_enabled() {
        return disabled_bridge_status(if cfg!(debug_assertions) {
            "preview_not_opted_in"
        } else {
            "release_build"
        });
    }
    match ensure_preview_ready(&app).await {
        Ok(_) => MarmotBridgeStatus {
            api_version: BRIDGE_API_VERSION,
            enabled: true,
            reason_code: "ready",
        },
        Err(_) => disabled_bridge_status("native_preview_unavailable"),
    }
}

/// Create one debug-preview encrypted conversation with exactly one invitee.
#[tauri::command]
pub async fn create_marmot_preview_conversation(
    app: AppHandle,
    input: MarmotCreateConversationInput,
) -> Result<MarmotConversationDto, String> {
    input.validate()?;
    let account_public_key = ensure_preview_ready(&app).await?;
    if input.invitee_pubkey == account_public_key {
        return Err("an encrypted conversation requires another member".to_string());
    }
    let (_, relay_url, keys) = active_native_context(&app)?;
    let key_package = fetch_latest_key_package(&relay_url, &keys, &input.invitee_pubkey).await?;
    let manager = app.state::<crate::marmot_sidecar::MarmotSidecarManager>();
    let conversation = manager
        .create_native_conversation(&app, input.name, input.description, vec![key_package])
        .await?;
    refresh_native_routes(&app).await?;
    // CreateConversation returns the projection captured before its queued
    // Welcome publication is drained. Read the projection back after the
    // publication completes so React receives `ready`, not the stale
    // `pending_publication` snapshot.
    let conversation = manager
        .list_native_conversations(&app, MAX_CONVERSATION_LIST_LIMIT)
        .await?
        .into_iter()
        .find(|current| current.conversation_id == conversation.conversation_id)
        .ok_or_else(|| "created encrypted conversation is unavailable".to_string())?;
    let _ = app.emit(
        MARMOT_CONVERSATION_CHANGED_EVENT,
        MarmotChangedPayload {
            conversation_id: Some(conversation.conversation_id.clone()),
        },
    );
    Ok(conversation.into())
}

/// List bounded sanitized encrypted conversations for the active account.
#[tauri::command]
pub async fn list_marmot_preview_conversations(
    app: AppHandle,
    input: MarmotListConversationsInput,
) -> Result<Vec<MarmotConversationDto>, String> {
    input.validate()?;
    ensure_preview_ready(&app).await?;
    app.state::<crate::marmot_sidecar::MarmotSidecarManager>()
        .list_native_conversations(&app, input.limit.unwrap_or(MAX_CONVERSATION_LIST_LIMIT))
        .await
        .map(|conversations| conversations.into_iter().map(Into::into).collect())
}

/// List bounded sanitized decrypted messages for one opaque conversation id.
#[tauri::command]
pub async fn list_marmot_preview_messages(
    app: AppHandle,
    input: MarmotListMessagesInput,
) -> Result<Vec<MarmotMessageDto>, String> {
    input.validate()?;
    ensure_preview_ready(&app).await?;
    app.state::<crate::marmot_sidecar::MarmotSidecarManager>()
        .list_native_messages(
            &app,
            input.conversation_id,
            input.limit.unwrap_or(MAX_MESSAGE_LIST_LIMIT),
        )
        .await
        .map(|messages| messages.into_iter().map(Into::into).collect())
}

/// Encrypt and publish one debug-preview text message without plaintext fallback.
#[tauri::command]
pub async fn send_marmot_preview_message(
    app: AppHandle,
    input: MarmotSendMessageInput,
) -> Result<MarmotSendResult, String> {
    input.validate()?;
    ensure_preview_ready(&app).await?;
    let created_at = nostr::Timestamp::now().as_secs();
    let queued = app
        .state::<crate::marmot_sidecar::MarmotSidecarManager>()
        .send_native_message(
            &app,
            input.conversation_id.clone(),
            created_at,
            input.content,
        )
        .await?;
    let _ = app.emit(
        MARMOT_MESSAGE_CHANGED_EVENT,
        MarmotChangedPayload {
            conversation_id: Some(queued.message.conversation_id.clone()),
        },
    );
    Ok(MarmotSendResult {
        conversation_id: queued.message.conversation_id,
        queued_behind_transition: queued.queued_behind_transition,
    })
}

fn verify_group_event(raw_event_json: String) -> Result<VerifiedMarmotEnvelope, String> {
    if raw_event_json.len() > MAX_INBOUND_EVENT_BYTES {
        return Err("Marmot relay event exceeds its safe bound".to_string());
    }
    let event = Event::from_json(&raw_event_json)
        .map_err(|_| "Marmot relay returned an invalid event".to_string())?;
    if event.kind.as_u16() != MARMOT_GROUP_MESSAGE_KIND || event.verify().is_err() {
        return Err("Marmot relay returned an invalid event".to_string());
    }

    let mut route = None;
    let mut expiration_seen = false;
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        match parts.first().map(String::as_str) {
            Some("h")
                if parts.len() == 2
                    && route.is_none()
                    && parts.get(1).is_some_and(|value| is_lower_hex_32(value)) =>
            {
                route = parts.get(1).cloned();
            }
            Some("expiration")
                if parts.len() == 2
                    && !expiration_seen
                    && parts
                        .get(1)
                        .is_some_and(|value| value.parse::<u64>().is_ok()) =>
            {
                expiration_seen = true;
            }
            _ => return Err("Marmot relay event has invalid routing metadata".to_string()),
        }
    }
    let route = route.ok_or_else(|| "Marmot relay event is missing its route".to_string())?;
    let decoded = BASE64_STANDARD
        .decode(event.content.as_bytes())
        .map_err(|_| "Marmot relay event has an invalid payload".to_string())?;
    if decoded.len() < MIN_MARMOT_PAYLOAD_BYTES {
        return Err("Marmot relay event has an invalid payload".to_string());
    }

    Ok(VerifiedMarmotEnvelope {
        event_id: event.id.to_hex(),
        route,
        raw_event_json,
    })
}

fn verify_welcome_event(raw_event_json: String) -> Result<(String, VerifiedMarmotWelcome), String> {
    if raw_event_json.len() > MAX_INBOUND_EVENT_BYTES {
        return Err("Marmot Welcome exceeds its safe bound".to_string());
    }
    let event = Event::from_json(&raw_event_json)
        .map_err(|_| "Marmot relay returned an invalid Welcome".to_string())?;
    if event.kind.as_u16() != MARMOT_WELCOME_KIND || event.verify().is_err() {
        return Err("Marmot relay returned an invalid Welcome".to_string());
    }

    let mut recipients = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("p"));
    let recipient_tag = recipients
        .next()
        .ok_or_else(|| "Marmot Welcome has invalid recipient metadata".to_string())?;
    if recipients.next().is_some() {
        return Err("Marmot Welcome has invalid recipient metadata".to_string());
    }
    let parts = recipient_tag.as_slice();
    if parts.len() != 2 || !parts.get(1).is_some_and(|value| is_lower_hex_32(value)) {
        return Err("Marmot Welcome has invalid recipient metadata".to_string());
    }
    let recipient = parts[1].clone();

    Ok((
        recipient,
        VerifiedMarmotWelcome {
            event_id: event.id.to_hex(),
            raw_event_json,
        },
    ))
}

/// Cancel the native relay generation during centralized app shutdown.
pub(crate) fn shutdown_marmot_bridge(app: &AppHandle) {
    let app = app.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    tauri::async_runtime::spawn(async move {
        let result = app.state::<MarmotBridgeState>().stop().await;
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(READER_STOP_TIMEOUT + Duration::from_secs(2)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("buzz-desktop: failed to stop Marmot relay bridge: {error}"),
        Err(_) => eprintln!("buzz-desktop: timed out stopping Marmot relay bridge"),
    }
}

#[cfg(test)]
mod tests {
    use nostr::{EventBuilder, Keys, Kind, Tag};

    use super::*;

    fn route(byte: &str) -> String {
        byte.repeat(64)
    }

    fn signed_group_event(route: &str) -> String {
        EventBuilder::new(
            Kind::Custom(MARMOT_GROUP_MESSAGE_KIND),
            BASE64_STANDARD.encode([7_u8; MIN_MARMOT_PAYLOAD_BYTES]),
        )
        .tags([Tag::parse(["h", route]).expect("h tag")])
        .sign_with_keys(&Keys::generate())
        .expect("sign event")
        .as_json()
    }

    fn signed_welcome_event(sender: &Keys, receiver: &Keys) -> String {
        EventBuilder::new(Kind::Custom(MARMOT_WELCOME_KIND), "opaque NIP-59 payload")
            .tags([Tag::parse(["p", receiver.public_key().to_hex().as_str()]).expect("p tag")])
            .sign_with_keys(sender)
            .expect("sign Welcome envelope")
            .as_json()
    }

    fn native_route(route: String, marker: char) -> NativeConversationRoute {
        NativeConversationRoute {
            conversation_id: format!("mcv1_{}", marker.to_string().repeat(43)),
            route,
        }
    }

    async fn begin_test_session(
        state: &MarmotBridgeState,
        account_public_key: &str,
        routes: Vec<NativeConversationRoute>,
    ) -> NativeRelaySubscriptionPlan {
        let (control_tx, _control_rx) = mpsc::channel(1);
        state
            .begin_native_session(
                account_public_key,
                "ws://localhost:3000",
                routes,
                control_tx,
            )
            .await
            .expect("begin session")
    }

    #[test]
    fn preview_gate_requires_debug_build_and_explicit_opt_in() {
        assert!(!preview_gate_value(false, Some("1")));
        assert!(!preview_gate_value(true, None));
        assert!(!preview_gate_value(true, Some("false")));
        assert!(preview_gate_value(true, Some("true")));
        assert_eq!(
            disabled_bridge_status("preview_not_opted_in"),
            MarmotBridgeStatus {
                api_version: 1,
                enabled: false,
                reason_code: "preview_not_opted_in",
            }
        );
    }

    #[test]
    fn ui_identifiers_cannot_be_raw_transport_routes() {
        let input = MarmotSendMessageInput {
            conversation_id: route("a"),
            content: "hello".into(),
        };
        assert!(input.validate().is_err());

        let input = MarmotSendMessageInput {
            conversation_id: format!("mcv1_{}", "A".repeat(43)),
            content: "hello".into(),
        };
        assert!(input.validate().is_ok());
    }

    #[test]
    fn command_inputs_enforce_content_member_and_page_bounds() {
        let create = MarmotCreateConversationInput {
            name: "project".into(),
            description: String::new(),
            invitee_pubkey: route("a"),
        };
        assert!(create.validate().is_ok());

        let invalid = MarmotCreateConversationInput {
            name: "project".into(),
            description: String::new(),
            invitee_pubkey: "not-a-pubkey".into(),
        };
        assert!(invalid.validate().is_err());

        let page = MarmotListMessagesInput {
            conversation_id: format!("mcv1_{}", "A".repeat(43)),
            limit: Some(MAX_MESSAGE_LIST_LIMIT + 1),
        };
        assert!(page.validate().is_err());
    }

    #[test]
    fn sanitized_dtos_use_the_camel_case_preview_contract() {
        let conversation_id = format!("mcv1_{}", "A".repeat(43));
        let dto = MarmotMessageDto::from(MessageSummary {
            message_id: format!("mmsg1_{}", "B".repeat(43)),
            conversation_id: conversation_id.clone(),
            author_public_key: route("c"),
            created_at: 1,
            content: "hello".into(),
            delivery: MessageDeliveryState::PendingPublication,
        });
        let json = serde_json::to_value(dto).expect("serialize message DTO");
        assert_eq!(json["conversationId"], conversation_id);
        assert_eq!(json["authorPublicKey"], route("c"));
        assert_eq!(json["createdAt"], 1);
        assert_eq!(json["delivery"], "pending_publication");
        assert!(json.get("conversation_id").is_none());
    }

    #[tokio::test]
    async fn native_plan_uses_one_exact_route_per_group_filter() {
        let state = MarmotBridgeState::default();
        let plan = begin_test_session(
            &state,
            &route("c"),
            vec![native_route(route("a"), 'A'), native_route(route("b"), 'B')],
        )
        .await;
        assert_eq!(plan.filters.len(), 3);
        let group_filters = plan
            .filters
            .iter()
            .filter(|entry| entry.filter["kinds"] == serde_json::json!([445]))
            .collect::<Vec<_>>();
        assert_eq!(group_filters.len(), 2);
        assert!(group_filters.iter().all(|entry| {
            entry.filter["#h"]
                .as_array()
                .is_some_and(|routes| routes.len() == 1)
        }));
        assert_eq!(
            plan.filters[0].filter["#p"],
            serde_json::json!([route("c")])
        );
    }

    #[tokio::test]
    async fn inbound_events_are_verified_deduplicated_and_generation_scoped() {
        let state = MarmotBridgeState::default();
        let active_route = route("a");
        let plan = begin_test_session(
            &state,
            &route("c"),
            vec![native_route(active_route.clone(), 'A')],
        )
        .await;
        let raw = signed_group_event(&active_route);
        let first = state
            .accept_group_event(plan.generation, raw.clone())
            .await
            .expect("accept first");
        assert!(first.is_some());
        let duplicate = state
            .accept_group_event(plan.generation, raw)
            .await
            .expect("deduplicate second");
        assert!(duplicate.is_none());

        let replacement = begin_test_session(
            &state,
            &route("c"),
            vec![native_route(active_route.clone(), 'A')],
        )
        .await;
        assert!(plan.cancellation.is_cancelled());
        assert!(state
            .accept_group_event(plan.generation, signed_group_event(&active_route))
            .await
            .is_err());
        assert!(!replacement.cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn welcomes_are_verified_recipient_scoped_and_deduplicated() {
        let state = MarmotBridgeState::default();
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let other = Keys::generate();
        let plan = begin_test_session(&state, &receiver.public_key().to_hex(), Vec::new()).await;
        let raw = signed_welcome_event(&sender, &receiver);
        assert!(state
            .accept_welcome_event(plan.generation, raw.clone())
            .await
            .expect("accept Welcome")
            .is_some());
        assert!(state
            .accept_welcome_event(plan.generation, raw)
            .await
            .expect("deduplicate Welcome")
            .is_none());

        let wrong_recipient = signed_welcome_event(&sender, &other);
        assert!(state
            .accept_welcome_event(plan.generation, wrong_recipient)
            .await
            .is_err());
    }

    #[test]
    fn group_event_validation_rejects_extra_or_wrong_tags() {
        let route = route("a");
        let event = EventBuilder::new(
            Kind::Custom(MARMOT_GROUP_MESSAGE_KIND),
            BASE64_STANDARD.encode([7_u8; MIN_MARMOT_PAYLOAD_BYTES]),
        )
        .tags([
            Tag::parse(["h", route.as_str()]).expect("h tag"),
            Tag::parse(["encoding", "base64"]).expect("legacy encoding tag"),
        ])
        .sign_with_keys(&Keys::generate())
        .expect("sign event")
        .as_json();
        assert!(verify_group_event(event).is_err());
    }
}
