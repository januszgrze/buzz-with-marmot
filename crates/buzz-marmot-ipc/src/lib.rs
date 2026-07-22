//! Versioned, length-prefixed IPC messages for the native Marmot sidecar.
//!
//! Frames use a four-byte big-endian payload length followed by UTF-8 JSON.
//! The crate deliberately has no MDK or SQLite dependency so it can also be
//! linked into the Tauri process without creating a native SQLite conflict.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{collections::BTreeSet, fmt, mem, path::Path};

use nostr::{Event, JsonUtil};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

/// The only protocol version understood by this initial sidecar.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum JSON payload size accepted from either side of the IPC boundary.
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Maximum UTF-8 byte length of a handshake client build identifier.
pub const MAX_CLIENT_NAME_BYTES: usize = 128;

/// Maximum UTF-8 byte length of a native SQLCipher database path.
pub const MAX_DATABASE_PATH_BYTES: usize = 4 * 1024;

/// Maximum UTF-8 byte length of an opaque native action identifier.
pub const MAX_ACTION_ID_BYTES: usize = 128;

/// Maximum number of relay endpoints attached to one publication action.
pub const MAX_RELAY_ENDPOINTS: usize = 16;

/// Maximum UTF-8 byte length of one relay endpoint URL.
pub const MAX_RELAY_ENDPOINT_BYTES: usize = 512;

/// Maximum number of tags carried in one signed Nostr event DTO.
pub const MAX_NOSTR_TAGS: usize = 64;

/// Maximum number of string fields in one Nostr tag.
pub const MAX_NOSTR_TAG_ITEMS: usize = 32;

/// Maximum UTF-8 byte length of one Nostr tag field.
pub const MAX_NOSTR_TAG_ITEM_BYTES: usize = 4 * 1024;

/// Maximum signed-event content length below the overall frame ceiling.
pub const MAX_NOSTR_CONTENT_BYTES: usize = 56 * 1024;

/// Maximum UTF-8 byte length of a relay-controlled publish detail.
pub const MAX_RELAY_REPORT_DETAIL_BYTES: usize = 512;

/// Maximum UTF-8 byte length of an opaque desktop conversation identifier.
pub const MAX_CONVERSATION_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of an encrypted conversation name.
pub const MAX_CONVERSATION_NAME_BYTES: usize = 128;

/// Maximum UTF-8 byte length of an encrypted conversation description.
pub const MAX_CONVERSATION_DESCRIPTION_BYTES: usize = 1024;

/// Maximum UTF-8 byte length of one encrypted text message.
pub const MAX_MESSAGE_CONTENT_BYTES: usize = 4 * 1024;

/// Maximum number of KeyPackage events accepted for one group creation.
pub const MAX_INVITEE_KEY_PACKAGES: usize = 32;

/// Maximum number of conversation summaries returned in one frame.
pub const MAX_CONVERSATION_LIST_LIMIT: u16 = 32;

/// Maximum number of decrypted messages returned in one frame.
pub const MAX_MESSAGE_LIST_LIMIT: u16 = 8;

/// Maximum number of exact native subscription routes returned in one frame.
pub const MAX_SUBSCRIPTION_ROUTES: usize = 32;

/// Maximum number of sanitized changed identifiers returned for one ingest.
pub const MAX_CHANGED_IDS: usize = 32;

/// Stable handshake capability enabling the debug-only desktop preview.
pub const CAPABILITY_EXPERIMENTAL_PREVIEW_V1: &str = "experimental_preview_v1";

/// Versioned prefix for opaque encrypted conversation identifiers.
pub const CONVERSATION_ID_PREFIX: &str = "mcv1_";

/// Versioned prefix for opaque encrypted message identifiers.
pub const MESSAGE_ID_PREFIX: &str = "mmsg1_";

/// Errors produced by frame encoding, decoding, or schema validation.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// A frame declares or encodes a payload larger than [`MAX_FRAME_SIZE`].
    #[error("IPC frame is too large")]
    FrameTooLarge,
    /// JSON serialization or deserialization failed.
    #[error("invalid IPC JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The peer selected a protocol version this build does not understand.
    #[error("unsupported IPC protocol version {received}")]
    UnsupportedVersion {
        /// Version advertised by the peer.
        received: u16,
    },
    /// Request id zero is reserved for messages that cannot be correlated.
    #[error("IPC request id must be non-zero")]
    InvalidRequestId,
    /// A schema field is empty, too long, or otherwise structurally invalid.
    #[error("invalid IPC request field")]
    InvalidField,
}

/// Exactly 32 secret bytes transported inside an authenticated native pipe.
///
/// The value is intentionally serializable because the first sidecar slice
/// receives initialization material over stdin. It must never be placed in
/// argv, environment variables, logs, error messages, or responses.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretBytes32([u8; 32]);

impl SecretBytes32 {
    /// Wrap 32 bytes that will be zeroized when this value is dropped.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Consume the wrapper, transferring its bytes to the native runtime.
    #[must_use]
    pub fn into_bytes(mut self) -> [u8; 32] {
        mem::take(&mut self.0)
    }
}

impl Drop for SecretBytes32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes32(<redacted>)")
    }
}

/// One client request sent to the sidecar.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Protocol version used to encode this request.
    pub version: u16,
    /// Non-zero id echoed by the matching response.
    pub request_id: u64,
    /// Requested sidecar operation.
    pub command: Command,
}

impl Request {
    /// Build a request using the current protocol version.
    #[must_use]
    pub fn new(request_id: u64, command: Command) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            command,
        }
    }

    /// Validate fields shared by every request variant.
    pub fn validate(&self) -> Result<(), IpcError> {
        validate_envelope(self.version, self.request_id)?;
        match &self.command {
            Command::Handshake { client_name } => {
                validate_bounded_text(client_name, MAX_CLIENT_NAME_BYTES, false)
            }
            Command::Initialize {
                database_path,
                relay_endpoint,
                ..
            } => {
                validate_bounded_text(database_path, MAX_DATABASE_PATH_BYTES, true)?;
                if !Path::new(database_path).is_absolute() {
                    return Err(IpcError::InvalidField);
                }
                validate_relay_endpoint(relay_endpoint)
            }
            Command::CompleteAction {
                action_id,
                completion,
            } => {
                validate_action_id(action_id)?;
                completion.validate()
            }
            Command::CreateConversation {
                name,
                description,
                invitee_key_packages,
            } => {
                validate_bounded_text(name, MAX_CONVERSATION_NAME_BYTES, true)?;
                validate_optional_bounded_text(
                    description,
                    MAX_CONVERSATION_DESCRIPTION_BYTES,
                    true,
                )?;
                if invitee_key_packages.is_empty()
                    || invitee_key_packages.len() > MAX_INVITEE_KEY_PACKAGES
                {
                    return Err(IpcError::InvalidField);
                }
                for event in invitee_key_packages {
                    event.validate()?;
                    if event.kind != 30_443 {
                        return Err(IpcError::InvalidField);
                    }
                }
                Ok(())
            }
            Command::SendMessage {
                conversation_id,
                created_at,
                content,
            } => {
                validate_conversation_id(conversation_id)?;
                if *created_at == 0 {
                    return Err(IpcError::InvalidField);
                }
                validate_bounded_text(content, MAX_MESSAGE_CONTENT_BYTES, true)
            }
            Command::IngestEvent { event } => {
                event.validate()?;
                if !matches!(event.kind, 445 | 1059) {
                    return Err(IpcError::InvalidField);
                }
                Ok(())
            }
            Command::ListConversations { limit } => {
                validate_limit(*limit, MAX_CONVERSATION_LIST_LIMIT)
            }
            Command::ListMessages {
                conversation_id,
                limit,
            } => {
                validate_conversation_id(conversation_id)?;
                validate_limit(*limit, MAX_MESSAGE_LIST_LIMIT)
            }
            Command::GetSubscriptionPlan => Ok(()),
            Command::Status
            | Command::PublishKeyPackage
            | Command::NextAction
            | Command::Shutdown => Ok(()),
        }
    }
}

/// Operations supported by the first native sidecar slice.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Negotiate the protocol before any stateful operation.
    Handshake {
        /// Human-readable client build identifier used only for diagnostics.
        client_name: String,
    },
    /// Open or restore one encrypted MDK account-device runtime.
    Initialize {
        /// Native path of the SQLCipher database owned by this identity scope.
        database_path: String,
        /// Independently random SQLCipher database key.
        database_key: SecretBytes32,
        /// Nostr account secret used by native MDK signers.
        account_secret_key: SecretBytes32,
        /// Canonical WebSocket relay endpoint for this desktop community.
        relay_endpoint: String,
    },
    /// Return whether the runtime is initialized, without exposing secrets.
    Status,
    /// Generate, persist, sign, and enqueue a fresh Marmot KeyPackage event.
    PublishKeyPackage,
    /// Create a new encrypted group from fully signed invitee KeyPackages.
    CreateConversation {
        /// MLS-authenticated encrypted group name.
        name: String,
        /// MLS-authenticated encrypted group description.
        description: String,
        /// Full kind `30443` events fetched for every initial invitee.
        invitee_key_packages: Vec<SignedNostrEvent>,
    },
    /// Encrypt and enqueue one text message for an opaque local conversation.
    SendMessage {
        /// Opaque sidecar-generated conversation identifier.
        conversation_id: String,
        /// Inner application-event timestamp in Unix seconds.
        created_at: u64,
        /// Plaintext visible only inside the private native boundary.
        content: String,
    },
    /// Ingest one exact signed Welcome gift-wrap or Marmot group event.
    IngestEvent {
        /// Verified by the sidecar before it is passed to MDK.
        event: SignedNostrEvent,
    },
    /// List a bounded number of sanitized encrypted conversations.
    ListConversations {
        /// Maximum number of summaries to return.
        limit: u16,
    },
    /// List a bounded number of locally projected decrypted messages.
    ListMessages {
        /// Opaque sidecar-generated conversation identifier.
        conversation_id: String,
        /// Maximum number of messages to return.
        limit: u16,
    },
    /// Return exact native-only kind `445` routes for the live session.
    GetSubscriptionPlan,
    /// Poll the next native action without allowing the client to rewrite it.
    NextAction,
    /// Report the outcome of one previously returned native action.
    CompleteAction {
        /// Opaque id copied exactly from the action being completed.
        action_id: String,
        /// Definite per-endpoint outcome or an ambiguous result requiring an
        /// exact retry of the native action.
        completion: ActionCompletion,
    },
    /// Flush the response and end the sidecar process cleanly.
    Shutdown,
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake { client_name } => formatter
                .debug_struct("Handshake")
                .field("client_name", client_name)
                .finish(),
            Self::Initialize {
                database_path,
                database_key,
                account_secret_key,
                relay_endpoint,
            } => formatter
                .debug_struct("Initialize")
                .field("database_path", database_path)
                .field("database_key", database_key)
                .field("account_secret_key", account_secret_key)
                .field("relay_endpoint", relay_endpoint)
                .finish(),
            Self::Status => formatter.write_str("Status"),
            Self::PublishKeyPackage => formatter.write_str("PublishKeyPackage"),
            Self::CreateConversation {
                invitee_key_packages,
                ..
            } => formatter
                .debug_struct("CreateConversation")
                .field("name", &"<redacted>")
                .field("description", &"<redacted>")
                .field("invitee_key_package_count", &invitee_key_packages.len())
                .finish(),
            Self::SendMessage { .. } => formatter
                .debug_struct("SendMessage")
                .field("conversation_id", &"<redacted>")
                .field("created_at", &"<redacted>")
                .field("content", &"<redacted>")
                .finish(),
            Self::IngestEvent { event } => formatter
                .debug_struct("IngestEvent")
                .field("kind", &event.kind)
                .finish(),
            Self::ListConversations { limit } => formatter
                .debug_struct("ListConversations")
                .field("limit", limit)
                .finish(),
            Self::ListMessages { limit, .. } => formatter
                .debug_struct("ListMessages")
                .field("conversation_id", &"<redacted>")
                .field("limit", limit)
                .finish(),
            Self::GetSubscriptionPlan => formatter.write_str("GetSubscriptionPlan"),
            Self::NextAction => formatter.write_str("NextAction"),
            Self::CompleteAction { completion, .. } => formatter
                .debug_struct("CompleteAction")
                .field("action_id", &"<redacted>")
                .field("completion", completion)
                .finish(),
            Self::Shutdown => formatter.write_str("Shutdown"),
        }
    }
}

/// One sidecar response correlated to a [`Request`].
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    /// Protocol version used to encode this response.
    pub version: u16,
    /// Request id copied from the matching request.
    pub request_id: u64,
    /// Successful result or sanitized error.
    #[serde(flatten)]
    pub outcome: ResponseOutcome,
}

impl Response {
    /// Build a successful response using the current protocol version.
    #[must_use]
    pub fn success(request_id: u64, result: ResponseResult) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            outcome: ResponseOutcome::Success { result },
        }
    }

    /// Build a sanitized failure response using the current protocol version.
    #[must_use]
    pub fn failure(request_id: u64, error: RpcError) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            outcome: ResponseOutcome::Failure { error },
        }
    }

    /// Validate fields shared by every response variant.
    pub fn validate(&self) -> Result<(), IpcError> {
        validate_envelope(self.version, self.request_id)?;
        if let ResponseOutcome::Success { result } = &self.outcome {
            result.validate()?;
        }
        Ok(())
    }
}

/// Success or failure returned for a request.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseOutcome {
    /// The operation completed successfully.
    Success {
        /// Variant-specific response body.
        result: ResponseResult,
    },
    /// The operation failed without exposing secret or database internals.
    Failure {
        /// Stable machine code and safe user-facing text.
        error: RpcError,
    },
}

/// Successful response bodies supported by the first protocol version.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseResult {
    /// Handshake metadata and supported operation names.
    Handshake {
        /// Sidecar package version.
        sidecar_version: String,
        /// Stable capability identifiers understood by this sidecar.
        capabilities: Vec<String>,
    },
    /// The encrypted MDK device is ready.
    Initialized {
        /// Lowercase hexadecimal Nostr account public key.
        account_public_key: String,
        /// Whether opening the session emitted effects awaiting integration.
        startup_effects_pending: bool,
    },
    /// Current runtime state.
    Status {
        /// Public, non-secret status description.
        state: RuntimeStatus,
    },
    /// Next queued native operation, or `None` when the queue is empty.
    Action {
        /// Exact action payload. The client must not rebuild signed events.
        action: Option<NativeAction>,
    },
    /// A fresh KeyPackage was generated and queued for exact publication.
    KeyPackageQueued,
    /// A local encrypted conversation was staged for Welcome publication.
    ConversationCreated {
        /// Sanitized pending conversation summary.
        conversation: ConversationSummary,
    },
    /// A text message was accepted by MDK for publication or durable queuing.
    MessageQueued {
        /// Sanitized local outgoing projection for immediate UI display.
        message: MessageSummary,
        /// Whether MDK queued the send behind an in-flight state transition.
        queued_behind_transition: bool,
    },
    /// One inbound transport event was classified and its effects absorbed.
    EventIngested {
        /// Sanitized MDK ingest classification.
        outcome: IngestOutcome,
        /// Number of valid decrypted chat messages added to the projection.
        delivered_messages: u16,
        /// Number of malformed or unsupported inner messages not projected.
        rejected_messages: u16,
        /// Newly joined encrypted conversations, if this was a Welcome.
        joined_conversations: Vec<ConversationSummary>,
        /// Opaque conversations changed by the ingest operation.
        changed_conversation_ids: Vec<String>,
        /// Opaque messages added by the ingest operation.
        changed_message_ids: Vec<String>,
    },
    /// Sanitized local encrypted conversations.
    Conversations {
        /// At most the requested bounded number of summaries.
        conversations: Vec<ConversationSummary>,
    },
    /// Sanitized locally projected decrypted chat messages.
    Messages {
        /// Opaque conversation identifier copied from the request.
        conversation_id: String,
        /// At most the requested bounded number of messages.
        messages: Vec<MessageSummary>,
    },
    /// Exact native-only Marmot routes for active local conversations.
    SubscriptionPlan {
        /// Bounded exact kind `445` subscriptions. Never expose these to React.
        routes: Vec<NativeSubscriptionRoute>,
    },
    /// The response has been flushed and the process will exit.
    ShuttingDown,
}

impl fmt::Debug for ResponseResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake {
                sidecar_version,
                capabilities,
            } => formatter
                .debug_struct("Handshake")
                .field("sidecar_version", sidecar_version)
                .field("capabilities", capabilities)
                .finish(),
            Self::Initialized {
                startup_effects_pending,
                ..
            } => formatter
                .debug_struct("Initialized")
                .field("account_public_key", &"<redacted>")
                .field("startup_effects_pending", startup_effects_pending)
                .finish(),
            Self::Status { state } => formatter
                .debug_struct("Status")
                .field("state", state)
                .finish(),
            Self::Action { action } => formatter
                .debug_struct("Action")
                .field("present", &action.is_some())
                .finish(),
            Self::KeyPackageQueued => formatter.write_str("KeyPackageQueued"),
            Self::ConversationCreated { conversation } => formatter
                .debug_struct("ConversationCreated")
                .field("conversation", conversation)
                .finish(),
            Self::MessageQueued {
                message,
                queued_behind_transition,
            } => formatter
                .debug_struct("MessageQueued")
                .field("message", message)
                .field("queued_behind_transition", queued_behind_transition)
                .finish(),
            Self::EventIngested {
                outcome,
                delivered_messages,
                rejected_messages,
                joined_conversations,
                changed_conversation_ids,
                changed_message_ids,
            } => formatter
                .debug_struct("EventIngested")
                .field("outcome", outcome)
                .field("delivered_messages", delivered_messages)
                .field("rejected_messages", rejected_messages)
                .field("joined_conversation_count", &joined_conversations.len())
                .field(
                    "changed_conversation_count",
                    &changed_conversation_ids.len(),
                )
                .field("changed_message_count", &changed_message_ids.len())
                .finish(),
            Self::Conversations { conversations } => formatter
                .debug_struct("Conversations")
                .field("count", &conversations.len())
                .finish(),
            Self::Messages { messages, .. } => formatter
                .debug_struct("Messages")
                .field("conversation_id", &"<redacted>")
                .field("count", &messages.len())
                .finish(),
            Self::SubscriptionPlan { routes } => formatter
                .debug_struct("SubscriptionPlan")
                .field("route_count", &routes.len())
                .finish(),
            Self::ShuttingDown => formatter.write_str("ShuttingDown"),
        }
    }
}

impl ResponseResult {
    fn validate(&self) -> Result<(), IpcError> {
        match self {
            Self::Handshake {
                sidecar_version,
                capabilities,
            } => {
                validate_bounded_text(sidecar_version, MAX_CLIENT_NAME_BYTES, true)?;
                if capabilities.len() > 32 {
                    return Err(IpcError::InvalidField);
                }
                for capability in capabilities {
                    validate_bounded_text(capability, MAX_CLIENT_NAME_BYTES, true)?;
                }
                Ok(())
            }
            Self::Initialized {
                account_public_key, ..
            } => validate_public_key(account_public_key),
            Self::Status { state } => state.validate(),
            Self::Action { action } => {
                if let Some(action) = action {
                    action.validate()?;
                }
                Ok(())
            }
            Self::KeyPackageQueued | Self::ShuttingDown => Ok(()),
            Self::ConversationCreated { conversation } => conversation.validate(),
            Self::MessageQueued { message, .. } => message.validate(),
            Self::EventIngested {
                joined_conversations,
                changed_conversation_ids,
                changed_message_ids,
                ..
            } => {
                if joined_conversations.len() > MAX_INVITEE_KEY_PACKAGES {
                    return Err(IpcError::InvalidField);
                }
                joined_conversations
                    .iter()
                    .try_for_each(ConversationSummary::validate)?;
                validate_changed_ids(changed_conversation_ids, validate_conversation_id)?;
                validate_changed_ids(changed_message_ids, validate_message_id)
            }
            Self::Conversations { conversations } => {
                if conversations.len() > usize::from(MAX_CONVERSATION_LIST_LIMIT) {
                    return Err(IpcError::InvalidField);
                }
                conversations
                    .iter()
                    .try_for_each(ConversationSummary::validate)
            }
            Self::Messages {
                conversation_id,
                messages,
            } => {
                validate_conversation_id(conversation_id)?;
                if messages.len() > usize::from(MAX_MESSAGE_LIST_LIMIT) {
                    return Err(IpcError::InvalidField);
                }
                messages.iter().try_for_each(MessageSummary::validate)
            }
            Self::SubscriptionPlan { routes } => {
                if routes.len() > MAX_SUBSCRIPTION_ROUTES {
                    return Err(IpcError::InvalidField);
                }
                routes
                    .iter()
                    .try_for_each(NativeSubscriptionRoute::validate)
            }
        }
    }
}

/// One exact native-only kind `445` Marmot subscription route.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeSubscriptionRoute {
    /// Opaque conversation identifier associated with the route.
    pub conversation_id: String,
    /// Lowercase hexadecimal `h` tag route authenticated by group state.
    pub route: String,
}

impl fmt::Debug for NativeSubscriptionRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSubscriptionRoute")
            .field("conversation_id", &"<redacted>")
            .field("route", &"<redacted>")
            .finish()
    }
}

impl NativeSubscriptionRoute {
    fn validate(&self) -> Result<(), IpcError> {
        validate_conversation_id(&self.conversation_id)?;
        validate_hex_32(&self.route)
    }
}

/// Sanitized state of one encrypted conversation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationState {
    /// The group exists only as a staged MDK transition awaiting publication.
    PendingPublication,
    /// MDK has applied the authenticated group state locally.
    Ready,
}

/// Sanitized encrypted conversation data safe for the Tauri application layer.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConversationSummary {
    /// Opaque sidecar-generated identifier; never an MLS or Nostr routing id.
    pub conversation_id: String,
    /// MLS-authenticated group name.
    pub name: String,
    /// MLS-authenticated group description.
    pub description: String,
    /// Current locally applied MLS epoch.
    pub epoch: u64,
    /// Current authenticated member count.
    pub member_count: u32,
    /// Whether founding publication has been confirmed locally.
    pub state: ConversationState,
}

impl fmt::Debug for ConversationSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationSummary")
            .field("conversation_id", &"<redacted>")
            .field("name", &"<redacted>")
            .field("description", &"<redacted>")
            .field("epoch", &self.epoch)
            .field("member_count", &self.member_count)
            .field("state", &self.state)
            .finish()
    }
}

impl ConversationSummary {
    fn validate(&self) -> Result<(), IpcError> {
        validate_conversation_id(&self.conversation_id)?;
        validate_bounded_text(&self.name, MAX_CONVERSATION_NAME_BYTES, true)?;
        validate_optional_bounded_text(
            &self.description,
            MAX_CONVERSATION_DESCRIPTION_BYTES,
            true,
        )?;
        if self.member_count == 0 {
            return Err(IpcError::InvalidField);
        }
        Ok(())
    }
}

/// One sanitized, MLS-authenticated decrypted chat message.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MessageSummary {
    /// Opaque sidecar-generated message identifier.
    pub message_id: String,
    /// Opaque sidecar-generated conversation identifier.
    pub conversation_id: String,
    /// Nostr account public key authenticated by the MLS member leaf.
    pub author_public_key: String,
    /// Inner application event timestamp in Unix seconds.
    pub created_at: u64,
    /// Decrypted text content.
    pub content: String,
    /// Coarse local delivery state for preview rendering.
    pub delivery: MessageDeliveryState,
}

impl fmt::Debug for MessageSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageSummary")
            .field("message_id", &"<redacted>")
            .field("conversation_id", &"<redacted>")
            .field("author_public_key", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("content", &"<redacted>")
            .field("delivery", &self.delivery)
            .finish()
    }
}

/// Coarse message delivery state exposed to the debug-only desktop preview.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageDeliveryState {
    /// Locally encrypted and waiting for, or undergoing, exact publication.
    PendingPublication,
    /// Authenticated and decrypted from a received Marmot transport event.
    Received,
}

impl MessageSummary {
    fn validate(&self) -> Result<(), IpcError> {
        validate_message_id(&self.message_id)?;
        validate_conversation_id(&self.conversation_id)?;
        validate_public_key(&self.author_public_key)?;
        if self.created_at == 0 {
            return Err(IpcError::InvalidField);
        }
        validate_bounded_text(&self.content, MAX_MESSAGE_CONTENT_BYTES, true)
    }
}

/// Sanitized classification of one inbound Marmot transport event.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum IngestOutcome {
    /// MDK validated and applied the event.
    Processed,
    /// MDK retained the event until an in-flight state transition resolves.
    Buffered,
    /// MDK classified the event as stale or not applicable locally.
    Stale {
        /// Coarse stable reason without raw protocol identifiers.
        reason: StaleReason,
    },
}

/// Sanitized stale-input reasons exposed across native IPC.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StaleReason {
    /// The exact transport message was already processed.
    AlreadySeen,
    /// Local state is already at or beyond the message epoch.
    AlreadyAtEpoch,
    /// A Welcome was addressed to another account.
    NotForThisClient,
    /// No local group matches the event routing state.
    UnknownGroup,
    /// The event is this account's own echoed commit.
    OwnEcho,
    /// The transport envelope could not be peeled in current state.
    PeelFailed,
    /// Authenticated group state records this account as removed.
    SelfEvicted,
    /// The group is locally quarantined pending repair.
    Quarantined,
}

/// A side effect prepared by native MDK and awaiting client execution.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeAction {
    /// Publish the exact signed event to a bounded relay set.
    PublishExactEvent {
        /// Opaque native id used to correlate completion and retry.
        action_id: String,
        /// Fully signed NIP-01 event. The client publishes these exact fields.
        event: SignedNostrEvent,
        /// Validated, unique relay endpoints.
        relay_endpoints: Vec<String>,
        /// Number of definite relay acceptances required for success.
        required_acks: u16,
    },
}

impl fmt::Debug for NativeAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublishExactEvent {
                event,
                relay_endpoints,
                required_acks,
                ..
            } => formatter
                .debug_struct("PublishExactEvent")
                .field("action_id", &"<redacted>")
                .field("event", event)
                .field("relay_endpoint_count", &relay_endpoints.len())
                .field("required_acks", required_acks)
                .finish(),
        }
    }
}

impl NativeAction {
    /// Validate all bounds and cryptographic event invariants.
    pub fn validate(&self) -> Result<(), IpcError> {
        match self {
            Self::PublishExactEvent {
                action_id,
                event,
                relay_endpoints,
                required_acks,
            } => {
                validate_action_id(action_id)?;
                event.validate()?;
                validate_relay_endpoints(relay_endpoints)?;
                if *required_acks == 0 || usize::from(*required_acks) > relay_endpoints.len() {
                    return Err(IpcError::InvalidField);
                }
                Ok(())
            }
        }
    }

    /// Return the opaque action identifier.
    #[must_use]
    pub fn action_id(&self) -> &str {
        match self {
            Self::PublishExactEvent { action_id, .. } => action_id,
        }
    }
}

/// Exact signed Nostr event representation carried across native IPC.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedNostrEvent {
    /// Lowercase 32-byte NIP-01 event id.
    pub id: String,
    /// Lowercase 32-byte Schnorr public key.
    pub pubkey: String,
    /// NIP-01 timestamp in Unix seconds.
    pub created_at: u64,
    /// NIP-01 event kind.
    pub kind: u16,
    /// Ordered event tags covered by the signature.
    pub tags: Vec<Vec<String>>,
    /// Exact event content covered by the signature.
    pub content: String,
    /// Lowercase 64-byte BIP-340 Schnorr signature.
    pub sig: String,
}

impl fmt::Debug for SignedNostrEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedNostrEvent")
            .field("id", &"<redacted>")
            .field("pubkey", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("kind", &self.kind)
            .field("tag_count", &self.tags.len())
            .field("content_bytes", &self.content.len())
            .field("sig", &"<redacted>")
            .finish()
    }
}

impl SignedNostrEvent {
    /// Copy exact signed fields from a verified-or-unverified SDK event.
    ///
    /// Call [`Self::validate`] before enqueueing the result. This constructor
    /// intentionally does not imply that the input was already verified.
    #[must_use]
    pub fn from_nostr_event(event: &Event) -> Self {
        Self {
            id: event.id.to_hex(),
            pubkey: event.pubkey.to_hex(),
            created_at: event.created_at.as_secs(),
            kind: event.kind.as_u16(),
            tags: event
                .tags
                .iter()
                .map(|tag| tag.as_slice().to_vec())
                .collect(),
            content: event.content.clone(),
            sig: event.sig.to_string(),
        }
    }

    /// Validate structural bounds, canonical hex fields, NIP-01 id, and the
    /// Schnorr signature without rewriting any signed field.
    pub fn validate(&self) -> Result<(), IpcError> {
        self.to_verified_nostr_event().map(|_| ())
    }

    /// Parse these exact fields into a verified Nostr SDK event.
    ///
    /// The returned event is equivalent at the signed NIP-01 field boundary;
    /// callers must publish it without rebuilding or re-signing it.
    pub fn to_verified_nostr_event(&self) -> Result<Event, IpcError> {
        if !is_lower_hex(&self.id, 64)
            || !is_lower_hex(&self.pubkey, 64)
            || !is_lower_hex(&self.sig, 128)
            || self.content.len() > MAX_NOSTR_CONTENT_BYTES
            || self.tags.len() > MAX_NOSTR_TAGS
            || self.tags.iter().any(|tag| {
                tag.is_empty()
                    || tag.len() > MAX_NOSTR_TAG_ITEMS
                    || tag.iter().any(|item| item.len() > MAX_NOSTR_TAG_ITEM_BYTES)
            })
        {
            return Err(IpcError::InvalidField);
        }

        let event =
            Event::from_json(serde_json::to_vec(self)?).map_err(|_| IpcError::InvalidField)?;
        event.verify().map_err(|_| IpcError::InvalidField)?;
        Ok(event)
    }
}

/// Client report for one native action.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionCompletion {
    /// Every endpoint outcome is known. The sidecar correlates this exact set
    /// with the queued action before resolving MDK state.
    Definite {
        /// Unique endpoint reports.
        endpoint_reports: Vec<RelayPublishReport>,
    },
    /// Publication may or may not have reached a relay. MDK state must remain
    /// unresolved and the exact signed action must be retried.
    Ambiguous,
}

impl ActionCompletion {
    /// Validate report counts, endpoints, uniqueness, and bounded details.
    pub fn validate(&self) -> Result<(), IpcError> {
        let Self::Definite { endpoint_reports } = self else {
            return Ok(());
        };
        if endpoint_reports.is_empty() || endpoint_reports.len() > MAX_RELAY_ENDPOINTS {
            return Err(IpcError::InvalidField);
        }

        let mut endpoints = BTreeSet::new();
        for report in endpoint_reports {
            validate_relay_endpoint(&report.relay_endpoint)?;
            if !endpoints.insert(report.relay_endpoint.as_str()) {
                return Err(IpcError::InvalidField);
            }
            report.outcome.validate()?;
        }
        Ok(())
    }
}

/// Definite publication outcome for one relay endpoint.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayPublishReport {
    /// Exact endpoint copied from the native action.
    pub relay_endpoint: String,
    /// Definite relay result.
    pub outcome: RelayPublishOutcome,
}

/// Definite result returned by one relay publish attempt.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayPublishOutcome {
    /// The relay acknowledged the event.
    Accepted,
    /// The relay definitively rejected the event.
    Rejected {
        /// Optional bounded relay-provided diagnostic.
        detail: Option<String>,
    },
    /// The request definitively failed before publication could succeed.
    Failed {
        /// Optional bounded local transport diagnostic.
        detail: Option<String>,
    },
}

impl RelayPublishOutcome {
    fn validate(&self) -> Result<(), IpcError> {
        let detail = match self {
            Self::Accepted => return Ok(()),
            Self::Rejected { detail } | Self::Failed { detail } => detail,
        };
        if detail.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_RELAY_REPORT_DETAIL_BYTES
                || value.as_bytes().contains(&0)
        }) {
            return Err(IpcError::InvalidField);
        }
        Ok(())
    }
}

/// Public sidecar runtime state.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeStatus {
    /// No MDK database is open.
    Uninitialized,
    /// The encrypted MDK device is open for one Nostr account.
    Ready {
        /// Lowercase hexadecimal Nostr account public key.
        account_public_key: String,
    },
    /// The database opened, but recovery effects must be drained before use.
    RecoveryRequired {
        /// Lowercase hexadecimal Nostr account public key.
        account_public_key: String,
    },
}

impl fmt::Debug for RuntimeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => formatter.write_str("Uninitialized"),
            Self::Ready { .. } => formatter
                .debug_struct("Ready")
                .field("account_public_key", &"<redacted>")
                .finish(),
            Self::RecoveryRequired { .. } => formatter
                .debug_struct("RecoveryRequired")
                .field("account_public_key", &"<redacted>")
                .finish(),
        }
    }
}

impl RuntimeStatus {
    fn validate(&self) -> Result<(), IpcError> {
        match self {
            Self::Uninitialized => Ok(()),
            Self::Ready { account_public_key } | Self::RecoveryRequired { account_public_key } => {
                validate_public_key(account_public_key)
            }
        }
    }
}

/// Stable sidecar error returned over IPC.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcError {
    /// Machine-readable error category.
    pub code: RpcErrorCode,
    /// Sanitized explanation suitable for logs and UI surfaces.
    pub message: String,
}

impl RpcError {
    /// Build a sanitized RPC error.
    #[must_use]
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Stable error categories returned by the sidecar.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    /// The request uses a protocol version this build does not support.
    UnsupportedVersion,
    /// The request is malformed or violates protocol sequencing.
    InvalidRequest,
    /// The client must complete a handshake before this operation.
    HandshakeRequired,
    /// A Marmot runtime is already open in this process.
    AlreadyInitialized,
    /// SQLCipher or MDK initialization failed; details are intentionally hidden.
    InitializationFailed,
    /// A stateful native operation failed without exposing cryptographic detail.
    OperationFailed,
}

/// Incrementally extracts length-prefixed payloads from fragmented input.
pub struct FrameDecoder {
    header: [u8; 4],
    header_len: usize,
    expected_payload_len: Option<usize>,
    payload: Zeroizing<Vec<u8>>,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self {
            header: [0; 4],
            header_len: 0,
            expected_payload_len: None,
            payload: Zeroizing::new(Vec::new()),
        }
    }
}

impl Drop for FrameDecoder {
    fn drop(&mut self) {
        self.header.zeroize();
        self.payload.zeroize();
    }
}

impl FrameDecoder {
    /// Create an empty frame decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add bytes and return every complete JSON payload now available.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Zeroizing<Vec<u8>>>, IpcError> {
        let mut frames = Vec::new();
        let mut offset = 0;

        while offset < bytes.len() {
            if self.expected_payload_len.is_none() {
                let header_bytes = (4 - self.header_len).min(bytes.len() - offset);
                self.header[self.header_len..self.header_len + header_bytes]
                    .copy_from_slice(&bytes[offset..offset + header_bytes]);
                self.header_len += header_bytes;
                offset += header_bytes;
                if self.header_len < 4 {
                    continue;
                }

                let length = u32::from_be_bytes(self.header) as usize;
                if length > MAX_FRAME_SIZE {
                    return Err(IpcError::FrameTooLarge);
                }
                self.expected_payload_len = Some(length);
                self.payload.reserve(length);
            }

            let expected = self.expected_payload_len.unwrap_or_default();
            let payload_bytes = (expected - self.payload.len()).min(bytes.len() - offset);
            self.payload
                .extend_from_slice(&bytes[offset..offset + payload_bytes]);
            offset += payload_bytes;

            if self.payload.len() == expected {
                frames.push(Zeroizing::new(mem::take(&mut *self.payload)));
                self.header.zeroize();
                self.header_len = 0;
                self.expected_payload_len = None;
            }
        }

        Ok(frames)
    }

    /// Whether no partial frame bytes are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.header_len == 0 && self.expected_payload_len.is_none() && self.payload.is_empty()
    }
}

/// Encode a serializable value as one length-prefixed JSON frame.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let payload = Zeroizing::new(serde_json::to_vec(value)?);
    if payload.len() > MAX_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge);
    }

    let length = u32::try_from(payload.len()).map_err(|_| IpcError::FrameTooLarge)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode one already-extracted JSON payload.
pub fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, IpcError> {
    Ok(serde_json::from_slice(payload)?)
}

fn validate_envelope(version: u16, request_id: u64) -> Result<(), IpcError> {
    if version != PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedVersion { received: version });
    }
    if request_id == 0 {
        return Err(IpcError::InvalidRequestId);
    }
    Ok(())
}

fn validate_bounded_text(value: &str, max_bytes: usize, reject_nul: bool) -> Result<(), IpcError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || (reject_nul && value.as_bytes().contains(&0))
    {
        return Err(IpcError::InvalidField);
    }
    Ok(())
}

fn validate_optional_bounded_text(
    value: &str,
    max_bytes: usize,
    reject_nul: bool,
) -> Result<(), IpcError> {
    if value.len() > max_bytes || (reject_nul && value.as_bytes().contains(&0)) {
        return Err(IpcError::InvalidField);
    }
    Ok(())
}

fn validate_limit(limit: u16, max: u16) -> Result<(), IpcError> {
    if limit == 0 || limit > max {
        return Err(IpcError::InvalidField);
    }
    Ok(())
}

fn validate_conversation_id(value: &str) -> Result<(), IpcError> {
    validate_prefixed_opaque_id(value, CONVERSATION_ID_PREFIX)
}

fn validate_message_id(value: &str) -> Result<(), IpcError> {
    validate_prefixed_opaque_id(value, MESSAGE_ID_PREFIX)
}

fn validate_prefixed_opaque_id(value: &str, prefix: &str) -> Result<(), IpcError> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(IpcError::InvalidField);
    };
    if value.len() > MAX_CONVERSATION_ID_BYTES || !is_lower_hex(suffix, 64) {
        return Err(IpcError::InvalidField);
    }
    Ok(())
}

fn validate_public_key(value: &str) -> Result<(), IpcError> {
    validate_hex_32(value)
}

fn validate_hex_32(value: &str) -> Result<(), IpcError> {
    if !is_lower_hex(value, 64) {
        return Err(IpcError::InvalidField);
    }
    Ok(())
}

fn validate_changed_ids(
    values: &[String],
    validate: fn(&str) -> Result<(), IpcError>,
) -> Result<(), IpcError> {
    if values.len() > MAX_CHANGED_IDS {
        return Err(IpcError::InvalidField);
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate(value)?;
        if !unique.insert(value.as_str()) {
            return Err(IpcError::InvalidField);
        }
    }
    Ok(())
}

fn validate_action_id(action_id: &str) -> Result<(), IpcError> {
    validate_bounded_text(action_id, MAX_ACTION_ID_BYTES, true)
}

fn validate_relay_endpoints(endpoints: &[String]) -> Result<(), IpcError> {
    if endpoints.is_empty() || endpoints.len() > MAX_RELAY_ENDPOINTS {
        return Err(IpcError::InvalidField);
    }
    let mut unique = BTreeSet::new();
    for endpoint in endpoints {
        validate_relay_endpoint(endpoint)?;
        if !unique.insert(endpoint.as_str()) {
            return Err(IpcError::InvalidField);
        }
    }
    Ok(())
}

fn validate_relay_endpoint(endpoint: &str) -> Result<(), IpcError> {
    if endpoint.is_empty() || endpoint.len() > MAX_RELAY_ENDPOINT_BYTES {
        return Err(IpcError::InvalidField);
    }
    let url = Url::parse(endpoint).map_err(|_| IpcError::InvalidField)?;
    if !matches!(url.scheme(), "ws" | "wss")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(IpcError::InvalidField);
    }
    Ok(())
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    fn signed_event() -> SignedNostrEvent {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("valid test key");
        let event = EventBuilder::new(Kind::Custom(445), "opaque ciphertext")
            .tags([
                Tag::parse(["h", &"11".repeat(32)]).expect("h tag"),
                Tag::parse(["expiration", "1900000000"]).expect("expiration tag"),
            ])
            .sign_with_keys(&keys)
            .expect("sign test event");
        SignedNostrEvent::from_nostr_event(&event)
    }

    fn signed_event_of_kind(kind: u16) -> SignedNostrEvent {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000002")
            .expect("valid test key");
        let event = EventBuilder::new(Kind::Custom(kind), "opaque transport content")
            .sign_with_keys(&keys)
            .expect("sign test event");
        SignedNostrEvent::from_nostr_event(&event)
    }

    fn conversation_id() -> String {
        format!("{CONVERSATION_ID_PREFIX}{}", "ab".repeat(32))
    }

    fn message_id() -> String {
        format!("{MESSAGE_ID_PREFIX}{}", "cd".repeat(32))
    }

    fn publish_action() -> NativeAction {
        NativeAction::PublishExactEvent {
            action_id: "publish-0001".into(),
            event: signed_event(),
            relay_endpoints: vec![
                "wss://relay-one.example".into(),
                "wss://relay-two.example/path".into(),
            ],
            required_acks: 1,
        }
    }

    #[test]
    fn decoder_accepts_fragmented_and_coalesced_frames() {
        let first = encode_frame(&Request::new(
            1,
            Command::Handshake {
                client_name: "test".into(),
            },
        ))
        .expect("encode first frame");
        let second = encode_frame(&Request::new(2, Command::Status)).expect("encode second frame");
        let split = first.len() / 2;
        let mut decoder = FrameDecoder::new();

        assert!(decoder
            .push(&first[..split])
            .expect("partial frame")
            .is_empty());
        let mut remainder = first[split..].to_vec();
        remainder.extend_from_slice(&second);
        let frames = decoder.push(&remainder).expect("complete frames");

        assert_eq!(frames.len(), 2);
        let request: Request = decode_payload(&frames[0]).expect("decode first request");
        assert_eq!(request.request_id, 1);
        let request: Request = decode_payload(&frames[1]).expect("decode second request");
        assert_eq!(request.request_id, 2);
        assert!(decoder.is_empty());
    }

    #[test]
    fn decoder_rejects_advertised_oversize_before_body_arrives() {
        let mut decoder = FrameDecoder::new();
        let length = u32::try_from(MAX_FRAME_SIZE + 1).expect("test size fits u32");
        assert!(matches!(
            decoder.push(&length.to_be_bytes()),
            Err(IpcError::FrameTooLarge)
        ));
    }

    #[test]
    fn encoder_rejects_oversize_payload() {
        let value = "x".repeat(MAX_FRAME_SIZE + 1);
        assert!(matches!(encode_frame(&value), Err(IpcError::FrameTooLarge)));
    }

    #[test]
    fn envelope_rejects_unknown_version_and_zero_request_id() {
        let mut request = Request::new(1, Command::Status);
        request.version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            request.validate(),
            Err(IpcError::UnsupportedVersion { .. })
        ));

        let request = Request::new(0, Command::Status);
        assert!(matches!(
            request.validate(),
            Err(IpcError::InvalidRequestId)
        ));
    }

    #[test]
    fn request_validation_bounds_client_names_and_database_paths() {
        let request = Request::new(
            1,
            Command::Handshake {
                client_name: "x".repeat(MAX_CLIENT_NAME_BYTES + 1),
            },
        );
        assert!(matches!(request.validate(), Err(IpcError::InvalidField)));

        let request = Request::new(
            1,
            Command::Initialize {
                database_path: format!("valid\0{}", "x".repeat(MAX_DATABASE_PATH_BYTES)),
                database_key: SecretBytes32::new([1; 32]),
                account_secret_key: SecretBytes32::new([2; 32]),
                relay_endpoint: "wss://relay.example".into(),
            },
        );
        assert!(matches!(request.validate(), Err(IpcError::InvalidField)));

        let request = Request::new(
            2,
            Command::Initialize {
                database_path: "relative/marmot.sqlite3".into(),
                database_key: SecretBytes32::new([1; 32]),
                account_secret_key: SecretBytes32::new([2; 32]),
                relay_endpoint: "wss://relay.example".into(),
            },
        );
        assert!(matches!(request.validate(), Err(IpcError::InvalidField)));
    }

    #[test]
    fn decoder_handles_many_coalesced_frames_without_an_unbounded_input_buffer() {
        let frame = encode_frame(&Request::new(1, Command::Status)).expect("encode frame");
        let mut input = Vec::new();
        for _ in 0..2_000 {
            input.extend_from_slice(&frame);
        }

        let mut decoder = FrameDecoder::new();
        let frames = decoder.push(&input).expect("decode coalesced frames");
        assert_eq!(frames.len(), 2_000);
        assert!(decoder.is_empty());
        assert!(decoder.payload.capacity() <= MAX_FRAME_SIZE);
    }

    #[test]
    fn request_json_rejects_unknown_fields() {
        let payload = br#"{
            "version":1,
            "request_id":1,
            "command":{"type":"status"},
            "unexpected":"value"
        }"#;
        assert!(matches!(
            decode_payload::<Request>(payload),
            Err(IpcError::Json(_))
        ));
    }

    #[test]
    fn secret_debug_is_always_redacted() {
        let secret = SecretBytes32::new([0xA5; 32]);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretBytes32(<redacted>)");
        assert!(!rendered.contains("165"));

        let request = Request::new(
            9,
            Command::Initialize {
                database_path: "/tmp/marmot.sqlite3".into(),
                database_key: SecretBytes32::new([0xA5; 32]),
                account_secret_key: SecretBytes32::new([0x5A; 32]),
                relay_endpoint: "wss://relay.example".into(),
            },
        );
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("165"));
        assert!(!rendered.contains("90"));
    }

    #[test]
    fn exact_publish_action_round_trips_and_validates_signature() {
        let response = Response::success(
            17,
            ResponseResult::Action {
                action: Some(publish_action()),
            },
        );
        response.validate().expect("valid native action");

        let frame = encode_frame(&response).expect("encode action frame");
        let mut decoder = FrameDecoder::new();
        let frames = decoder.push(&frame).expect("decode action frame");
        let decoded: Response = decode_payload(&frames[0]).expect("decode action response");
        decoded
            .validate()
            .expect("round-tripped action remains valid");
        assert_eq!(decoded, response);
    }

    #[test]
    fn signed_event_rejects_malformed_or_mismatched_id_and_signature() {
        let mut malformed_id = signed_event();
        malformed_id.id = "AA".repeat(32);
        assert!(matches!(
            malformed_id.validate(),
            Err(IpcError::InvalidField)
        ));

        let mut malformed_signature = signed_event();
        malformed_signature.sig = "0".repeat(127);
        assert!(matches!(
            malformed_signature.validate(),
            Err(IpcError::InvalidField)
        ));

        let mut mismatched_signature = signed_event();
        mismatched_signature.content.push('!');
        assert!(matches!(
            mismatched_signature.validate(),
            Err(IpcError::InvalidField)
        ));
    }

    #[test]
    fn native_action_rejects_id_endpoint_and_ack_bound_violations() {
        let mut action = publish_action();
        let NativeAction::PublishExactEvent { action_id, .. } = &mut action;
        *action_id = "x".repeat(MAX_ACTION_ID_BYTES + 1);
        assert!(matches!(action.validate(), Err(IpcError::InvalidField)));

        let mut action = publish_action();
        let NativeAction::PublishExactEvent {
            relay_endpoints, ..
        } = &mut action;
        relay_endpoints.push(relay_endpoints[0].clone());
        assert!(matches!(action.validate(), Err(IpcError::InvalidField)));

        let mut action = publish_action();
        let NativeAction::PublishExactEvent {
            relay_endpoints, ..
        } = &mut action;
        relay_endpoints[0] = "https://not-a-nostr-relay.example".into();
        assert!(matches!(action.validate(), Err(IpcError::InvalidField)));

        let mut action = publish_action();
        let NativeAction::PublishExactEvent { required_acks, .. } = &mut action;
        *required_acks = 3;
        assert!(matches!(action.validate(), Err(IpcError::InvalidField)));
    }

    #[test]
    fn complete_action_distinguishes_definite_reports_from_ambiguous_retry() {
        let definite = Request::new(
            21,
            Command::CompleteAction {
                action_id: "publish-0001".into(),
                completion: ActionCompletion::Definite {
                    endpoint_reports: vec![
                        RelayPublishReport {
                            relay_endpoint: "wss://relay-one.example".into(),
                            outcome: RelayPublishOutcome::Accepted,
                        },
                        RelayPublishReport {
                            relay_endpoint: "wss://relay-two.example/path".into(),
                            outcome: RelayPublishOutcome::Rejected {
                                detail: Some("policy rejected".into()),
                            },
                        },
                    ],
                },
            },
        );
        definite.validate().expect("definite endpoint report");

        let ambiguous = Request::new(
            22,
            Command::CompleteAction {
                action_id: "publish-0001".into(),
                completion: ActionCompletion::Ambiguous,
            },
        );
        ambiguous
            .validate()
            .expect("ambiguous completion requests an exact retry");

        let duplicate = Request::new(
            23,
            Command::CompleteAction {
                action_id: "publish-0001".into(),
                completion: ActionCompletion::Definite {
                    endpoint_reports: vec![
                        RelayPublishReport {
                            relay_endpoint: "wss://relay.example".into(),
                            outcome: RelayPublishOutcome::Accepted,
                        },
                        RelayPublishReport {
                            relay_endpoint: "wss://relay.example".into(),
                            outcome: RelayPublishOutcome::Failed { detail: None },
                        },
                    ],
                },
            },
        );
        assert!(matches!(duplicate.validate(), Err(IpcError::InvalidField)));
    }

    #[test]
    fn action_frames_remain_subject_to_the_global_size_ceiling() {
        let mut action = publish_action();
        let NativeAction::PublishExactEvent { event, .. } = &mut action;
        event.content = "x".repeat(MAX_FRAME_SIZE);
        let response = Response::success(
            24,
            ResponseResult::Action {
                action: Some(action),
            },
        );
        assert!(matches!(
            encode_frame(&response),
            Err(IpcError::FrameTooLarge)
        ));
    }

    #[test]
    fn domain_requests_enforce_kinds_text_counts_and_page_limits() {
        let valid_create = Request::new(
            30,
            Command::CreateConversation {
                name: "encrypted group".into(),
                description: "private description".into(),
                invitee_key_packages: vec![signed_event_of_kind(30_443)],
            },
        );
        valid_create.validate().expect("bounded creation request");

        let wrong_kind = Request::new(
            31,
            Command::CreateConversation {
                name: "encrypted group".into(),
                description: String::new(),
                invitee_key_packages: vec![signed_event_of_kind(445)],
            },
        );
        assert!(matches!(wrong_kind.validate(), Err(IpcError::InvalidField)));

        let oversized_message = Request::new(
            32,
            Command::SendMessage {
                conversation_id: conversation_id(),
                created_at: 1_700_000_001,
                content: "x".repeat(MAX_MESSAGE_CONTENT_BYTES + 1),
            },
        );
        assert!(matches!(
            oversized_message.validate(),
            Err(IpcError::InvalidField)
        ));

        let invalid_ingest = Request::new(
            33,
            Command::IngestEvent {
                event: signed_event_of_kind(30_443),
            },
        );
        assert!(matches!(
            invalid_ingest.validate(),
            Err(IpcError::InvalidField)
        ));

        let invalid_page = Request::new(
            34,
            Command::ListMessages {
                conversation_id: conversation_id(),
                limit: MAX_MESSAGE_LIST_LIMIT + 1,
            },
        );
        assert!(matches!(
            invalid_page.validate(),
            Err(IpcError::InvalidField)
        ));

        let raw_route_like_id = Request::new(
            35,
            Command::ListMessages {
                conversation_id: "ab".repeat(32),
                limit: 1,
            },
        );
        assert!(matches!(
            raw_route_like_id.validate(),
            Err(IpcError::InvalidField)
        ));
    }

    #[test]
    fn sanitized_domain_results_round_trip_within_frame_bounds() {
        let conversation = ConversationSummary {
            conversation_id: conversation_id(),
            name: "encrypted group".into(),
            description: "private description".into(),
            epoch: 7,
            member_count: 2,
            state: ConversationState::Ready,
        };
        let message = MessageSummary {
            message_id: message_id(),
            conversation_id: conversation.conversation_id.clone(),
            author_public_key: "11".repeat(32),
            created_at: 1_700_000_001,
            content: "private text".into(),
            delivery: MessageDeliveryState::Received,
        };
        let response = Response::success(
            35,
            ResponseResult::Messages {
                conversation_id: conversation.conversation_id.clone(),
                messages: vec![message],
            },
        );
        response.validate().expect("valid message projection");
        let frame = encode_frame(&response).expect("bounded result frame");
        let mut decoder = FrameDecoder::new();
        let frames = decoder.push(&frame).expect("decode result frame");
        let decoded: Response = decode_payload(&frames[0]).expect("domain result JSON");
        decoded.validate().expect("round-tripped domain result");

        let created = Response::success(36, ResponseResult::ConversationCreated { conversation });
        created.validate().expect("valid conversation projection");
    }

    #[test]
    fn native_subscription_plans_are_bounded_validated_and_redacted() {
        Request::new(40, Command::GetSubscriptionPlan)
            .validate()
            .expect("native subscription plan request");
        let conversation_id = conversation_id();
        let route = "ab".repeat(32);
        let response = Response::success(
            41,
            ResponseResult::SubscriptionPlan {
                routes: vec![NativeSubscriptionRoute {
                    conversation_id: conversation_id.clone(),
                    route: route.clone(),
                }],
            },
        );
        response.validate().expect("valid exact route plan");
        let rendered = format!("{response:?}");
        assert!(!rendered.contains(&conversation_id));
        assert!(!rendered.contains(&route));

        let invalid_route = Response::success(
            42,
            ResponseResult::SubscriptionPlan {
                routes: vec![NativeSubscriptionRoute {
                    conversation_id: conversation_id.clone(),
                    route: "AB".repeat(32),
                }],
            },
        );
        assert!(matches!(
            invalid_route.validate(),
            Err(IpcError::InvalidField)
        ));

        let too_many = Response::success(
            43,
            ResponseResult::SubscriptionPlan {
                routes: (0..=MAX_SUBSCRIPTION_ROUTES)
                    .map(|_| NativeSubscriptionRoute {
                        conversation_id: conversation_id.clone(),
                        route: route.clone(),
                    })
                    .collect(),
            },
        );
        assert!(matches!(too_many.validate(), Err(IpcError::InvalidField)));
    }

    #[test]
    fn ingest_change_identifiers_are_bounded_and_unique() {
        let conversation_id = conversation_id();
        let message_id = message_id();
        let valid = Response::success(
            44,
            ResponseResult::EventIngested {
                outcome: IngestOutcome::Processed,
                delivered_messages: 1,
                rejected_messages: 0,
                joined_conversations: Vec::new(),
                changed_conversation_ids: vec![conversation_id.clone()],
                changed_message_ids: vec![message_id.clone()],
            },
        );
        valid.validate().expect("bounded changed identifiers");

        let duplicate = Response::success(
            45,
            ResponseResult::EventIngested {
                outcome: IngestOutcome::Processed,
                delivered_messages: 0,
                rejected_messages: 0,
                joined_conversations: Vec::new(),
                changed_conversation_ids: vec![conversation_id.clone(), conversation_id],
                changed_message_ids: vec![message_id],
            },
        );
        assert!(matches!(duplicate.validate(), Err(IpcError::InvalidField)));
    }

    #[test]
    fn domain_debug_output_redacts_plaintext_and_opaque_identifiers() {
        let name_canary = "group-name-canary";
        let description_canary = "group-description-canary";
        let content_canary = "message-content-canary";
        let conversation_canary = conversation_id();
        let create = Request::new(
            37,
            Command::CreateConversation {
                name: name_canary.into(),
                description: description_canary.into(),
                invitee_key_packages: vec![signed_event_of_kind(30_443)],
            },
        );
        let send = Request::new(
            38,
            Command::SendMessage {
                conversation_id: conversation_canary.clone(),
                created_at: 1_700_000_001,
                content: content_canary.into(),
            },
        );
        let result = Response::success(
            39,
            ResponseResult::Messages {
                conversation_id: conversation_canary.clone(),
                messages: vec![MessageSummary {
                    message_id: message_id(),
                    conversation_id: conversation_canary.clone(),
                    author_public_key: "22".repeat(32),
                    created_at: 1_700_000_001,
                    content: content_canary.into(),
                    delivery: MessageDeliveryState::Received,
                }],
            },
        );

        let rendered = format!("{create:?} {send:?} {result:?}");
        for canary in [
            name_canary,
            description_canary,
            content_canary,
            conversation_canary.as_str(),
            message_id().as_str(),
        ] {
            assert!(!rendered.contains(canary));
        }
        assert!(rendered.contains("<redacted>"));
    }
}
