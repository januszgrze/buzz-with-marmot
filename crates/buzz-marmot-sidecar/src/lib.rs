//! Long-lived native process boundary for the current Marmot MDK runtime.
//!
//! Standard output is reserved exclusively for framed protocol responses.
//! Initialization secrets arrive only inside stdin frames and are never
//! reflected in responses or errors.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::PathBuf,
};

use buzz_marmot::{
    MarmotApplicationMessage, MarmotDatabaseKey, MarmotDevice, MarmotDeviceConfig, MarmotEffects,
    MarmotGroupConfig, MarmotGroupId, MarmotGroupSnapshot, MarmotKeyPackage,
    MarmotPendingPublication,
};
use buzz_marmot_ipc::{
    decode_payload, encode_frame, ActionCompletion, Command, ConversationState,
    ConversationSummary, FrameDecoder, IngestOutcome as IpcIngestOutcome, IpcError,
    MessageDeliveryState, MessageSummary, NativeAction, NativeSubscriptionRoute,
    RelayPublishOutcome, Request, Response, ResponseResult, RpcError, RpcErrorCode, RuntimeStatus,
    SignedNostrEvent, StaleReason as IpcStaleReason, CAPABILITY_EXPERIMENTAL_PREVIEW_V1,
    CONVERSATION_ID_PREFIX, MAX_CHANGED_IDS, MAX_CONVERSATION_DESCRIPTION_BYTES,
    MAX_CONVERSATION_NAME_BYTES, MAX_MESSAGE_CONTENT_BYTES, MAX_SUBSCRIPTION_ROUTES,
    MESSAGE_ID_PREFIX,
};
use cgka_engine::key_package::key_package_metadata;
use cgka_session::PublishWork;
use cgka_traits::{
    app_event::MARMOT_APP_EVENT_KIND_CHAT,
    engine::{GroupEvent, KeyPackage},
    ingest::{IngestOutcome as MdkIngestOutcome, StaleReason as MdkStaleReason},
    transport::TransportMessage,
};
use nostr::base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use nostr::{EventBuilder, Keys, Kind, SecretKey, Tag, TagKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use transport_nostr_peeler::NostrTransportEvent;
use zeroize::{Zeroize, Zeroizing};

/// Fatal transport errors that prevent the sidecar from continuing safely.
#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    /// Reading from stdin or writing to stdout failed.
    #[error("sidecar pipe failed")]
    Io(#[from] std::io::Error),
    /// A frame could not be decoded or encoded safely.
    #[error("sidecar protocol failed")]
    Protocol(#[from] IpcError),
    /// The input pipe ended in the middle of a frame.
    #[error("sidecar input ended with an incomplete frame")]
    TruncatedFrame,
}

#[derive(Debug, thiserror::Error)]
enum ActionDriverError {
    #[error("prepared Marmot event is invalid")]
    InvalidPreparedEvent,
    #[error("Marmot action completion is invalid")]
    InvalidCompletion,
    #[error("Marmot action identifiers are exhausted")]
    ActionIdsExhausted,
    #[error("Marmot effect processing exceeded its bounded step budget")]
    StepBudgetExceeded,
    #[error("Marmot state transition failed")]
    Marmot,
}

enum DriverWork {
    ExactStateless {
        event: SignedNostrEvent,
    },
    Stateless {
        message: TransportMessage,
    },
    AutoPublish {
        message: TransportMessage,
        pending: MarmotPendingPublication,
    },
    GroupEvolution {
        commit: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: MarmotPendingPublication,
    },
    GroupCreated {
        welcomes: VecDeque<TransportMessage>,
        pending: MarmotPendingPublication,
        all_published: bool,
        any_exposed: bool,
    },
    Converge {
        group_id: MarmotGroupId,
    },
}

#[derive(Clone)]
enum ActionContinuation {
    Stateless,
    AutoPublish {
        pending: MarmotPendingPublication,
    },
    GroupEvolution {
        welcomes: Vec<TransportMessage>,
        pending: MarmotPendingPublication,
    },
    GroupCreated {
        remaining: VecDeque<TransportMessage>,
        pending: MarmotPendingPublication,
        all_published: bool,
        any_exposed: bool,
    },
}

#[derive(Clone)]
enum ActionPayload {
    Transport(TransportMessage),
    Exact(SignedNostrEvent),
}

#[derive(Clone)]
struct ActiveAction {
    action: NativeAction,
    payload: ActionPayload,
    continuation: ActionContinuation,
}

struct EffectDriver {
    generation: String,
    next_action_sequence: u64,
    relay_endpoint: String,
    work: VecDeque<DriverWork>,
    active: Option<ActiveAction>,
    unprojected_events: Vec<GroupEvent>,
    queued_intent_count: usize,
    failed_publishes: Vec<TransportMessage>,
    failed_exact_events: Vec<SignedNostrEvent>,
}

impl EffectDriver {
    fn new(relay_endpoint: String) -> Self {
        Self {
            generation: Keys::generate().public_key().to_hex(),
            next_action_sequence: 1,
            relay_endpoint,
            work: VecDeque::new(),
            active: None,
            unprojected_events: Vec::new(),
            queued_intent_count: 0,
            failed_publishes: Vec::new(),
            failed_exact_events: Vec::new(),
        }
    }

    fn absorb(&mut self, effects: MarmotEffects) {
        let convergence = effects.pending_convergence_groups();
        let (events, publish, queued, _) = effects.into_parts();
        self.unprojected_events.extend(events);
        self.queued_intent_count = self.queued_intent_count.saturating_add(queued.len());
        self.work.extend(publish.into_iter().map(|work| match work {
            PublishWork::ApplicationMessage { msg } | PublishWork::Proposal { msg } => {
                DriverWork::Stateless { message: msg }
            }
            PublishWork::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => DriverWork::GroupEvolution {
                commit: msg,
                welcomes,
                pending: MarmotPendingPublication::from_mdk(pending),
            },
            PublishWork::GroupCreated { welcomes, pending } => DriverWork::GroupCreated {
                welcomes: welcomes.into(),
                pending: MarmotPendingPublication::from_mdk(pending),
                all_published: true,
                any_exposed: false,
            },
            PublishWork::AutoPublish { msg, pending } => DriverWork::AutoPublish {
                message: msg,
                pending: MarmotPendingPublication::from_mdk(pending),
            },
        }));
        self.work.extend(
            convergence
                .into_iter()
                .map(|group_id| DriverWork::Converge { group_id }),
        );
    }

    fn has_recovery_work(&self) -> bool {
        self.active.is_some()
            || !self.work.is_empty()
            || !self.unprojected_events.is_empty()
            || self.queued_intent_count != 0
            || !self.failed_publishes.is_empty()
            || !self.failed_exact_events.is_empty()
    }

    fn prepare_action(
        &mut self,
        message: TransportMessage,
        continuation: ActionContinuation,
    ) -> Result<NativeAction, ActionDriverError> {
        let event = NostrTransportEvent::from_transport_message(&message)
            .and_then(|event| event.to_verified_nostr_event())
            .map_err(|_| ActionDriverError::InvalidPreparedEvent)?;
        self.prepare_signed_action(
            SignedNostrEvent::from_nostr_event(&event),
            ActionPayload::Transport(message),
            continuation,
        )
    }

    fn prepare_exact_action(
        &mut self,
        event: SignedNostrEvent,
        continuation: ActionContinuation,
    ) -> Result<NativeAction, ActionDriverError> {
        event
            .validate()
            .map_err(|_| ActionDriverError::InvalidPreparedEvent)?;
        self.prepare_signed_action(event.clone(), ActionPayload::Exact(event), continuation)
    }

    fn prepare_signed_action(
        &mut self,
        event: SignedNostrEvent,
        payload: ActionPayload,
        continuation: ActionContinuation,
    ) -> Result<NativeAction, ActionDriverError> {
        let action_id = format!("{}:{}", self.generation, self.next_action_sequence);
        self.next_action_sequence = self
            .next_action_sequence
            .checked_add(1)
            .ok_or(ActionDriverError::ActionIdsExhausted)?;
        let action = NativeAction::PublishExactEvent {
            action_id,
            event,
            relay_endpoints: vec![self.relay_endpoint.clone()],
            required_acks: 1,
        };
        action
            .validate()
            .map_err(|_| ActionDriverError::InvalidPreparedEvent)?;
        self.active = Some(ActiveAction {
            action: action.clone(),
            payload,
            continuation,
        });
        Ok(action)
    }

    fn prepare_action_or_requeue(
        &mut self,
        message: TransportMessage,
        continuation: ActionContinuation,
        original_work: DriverWork,
    ) -> Result<NativeAction, ActionDriverError> {
        match self.prepare_action(message, continuation) {
            Ok(action) => Ok(action),
            Err(error) => {
                self.prepend(original_work);
                Err(error)
            }
        }
    }

    fn prepare_exact_action_or_requeue(
        &mut self,
        event: SignedNostrEvent,
    ) -> Result<NativeAction, ActionDriverError> {
        match self.prepare_exact_action(event.clone(), ActionContinuation::Stateless) {
            Ok(action) => Ok(action),
            Err(error) => {
                self.prepend(DriverWork::ExactStateless { event });
                Err(error)
            }
        }
    }

    fn restore_active(&mut self, active: ActiveAction) {
        debug_assert!(self.active.is_none());
        self.active = Some(active);
    }

    fn prepend(&mut self, work: DriverWork) {
        self.work.push_front(work);
    }

    fn record_failed(&mut self, payload: ActionPayload) {
        match payload {
            ActionPayload::Transport(message) => self.failed_publishes.push(message),
            ActionPayload::Exact(event) => self.failed_exact_events.push(event),
        }
    }

    fn enqueue_exact_stateless(&mut self, event: SignedNostrEvent) {
        self.work.push_back(DriverWork::ExactStateless { event });
    }

    fn mark_events_projected(&mut self) {
        self.unprojected_events.clear();
    }
}

// Transitional, capability-disabled projection used to exercise the domain
// RPC boundary. It intentionally is not advertised by the handshake until it
// is replaced by the encrypted durable projection/outbox required for UI use.
#[derive(Default)]
struct ProjectionStore {
    conversations: BTreeMap<String, ProjectedConversation>,
    group_to_conversation: BTreeMap<String, String>,
    messages: BTreeMap<String, Vec<MessageSummary>>,
    seen_inner_event_ids: BTreeSet<String>,
}

struct ProjectedConversation {
    group_id: MarmotGroupId,
    summary: ConversationSummary,
}

#[derive(Default)]
struct ProjectionUpdate {
    delivered_messages: usize,
    rejected_messages: usize,
    joined_conversation_ids: Vec<String>,
    changed_conversation_ids: Vec<String>,
    changed_message_ids: Vec<String>,
}

impl ProjectionStore {
    fn insert_pending(
        &mut self,
        group_id: MarmotGroupId,
        name: String,
        description: String,
        member_count: u32,
    ) -> ConversationSummary {
        let conversation_id = self.new_conversation_id();
        let summary = ConversationSummary {
            conversation_id: conversation_id.clone(),
            name,
            description,
            epoch: 0,
            member_count,
            state: ConversationState::PendingPublication,
        };
        self.group_to_conversation
            .insert(group_key(&group_id), conversation_id.clone());
        self.conversations.insert(
            conversation_id,
            ProjectedConversation {
                group_id,
                summary: summary.clone(),
            },
        );
        summary
    }

    fn apply_effects(
        &mut self,
        device: &MarmotDevice,
        effects: &MarmotEffects,
    ) -> ProjectionUpdate {
        let mut update = ProjectionUpdate::default();
        let joined_groups = effects.joined_group_ids();
        for group_id in joined_groups {
            if let Some(conversation_id) = self.refresh_group(device, group_id) {
                if !update.joined_conversation_ids.contains(&conversation_id) {
                    update.joined_conversation_ids.push(conversation_id.clone());
                }
                if update.changed_conversation_ids.len() < MAX_CHANGED_IDS
                    && !update.changed_conversation_ids.contains(&conversation_id)
                {
                    update.changed_conversation_ids.push(conversation_id);
                }
            }
        }

        let existing_group_ids = effects
            .events()
            .iter()
            .filter_map(group_event_id)
            .filter_map(|group_id| {
                let conversation_id = self
                    .group_to_conversation
                    .get(&hex::encode(group_id.as_slice()))?;
                self.conversations
                    .get(conversation_id)
                    .map(|conversation| conversation.group_id.clone())
            })
            .collect::<Vec<_>>();
        for group_id in existing_group_ids {
            if let Some(conversation_id) = self.refresh_group(device, group_id) {
                if update.changed_conversation_ids.len() < MAX_CHANGED_IDS
                    && !update.changed_conversation_ids.contains(&conversation_id)
                {
                    update.changed_conversation_ids.push(conversation_id);
                }
            }
        }

        for decoded in effects.decoded_application_message_results() {
            match decoded {
                Ok(message) if message.kind() == MARMOT_APP_EVENT_KIND_CHAT => {
                    if let Some(message_id) = self.project_message(device, message) {
                        update.delivered_messages = update.delivered_messages.saturating_add(1);
                        if update.changed_message_ids.len() < MAX_CHANGED_IDS {
                            update.changed_message_ids.push(message_id);
                        }
                    } else {
                        update.rejected_messages = update.rejected_messages.saturating_add(1);
                    }
                }
                Ok(_) | Err(_) => {
                    update.rejected_messages = update.rejected_messages.saturating_add(1);
                }
            }
        }

        update
    }

    fn refresh_group(&mut self, device: &MarmotDevice, group_id: MarmotGroupId) -> Option<String> {
        let snapshot = device.group_snapshot(&group_id).ok()?;
        let key = group_key(&group_id);
        let conversation_id = self
            .group_to_conversation
            .get(&key)
            .cloned()
            .unwrap_or_else(|| self.new_conversation_id());
        let summary = summary_from_snapshot(&conversation_id, &snapshot)?;
        self.group_to_conversation
            .insert(key, conversation_id.clone());
        self.conversations.insert(
            conversation_id.clone(),
            ProjectedConversation { group_id, summary },
        );
        Some(conversation_id)
    }

    fn project_message(
        &mut self,
        device: &MarmotDevice,
        message: MarmotApplicationMessage,
    ) -> Option<String> {
        if message.content().is_empty()
            || message.content().len() > MAX_MESSAGE_CONTENT_BYTES
            || message.content().as_bytes().contains(&0)
            || message.created_at() == 0
            || self.seen_inner_event_ids.contains(message.event_id())
        {
            return None;
        }
        let group_id = message.group_id().clone();
        let group_key = group_key(&group_id);
        let conversation_id = self
            .group_to_conversation
            .get(&group_key)
            .cloned()
            .or_else(|| self.refresh_group(device, group_id))?;
        let projected = MessageSummary {
            message_id: new_opaque_id(MESSAGE_ID_PREFIX),
            conversation_id: conversation_id.clone(),
            author_public_key: message.author_public_key().to_owned(),
            created_at: message.created_at(),
            content: message.content().to_owned(),
            delivery: MessageDeliveryState::Received,
        };
        let message_id = projected.message_id.clone();
        self.seen_inner_event_ids
            .insert(message.event_id().to_owned());
        self.messages
            .entry(conversation_id)
            .or_default()
            .push(projected);
        Some(message_id)
    }

    fn insert_outgoing(
        &mut self,
        conversation_id: &str,
        author_public_key: &str,
        created_at: u64,
        content: String,
    ) -> MessageSummary {
        let message = MessageSummary {
            message_id: new_opaque_id(MESSAGE_ID_PREFIX),
            conversation_id: conversation_id.to_owned(),
            author_public_key: author_public_key.to_owned(),
            created_at,
            content,
            delivery: MessageDeliveryState::PendingPublication,
        };
        self.messages
            .entry(conversation_id.to_owned())
            .or_default()
            .push(message.clone());
        message
    }

    fn conversation(&self, conversation_id: &str) -> Option<&ProjectedConversation> {
        self.conversations.get(conversation_id)
    }

    fn list_conversations(&self, limit: usize) -> Vec<ConversationSummary> {
        self.conversations
            .values()
            .take(limit)
            .map(|conversation| conversation.summary.clone())
            .collect()
    }

    fn list_messages(&self, conversation_id: &str, limit: usize) -> Option<Vec<MessageSummary>> {
        self.conversation(conversation_id)?;
        let messages = self
            .messages
            .get(conversation_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let start = messages.len().saturating_sub(limit);
        Some(messages[start..].to_vec())
    }

    fn new_conversation_id(&self) -> String {
        loop {
            let candidate = new_opaque_id(CONVERSATION_ID_PREFIX);
            if !self.conversations.contains_key(&candidate) {
                return candidate;
            }
        }
    }
}

fn new_opaque_id(prefix: &str) -> String {
    format!("{prefix}{}", Keys::generate().public_key().to_hex())
}

fn group_key(group_id: &MarmotGroupId) -> String {
    hex::encode(group_id.as_bytes())
}

fn group_event_id(event: &GroupEvent) -> Option<&cgka_traits::types::GroupId> {
    match event {
        GroupEvent::GroupCreated { group_id }
        | GroupEvent::GroupJoined { group_id, .. }
        | GroupEvent::MessageReceived { group_id, .. }
        | GroupEvent::GroupStateChanged { group_id, .. }
        | GroupEvent::EpochChanged { group_id, .. } => Some(group_id),
        _ => None,
    }
}

fn summary_from_snapshot(
    conversation_id: &str,
    snapshot: &MarmotGroupSnapshot,
) -> Option<ConversationSummary> {
    if snapshot.name().trim().is_empty()
        || snapshot.name().len() > MAX_CONVERSATION_NAME_BYTES
        || snapshot.name().as_bytes().contains(&0)
        || snapshot.description().len() > MAX_CONVERSATION_DESCRIPTION_BYTES
        || snapshot.description().as_bytes().contains(&0)
    {
        return None;
    }
    Some(ConversationSummary {
        conversation_id: conversation_id.to_owned(),
        name: snapshot.name().to_owned(),
        description: snapshot.description().to_owned(),
        epoch: snapshot.epoch(),
        member_count: u32::try_from(snapshot.member_ids().len()).ok()?,
        state: ConversationState::Ready,
    })
}

#[derive(Debug, thiserror::Error)]
enum DomainError {
    #[error("invalid Marmot domain input")]
    InvalidInput,
    #[error("unknown Marmot conversation")]
    UnknownConversation,
    #[error("Marmot domain operation failed")]
    Marmot,
}

struct Runtime {
    device: MarmotDevice,
    account_keys: Keys,
    account_public_key: String,
    effects: EffectDriver,
    projections: ProjectionStore,
}

impl Runtime {
    const MAX_IMMEDIATE_EFFECT_STEPS: usize = 64;

    fn recovery_required(&self) -> bool {
        self.effects.has_recovery_work()
    }

    fn absorb_effects(&mut self, effects: MarmotEffects) -> ProjectionUpdate {
        let update = self.projections.apply_effects(&self.device, &effects);
        self.effects.absorb(effects);
        self.effects.mark_events_projected();
        update
    }

    async fn publish_key_package(&mut self) -> Result<(), DomainError> {
        let key_package = self
            .device
            .fresh_key_package()
            .await
            .map_err(|_| DomainError::Marmot)?;
        let metadata = key_package_metadata(&KeyPackage::new(key_package.as_bytes().to_vec()))
            .map_err(|_| DomainError::Marmot)?;
        if metadata.credential_identity_hex != self.account_public_key {
            return Err(DomainError::Marmot);
        }
        let event = EventBuilder::new(
            Kind::Custom(30_443),
            BASE64_STANDARD.encode(key_package.as_bytes()),
        )
        .tags([
            Tag::custom(TagKind::custom("d"), [metadata.key_package_ref_hex.clone()]),
            Tag::custom(TagKind::custom("mls_protocol_version"), ["1.0"]),
            Tag::custom(TagKind::custom("i"), [metadata.key_package_ref_hex]),
            Tag::custom(TagKind::custom("mls_ciphersuite"), ["0x0001"]),
            Tag::custom(
                TagKind::custom("mls_extensions"),
                ["0x0006", "0xf2f1", "0x000a"],
            ),
            Tag::custom(TagKind::custom("mls_proposals"), ["0x0008", "0x000a"]),
            Tag::custom(
                TagKind::custom("app_components"),
                ["0x8001", "0x8003", "0x8004"],
            ),
        ])
        .sign_with_keys(&self.account_keys)
        .map_err(|_| DomainError::Marmot)?;
        MarmotKeyPackage::from_signed_key_package_event(&event).map_err(|_| DomainError::Marmot)?;
        self.effects
            .enqueue_exact_stateless(SignedNostrEvent::from_nostr_event(&event));
        Ok(())
    }

    async fn create_conversation(
        &mut self,
        name: String,
        description: String,
        invitee_key_packages: Vec<SignedNostrEvent>,
    ) -> Result<ConversationSummary, DomainError> {
        let mut invitee_pubkeys = BTreeSet::new();
        let mut validated_key_packages = Vec::with_capacity(invitee_key_packages.len());
        for signed in invitee_key_packages {
            let event = signed
                .to_verified_nostr_event()
                .map_err(|_| DomainError::InvalidInput)?;
            if event.kind.as_u16() != 30_443
                || event.pubkey.to_hex() == self.account_public_key
                || !invitee_pubkeys.insert(event.pubkey.to_hex())
            {
                return Err(DomainError::InvalidInput);
            }
            validated_key_packages.push(
                MarmotKeyPackage::from_signed_key_package_event(&event)
                    .map_err(|_| DomainError::InvalidInput)?,
            );
        }

        let route = Keys::generate().public_key().to_bytes();
        let relay_endpoint = self.effects.relay_endpoint.clone();
        let creation = self
            .device
            .create_group(
                MarmotGroupConfig::new(
                    name.clone(),
                    description.clone(),
                    route,
                    vec![relay_endpoint],
                ),
                validated_key_packages,
            )
            .await
            .map_err(|_| DomainError::Marmot)?;
        let (group_id, effects) = creation.into_parts();
        let member_count = u32::try_from(invitee_pubkeys.len().saturating_add(1))
            .map_err(|_| DomainError::InvalidInput)?;
        let summary = self
            .projections
            .insert_pending(group_id, name, description, member_count);
        self.absorb_effects(effects);
        Ok(summary)
    }

    async fn send_message(
        &mut self,
        conversation_id: &str,
        created_at: u64,
        content: String,
    ) -> Result<(MessageSummary, bool), DomainError> {
        let group_id = self
            .projections
            .conversation(conversation_id)
            .ok_or(DomainError::UnknownConversation)?
            .group_id
            .clone();
        let effects = self
            .device
            .send_text(&group_id, created_at, content.clone())
            .await
            .map_err(|_| DomainError::Marmot)?;
        let queued = !effects.queued_intents().is_empty();
        self.absorb_effects(effects);
        let message = self.projections.insert_outgoing(
            conversation_id,
            &self.account_public_key,
            created_at,
            content,
        );
        Ok((message, queued))
    }

    fn subscription_plan(&self) -> Result<Vec<NativeSubscriptionRoute>, DomainError> {
        if self.projections.conversations.len() > MAX_SUBSCRIPTION_ROUTES {
            return Err(DomainError::Marmot);
        }
        self.projections
            .conversations
            .iter()
            .map(|(conversation_id, conversation)| {
                let snapshot = self
                    .device
                    .group_snapshot(&conversation.group_id)
                    .map_err(|_| DomainError::Marmot)?;
                Ok(NativeSubscriptionRoute {
                    conversation_id: conversation_id.clone(),
                    route: hex::encode(snapshot.nostr_group_id()),
                })
            })
            .collect()
    }

    async fn ingest_event(
        &mut self,
        signed: SignedNostrEvent,
    ) -> Result<(IpcIngestOutcome, ProjectionUpdate), DomainError> {
        let event = signed
            .to_verified_nostr_event()
            .map_err(|_| DomainError::InvalidInput)?;
        let kind = event.kind.as_u16();
        let transport =
            NostrTransportEvent::from_nostr_event(&event).map_err(|_| DomainError::InvalidInput)?;
        let ingested = match kind {
            1059 => self.device.accept_welcome(transport).await,
            445 => self.device.ingest_group_event(transport).await,
            _ => return Err(DomainError::InvalidInput),
        }
        .map_err(|_| DomainError::Marmot)?;
        let (outcome, effects) = ingested.into_parts();
        let update = self.absorb_effects(effects);
        Ok((map_ingest_outcome(outcome), update))
    }

    fn joined_conversations(&self, update: &ProjectionUpdate) -> Vec<ConversationSummary> {
        update
            .joined_conversation_ids
            .iter()
            .filter_map(|conversation_id| {
                self.projections
                    .conversation(conversation_id)
                    .map(|conversation| conversation.summary.clone())
            })
            .collect()
    }

    async fn next_action(&mut self) -> Result<Option<NativeAction>, ActionDriverError> {
        if let Some(active) = &self.effects.active {
            return Ok(Some(active.action.clone()));
        }

        for _ in 0..Self::MAX_IMMEDIATE_EFFECT_STEPS {
            let Some(work) = self.effects.work.pop_front() else {
                return Ok(None);
            };
            match work {
                DriverWork::ExactStateless { event } => {
                    return self
                        .effects
                        .prepare_exact_action_or_requeue(event)
                        .map(Some);
                }
                DriverWork::Stateless { message } => {
                    let original = DriverWork::Stateless {
                        message: message.clone(),
                    };
                    return self
                        .effects
                        .prepare_action_or_requeue(message, ActionContinuation::Stateless, original)
                        .map(Some);
                }
                DriverWork::AutoPublish { message, pending } => {
                    let original = DriverWork::AutoPublish {
                        message: message.clone(),
                        pending,
                    };
                    return self
                        .effects
                        .prepare_action_or_requeue(
                            message,
                            ActionContinuation::AutoPublish { pending },
                            original,
                        )
                        .map(Some);
                }
                DriverWork::GroupEvolution {
                    commit,
                    welcomes,
                    pending,
                } => {
                    let original = DriverWork::GroupEvolution {
                        commit: commit.clone(),
                        welcomes: welcomes.clone(),
                        pending,
                    };
                    return self
                        .effects
                        .prepare_action_or_requeue(
                            commit,
                            ActionContinuation::GroupEvolution { welcomes, pending },
                            original,
                        )
                        .map(Some);
                }
                DriverWork::GroupCreated {
                    mut welcomes,
                    pending,
                    all_published,
                    any_exposed,
                } => {
                    if let Some(message) = welcomes.pop_front() {
                        let original = DriverWork::GroupCreated {
                            welcomes: std::iter::once(message.clone())
                                .chain(welcomes.iter().cloned())
                                .collect(),
                            pending,
                            all_published,
                            any_exposed,
                        };
                        return self
                            .effects
                            .prepare_action_or_requeue(
                                message,
                                ActionContinuation::GroupCreated {
                                    remaining: welcomes,
                                    pending,
                                    all_published,
                                    any_exposed,
                                },
                                original,
                            )
                            .map(Some);
                    }

                    let follow_up = if all_published || any_exposed {
                        self.device.confirm_published(pending).await
                    } else {
                        self.device.publication_failed(pending).await
                    };
                    let follow_up = match follow_up {
                        Ok(effects) => effects,
                        Err(_) => {
                            self.effects.prepend(DriverWork::GroupCreated {
                                welcomes,
                                pending,
                                all_published,
                                any_exposed,
                            });
                            return Err(ActionDriverError::Marmot);
                        }
                    };
                    self.absorb_effects(follow_up);
                }
                DriverWork::Converge { group_id } => {
                    let follow_up = match self.device.advance_convergence(&group_id).await {
                        Ok(effects) => effects,
                        Err(_) => {
                            self.effects.prepend(DriverWork::Converge { group_id });
                            return Err(ActionDriverError::Marmot);
                        }
                    };
                    self.absorb_effects(follow_up);
                }
            }
        }

        Err(ActionDriverError::StepBudgetExceeded)
    }

    async fn complete_action(
        &mut self,
        action_id: &str,
        completion: ActionCompletion,
    ) -> Result<Option<NativeAction>, ActionDriverError> {
        let Some(active) = self.effects.active.as_ref() else {
            return Err(ActionDriverError::InvalidCompletion);
        };
        if active.action.action_id() != action_id {
            return Err(ActionDriverError::InvalidCompletion);
        }
        if matches!(completion, ActionCompletion::Ambiguous) {
            return Ok(Some(active.action.clone()));
        }

        let (relay_endpoints, required_acks) = match &active.action {
            NativeAction::PublishExactEvent {
                relay_endpoints,
                required_acks,
                ..
            } => (relay_endpoints, *required_acks),
        };
        let ActionCompletion::Definite { endpoint_reports } = completion else {
            return Err(ActionDriverError::InvalidCompletion);
        };
        if endpoint_reports.len() != relay_endpoints.len()
            || relay_endpoints.iter().any(|endpoint| {
                !endpoint_reports
                    .iter()
                    .any(|report| report.relay_endpoint == *endpoint)
            })
        {
            return Err(ActionDriverError::InvalidCompletion);
        }
        let accepted = endpoint_reports
            .iter()
            .filter(|report| matches!(report.outcome, RelayPublishOutcome::Accepted))
            .count();
        let met_required_acks = accepted >= usize::from(required_acks);
        let any_exposed = accepted != 0;

        let active = self
            .effects
            .active
            .take()
            .ok_or(ActionDriverError::InvalidCompletion)?;
        let continuation = active.continuation.clone();
        let resolution = match continuation {
            ActionContinuation::Stateless => {
                if !met_required_acks {
                    self.effects.record_failed(active.payload.clone());
                }
                Ok(None)
            }
            ActionContinuation::AutoPublish { pending } => {
                self.resolve_pending(pending, any_exposed).await.map(Some)
            }
            ActionContinuation::GroupEvolution { welcomes, pending } => {
                match self.resolve_pending(pending, any_exposed).await {
                    Ok(follow_up) => {
                        if any_exposed {
                            for welcome in welcomes.into_iter().rev() {
                                self.effects
                                    .prepend(DriverWork::Stateless { message: welcome });
                            }
                        }
                        Ok(Some(follow_up))
                    }
                    Err(error) => Err(error),
                }
            }
            ActionContinuation::GroupCreated {
                remaining,
                pending,
                all_published,
                any_exposed: previously_exposed,
            } => {
                let all_published = all_published && met_required_acks;
                let any_exposed = previously_exposed || any_exposed;
                if !met_required_acks && any_exposed {
                    self.effects.record_failed(active.payload.clone());
                }
                if !met_required_acks && !any_exposed {
                    self.resolve_pending(pending, false).await.map(Some)
                } else if remaining.is_empty() {
                    self.resolve_pending(pending, all_published || any_exposed)
                        .await
                        .map(Some)
                } else {
                    self.effects.prepend(DriverWork::GroupCreated {
                        welcomes: remaining,
                        pending,
                        all_published,
                        any_exposed,
                    });
                    Ok(None)
                }
            }
        };

        match resolution {
            Ok(Some(follow_up)) => {
                self.absorb_effects(follow_up);
            }
            Ok(None) => {}
            Err(error) => {
                self.effects.restore_active(active);
                return Err(error);
            }
        }
        self.next_action().await
    }

    async fn resolve_pending(
        &mut self,
        pending: MarmotPendingPublication,
        exposed: bool,
    ) -> Result<MarmotEffects, ActionDriverError> {
        if exposed {
            self.device.confirm_published(pending).await
        } else {
            self.device.publication_failed(pending).await
        }
        .map_err(|_| ActionDriverError::Marmot)
    }
}

fn map_ingest_outcome(outcome: MdkIngestOutcome) -> IpcIngestOutcome {
    match outcome {
        MdkIngestOutcome::Processed => IpcIngestOutcome::Processed,
        MdkIngestOutcome::Buffered { .. } => IpcIngestOutcome::Buffered,
        MdkIngestOutcome::Stale { reason } => IpcIngestOutcome::Stale {
            reason: match reason {
                MdkStaleReason::AlreadySeen => IpcStaleReason::AlreadySeen,
                MdkStaleReason::AlreadyAtEpoch { .. } => IpcStaleReason::AlreadyAtEpoch,
                MdkStaleReason::NotForThisClient => IpcStaleReason::NotForThisClient,
                MdkStaleReason::UnknownGroup => IpcStaleReason::UnknownGroup,
                MdkStaleReason::OwnEcho => IpcStaleReason::OwnEcho,
                MdkStaleReason::PeelFailed => IpcStaleReason::PeelFailed,
                MdkStaleReason::SelfEvicted => IpcStaleReason::SelfEvicted,
                MdkStaleReason::Quarantined => IpcStaleReason::Quarantined,
            },
        },
    }
}

#[derive(Default)]
struct Service {
    handshake_complete: bool,
    last_request_id: Option<u64>,
    runtime: Option<Runtime>,
}

impl Service {
    async fn handle(&mut self, request: Request) -> (Response, bool) {
        let request_id = request.request_id;
        if let Err(error) = request.validate() {
            let rpc_error = match error {
                IpcError::UnsupportedVersion { .. } => RpcError::new(
                    RpcErrorCode::UnsupportedVersion,
                    "unsupported Marmot sidecar protocol version",
                ),
                _ => RpcError::new(RpcErrorCode::InvalidRequest, "invalid sidecar request"),
            };
            return (Response::failure(request_id, rpc_error), false);
        }

        if self
            .last_request_id
            .is_some_and(|last_request_id| request_id <= last_request_id)
        {
            return (
                Response::failure(
                    request_id,
                    RpcError::new(
                        RpcErrorCode::InvalidRequest,
                        "request ids must increase within one sidecar session",
                    ),
                ),
                false,
            );
        }
        self.last_request_id = Some(request_id);

        if !self.handshake_complete && !matches!(&request.command, Command::Handshake { .. }) {
            return (
                Response::failure(
                    request_id,
                    RpcError::new(
                        RpcErrorCode::HandshakeRequired,
                        "complete the Marmot sidecar handshake first",
                    ),
                ),
                false,
            );
        }

        match request.command {
            Command::Handshake {
                client_name: _client_name,
            } => {
                if self.handshake_complete {
                    return (
                        Response::failure(
                            request_id,
                            RpcError::new(
                                RpcErrorCode::InvalidRequest,
                                "Marmot sidecar handshake is already complete",
                            ),
                        ),
                        false,
                    );
                }
                self.handshake_complete = true;
                (
                    Response::success(
                        request_id,
                        ResponseResult::Handshake {
                            sidecar_version: env!("CARGO_PKG_VERSION").into(),
                            capabilities: vec![
                                "initialize".into(),
                                "status".into(),
                                "publish_key_package".into(),
                                "create_conversation".into(),
                                "send_message".into(),
                                "ingest_event".into(),
                                "list_conversations".into(),
                                "list_messages".into(),
                                "get_subscription_plan".into(),
                                "next_action".into(),
                                "complete_action".into(),
                                "shutdown".into(),
                                CAPABILITY_EXPERIMENTAL_PREVIEW_V1.into(),
                            ],
                        },
                    ),
                    false,
                )
            }
            Command::Initialize {
                database_path,
                database_key,
                account_secret_key,
                relay_endpoint,
            } => {
                if self.runtime.is_some() {
                    return (
                        Response::failure(
                            request_id,
                            RpcError::new(
                                RpcErrorCode::AlreadyInitialized,
                                "Marmot sidecar is already initialized",
                            ),
                        ),
                        false,
                    );
                }
                let account_secret = Zeroizing::new(account_secret_key.into_bytes());
                let secret = match SecretKey::from_slice(account_secret.as_ref()) {
                    Ok(secret) => secret,
                    Err(_) => {
                        return (
                            Response::failure(
                                request_id,
                                RpcError::new(
                                    RpcErrorCode::InvalidRequest,
                                    "invalid Nostr account secret",
                                ),
                            ),
                            false,
                        );
                    }
                };
                let keys = Keys::new(secret);
                let mut device = match MarmotDevice::open(MarmotDeviceConfig::new(
                    PathBuf::from(database_path),
                    MarmotDatabaseKey::new(database_key.into_bytes()),
                    keys.clone(),
                )) {
                    Ok(device) => device,
                    Err(_) => {
                        return (
                            Response::failure(
                                request_id,
                                RpcError::new(
                                    RpcErrorCode::InitializationFailed,
                                    "could not initialize encrypted Marmot storage",
                                ),
                            ),
                            false,
                        );
                    }
                };
                let account_public_key = hex::encode(device.account_public_key());
                let startup_effects = device.drain_effects();
                let startup_effects_pending = !startup_effects.is_empty();
                let mut runtime = Runtime {
                    device,
                    account_keys: keys,
                    account_public_key: account_public_key.clone(),
                    effects: EffectDriver::new(relay_endpoint),
                    projections: ProjectionStore::default(),
                };
                runtime.absorb_effects(startup_effects);
                self.runtime = Some(runtime);

                (
                    Response::success(
                        request_id,
                        ResponseResult::Initialized {
                            account_public_key,
                            startup_effects_pending,
                        },
                    ),
                    false,
                )
            }
            Command::Status => {
                let state = self
                    .runtime
                    .as_ref()
                    .map_or(RuntimeStatus::Uninitialized, |runtime| {
                        if runtime.recovery_required() {
                            RuntimeStatus::RecoveryRequired {
                                account_public_key: runtime.account_public_key.clone(),
                            }
                        } else {
                            RuntimeStatus::Ready {
                                account_public_key: runtime.account_public_key.clone(),
                            }
                        }
                    });
                (
                    Response::success(request_id, ResponseResult::Status { state }),
                    false,
                )
            }
            Command::PublishKeyPackage => {
                let Some(runtime) = self.runtime.as_mut() else {
                    return runtime_required(request_id, "publishing a KeyPackage");
                };
                match runtime.publish_key_package().await {
                    Ok(()) => (
                        Response::success(request_id, ResponseResult::KeyPackageQueued),
                        false,
                    ),
                    Err(_) => operation_failed(
                        request_id,
                        "could not prepare a Marmot KeyPackage publication",
                    ),
                }
            }
            Command::CreateConversation {
                name,
                description,
                invitee_key_packages,
            } => {
                let Some(runtime) = self.runtime.as_mut() else {
                    return runtime_required(request_id, "creating an encrypted conversation");
                };
                match runtime
                    .create_conversation(name, description, invitee_key_packages)
                    .await
                {
                    Ok(conversation) => (
                        Response::success(
                            request_id,
                            ResponseResult::ConversationCreated { conversation },
                        ),
                        false,
                    ),
                    Err(DomainError::InvalidInput | DomainError::UnknownConversation) => {
                        invalid_domain_request(request_id, "invalid encrypted conversation request")
                    }
                    Err(DomainError::Marmot) => {
                        operation_failed(request_id, "could not create the encrypted conversation")
                    }
                }
            }
            Command::SendMessage {
                conversation_id,
                created_at,
                content,
            } => {
                let Some(runtime) = self.runtime.as_mut() else {
                    return runtime_required(request_id, "sending an encrypted message");
                };
                match runtime
                    .send_message(&conversation_id, created_at, content)
                    .await
                {
                    Ok((message, queued_behind_transition)) => (
                        Response::success(
                            request_id,
                            ResponseResult::MessageQueued {
                                message,
                                queued_behind_transition,
                            },
                        ),
                        false,
                    ),
                    Err(DomainError::UnknownConversation | DomainError::InvalidInput) => {
                        invalid_domain_request(request_id, "unknown encrypted conversation")
                    }
                    Err(DomainError::Marmot) => {
                        operation_failed(request_id, "could not prepare the encrypted message")
                    }
                }
            }
            Command::IngestEvent { event } => {
                let Some(runtime) = self.runtime.as_mut() else {
                    return runtime_required(request_id, "ingesting an encrypted event");
                };
                match runtime.ingest_event(event).await {
                    Ok((outcome, update)) => {
                        let delivered_messages = match u16::try_from(update.delivered_messages) {
                            Ok(count) => count,
                            Err(_) => {
                                return operation_failed(
                                    request_id,
                                    "encrypted event produced too many messages",
                                );
                            }
                        };
                        let rejected_messages = match u16::try_from(update.rejected_messages) {
                            Ok(count) => count,
                            Err(_) => {
                                return operation_failed(
                                    request_id,
                                    "encrypted event produced too many messages",
                                );
                            }
                        };
                        let joined_conversations = runtime.joined_conversations(&update);
                        (
                            Response::success(
                                request_id,
                                ResponseResult::EventIngested {
                                    outcome,
                                    delivered_messages,
                                    rejected_messages,
                                    joined_conversations,
                                    changed_conversation_ids: update.changed_conversation_ids,
                                    changed_message_ids: update.changed_message_ids,
                                },
                            ),
                            false,
                        )
                    }
                    Err(DomainError::InvalidInput | DomainError::UnknownConversation) => {
                        invalid_domain_request(request_id, "invalid encrypted transport event")
                    }
                    Err(DomainError::Marmot) => {
                        operation_failed(request_id, "could not ingest the encrypted event")
                    }
                }
            }
            Command::ListConversations { limit } => {
                let Some(runtime) = self.runtime.as_ref() else {
                    return runtime_required(request_id, "listing encrypted conversations");
                };
                let conversations = runtime.projections.list_conversations(usize::from(limit));
                (
                    Response::success(request_id, ResponseResult::Conversations { conversations }),
                    false,
                )
            }
            Command::ListMessages {
                conversation_id,
                limit,
            } => {
                let Some(runtime) = self.runtime.as_ref() else {
                    return runtime_required(request_id, "listing encrypted messages");
                };
                let Some(messages) = runtime
                    .projections
                    .list_messages(&conversation_id, usize::from(limit))
                else {
                    return invalid_domain_request(request_id, "unknown encrypted conversation");
                };
                (
                    Response::success(
                        request_id,
                        ResponseResult::Messages {
                            conversation_id,
                            messages,
                        },
                    ),
                    false,
                )
            }
            Command::GetSubscriptionPlan => {
                let Some(runtime) = self.runtime.as_ref() else {
                    return runtime_required(request_id, "planning encrypted subscriptions");
                };
                match runtime.subscription_plan() {
                    Ok(routes) => (
                        Response::success(request_id, ResponseResult::SubscriptionPlan { routes }),
                        false,
                    ),
                    Err(_) => {
                        operation_failed(request_id, "could not prepare encrypted subscriptions")
                    }
                }
            }
            Command::NextAction => {
                let Some(runtime) = self.runtime.as_mut() else {
                    return (
                        Response::failure(
                            request_id,
                            RpcError::new(
                                RpcErrorCode::InvalidRequest,
                                "initialize the Marmot runtime before polling actions",
                            ),
                        ),
                        false,
                    );
                };
                match runtime.next_action().await {
                    Ok(action) => (
                        Response::success(request_id, ResponseResult::Action { action }),
                        false,
                    ),
                    Err(_) => (
                        Response::failure(
                            request_id,
                            RpcError::new(
                                RpcErrorCode::OperationFailed,
                                "Marmot action processing failed",
                            ),
                        ),
                        false,
                    ),
                }
            }
            Command::CompleteAction {
                action_id,
                completion,
            } => {
                let Some(runtime) = self.runtime.as_mut() else {
                    return (
                        Response::failure(
                            request_id,
                            RpcError::new(
                                RpcErrorCode::InvalidRequest,
                                "initialize the Marmot runtime before completing actions",
                            ),
                        ),
                        false,
                    );
                };
                match runtime.complete_action(&action_id, completion).await {
                    Ok(action) => (
                        Response::success(request_id, ResponseResult::Action { action }),
                        false,
                    ),
                    Err(ActionDriverError::InvalidCompletion) => (
                        Response::failure(
                            request_id,
                            RpcError::new(
                                RpcErrorCode::InvalidRequest,
                                "no matching Marmot action is pending",
                            ),
                        ),
                        false,
                    ),
                    Err(_) => (
                        Response::failure(
                            request_id,
                            RpcError::new(
                                RpcErrorCode::OperationFailed,
                                "Marmot action processing failed",
                            ),
                        ),
                        false,
                    ),
                }
            }
            Command::Shutdown => (
                Response::success(request_id, ResponseResult::ShuttingDown),
                true,
            ),
        }
    }
}

fn runtime_required(request_id: u64, operation: &str) -> (Response, bool) {
    (
        Response::failure(
            request_id,
            RpcError::new(
                RpcErrorCode::InvalidRequest,
                format!("initialize the Marmot runtime before {operation}"),
            ),
        ),
        false,
    )
}

fn invalid_domain_request(request_id: u64, message: &'static str) -> (Response, bool) {
    (
        Response::failure(
            request_id,
            RpcError::new(RpcErrorCode::InvalidRequest, message),
        ),
        false,
    )
}

fn operation_failed(request_id: u64, message: &'static str) -> (Response, bool) {
    (
        Response::failure(
            request_id,
            RpcError::new(RpcErrorCode::OperationFailed, message),
        ),
        false,
    )
}

/// Run one sidecar session over an arbitrary pair of async pipes.
///
/// Production passes locked stdin/stdout handles. Tests use in-memory duplex
/// streams so framing and lifecycle behavior are exercised without spawning a
/// subprocess.
pub async fn run_sidecar<R, W>(mut input: R, mut output: W) -> Result<(), SidecarError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut service = Service::default();
    let mut decoder = FrameDecoder::new();
    let mut read_buffer = Zeroizing::new([0_u8; 8 * 1024]);

    loop {
        let bytes_read = input.read(&mut read_buffer[..]).await?;
        if bytes_read == 0 {
            return if decoder.is_empty() {
                Ok(())
            } else {
                Err(SidecarError::TruncatedFrame)
            };
        }

        for payload in decoder.push(&read_buffer[..bytes_read])? {
            let request: Request = decode_payload(&payload)?;
            if request.request_id == 0 {
                return Err(SidecarError::Protocol(IpcError::InvalidRequestId));
            }
            let (response, should_shutdown) = service.handle(request).await;
            output.write_all(&encode_frame(&response)?).await?;
            output.flush().await?;
            if should_shutdown {
                return Ok(());
            }
        }
        read_buffer[..bytes_read].zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_marmot_ipc::{RelayPublishReport, ResponseOutcome, SecretBytes32, PROTOCOL_VERSION};
    use nostr::{EventBuilder, Kind, Tag};
    use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt, DuplexStream};

    async fn request(stream: &mut DuplexStream, request: Request) -> Response {
        stream
            .write_all(&encode_frame(&request).expect("encode request"))
            .await
            .expect("write request");
        stream.flush().await.expect("flush request");

        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).await.expect("read length");
        let length = u32::from_be_bytes(length) as usize;
        let mut payload = vec![0_u8; length];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read response");
        let response: Response = decode_payload(&payload).expect("decode response");
        response.validate().expect("valid response envelope");
        response
    }

    async fn run_session(
        database_path: String,
        database_key: [u8; 32],
        expect_initialization: bool,
    ) -> Vec<Response> {
        run_session_with_account(
            database_path,
            database_key,
            [1_u8; 32],
            expect_initialization,
        )
        .await
    }

    async fn run_session_with_account(
        database_path: String,
        database_key: [u8; 32],
        account_secret_key: [u8; 32],
        expect_initialization: bool,
    ) -> Vec<Response> {
        let (mut client, server) = duplex(256 * 1024);
        let (server_read, server_write) = split(server);
        let server = run_sidecar(server_read, server_write);
        let client_flow = async move {
            let mut responses = Vec::new();
            responses.push(
                request(
                    &mut client,
                    Request::new(
                        1,
                        Command::Handshake {
                            client_name: "sidecar-test".into(),
                        },
                    ),
                )
                .await,
            );
            responses.push(
                request(
                    &mut client,
                    Request::new(
                        2,
                        Command::Initialize {
                            database_path,
                            database_key: SecretBytes32::new(database_key),
                            account_secret_key: SecretBytes32::new(account_secret_key),
                            relay_endpoint: "wss://relay.example".into(),
                        },
                    ),
                )
                .await,
            );
            if expect_initialization {
                responses.push(request(&mut client, Request::new(3, Command::Status)).await);
            }
            responses.push(request(&mut client, Request::new(4, Command::Shutdown)).await);
            responses
        };

        let (server_result, responses) = tokio::join!(server, client_flow);
        server_result.expect("sidecar exits cleanly");
        responses
    }

    #[tokio::test]
    async fn initializes_reports_status_and_reopens_after_restart() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database_path = directory
            .path()
            .join("marmot.sqlite3")
            .to_string_lossy()
            .into_owned();

        for _ in 0..2 {
            let responses = run_session(database_path.clone(), [0xA5; 32], true).await;
            let ResponseOutcome::Success {
                result: ResponseResult::Handshake { capabilities, .. },
            } = &responses[0].outcome
            else {
                panic!("handshake response expected");
            };
            assert!(capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_EXPERIMENTAL_PREVIEW_V1));
            assert!(matches!(
                responses[0].outcome,
                ResponseOutcome::Success {
                    result: ResponseResult::Handshake { .. }
                }
            ));
            assert!(matches!(
                responses[1].outcome,
                ResponseOutcome::Success {
                    result: ResponseResult::Initialized { .. }
                }
            ));
            assert!(matches!(
                responses[2].outcome,
                ResponseOutcome::Success {
                    result: ResponseResult::Status {
                        state: RuntimeStatus::Ready { .. }
                    }
                }
            ));
            assert!(matches!(
                responses[3].outcome,
                ResponseOutcome::Success {
                    result: ResponseResult::ShuttingDown
                }
            ));
        }
    }

    #[tokio::test]
    async fn wrong_database_key_returns_only_sanitized_error() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database_path = directory
            .path()
            .join("marmot.sqlite3")
            .to_string_lossy()
            .into_owned();

        let initialized = run_session(database_path.clone(), [0x11; 32], true).await;
        assert!(matches!(
            initialized[1].outcome,
            ResponseOutcome::Success { .. }
        ));

        let rejected = run_session(database_path.clone(), [0x22; 32], false).await;
        let ResponseOutcome::Failure { error } = &rejected[1].outcome else {
            panic!("wrong database key must fail");
        };
        assert_eq!(error.code, RpcErrorCode::InitializationFailed);
        assert_eq!(
            error.message,
            "could not initialize encrypted Marmot storage"
        );
        assert!(!error.message.contains(&database_path));
        assert!(!error.message.to_ascii_lowercase().contains("sqlite"));

        let recovered = run_session(database_path, [0x11; 32], true).await;
        assert!(matches!(
            recovered[1].outcome,
            ResponseOutcome::Success {
                result: ResponseResult::Initialized { .. }
            }
        ));
    }

    #[tokio::test]
    async fn account_binding_failure_is_sanitized_and_does_not_damage_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database_path = directory
            .path()
            .join("marmot.sqlite3")
            .to_string_lossy()
            .into_owned();

        let initialized =
            run_session_with_account(database_path.clone(), [0x33; 32], [1_u8; 32], true).await;
        assert!(matches!(
            initialized[1].outcome,
            ResponseOutcome::Success { .. }
        ));

        let rejected =
            run_session_with_account(database_path.clone(), [0x33; 32], [2_u8; 32], false).await;
        let ResponseOutcome::Failure { error } = &rejected[1].outcome else {
            panic!("a different account must not hydrate existing MLS state");
        };
        assert_eq!(error.code, RpcErrorCode::InitializationFailed);
        assert_eq!(
            error.message,
            "could not initialize encrypted Marmot storage"
        );
        assert!(!error.message.contains(&database_path));

        let reopened = run_session_with_account(database_path, [0x33; 32], [1_u8; 32], true).await;
        assert!(matches!(
            reopened[1].outcome,
            ResponseOutcome::Success {
                result: ResponseResult::Initialized { .. }
            }
        ));
    }

    #[tokio::test]
    async fn rejects_stateful_commands_before_handshake_and_unknown_versions() {
        let (mut client, server) = duplex(64 * 1024);
        let (server_read, server_write) = split(server);
        let server = run_sidecar(server_read, server_write);
        let client_flow = async move {
            let response = request(&mut client, Request::new(1, Command::Status)).await;
            assert!(matches!(
                response.outcome,
                ResponseOutcome::Failure {
                    error: RpcError {
                        code: RpcErrorCode::HandshakeRequired,
                        ..
                    }
                }
            ));

            let mut request_value = Request::new(
                2,
                Command::Handshake {
                    client_name: "sidecar-test".into(),
                },
            );
            request_value.version = PROTOCOL_VERSION + 1;
            let response = request(&mut client, request_value).await;
            assert!(matches!(
                response.outcome,
                ResponseOutcome::Failure {
                    error: RpcError {
                        code: RpcErrorCode::UnsupportedVersion,
                        ..
                    }
                }
            ));

            let _ = request(
                &mut client,
                Request::new(
                    3,
                    Command::Handshake {
                        client_name: "sidecar-test".into(),
                    },
                ),
            )
            .await;
            let _ = request(&mut client, Request::new(4, Command::Shutdown)).await;
        };

        let (server_result, ()) = tokio::join!(server, client_flow);
        server_result.expect("sidecar exits cleanly");
    }

    #[tokio::test]
    async fn rejects_duplicate_ids_and_repeated_handshakes() {
        let (mut client, server) = duplex(64 * 1024);
        let (server_read, server_write) = split(server);
        let server = run_sidecar(server_read, server_write);
        let client_flow = async move {
            let handshake = || Command::Handshake {
                client_name: "sidecar-test".into(),
            };
            let first = request(&mut client, Request::new(1, handshake())).await;
            assert!(matches!(first.outcome, ResponseOutcome::Success { .. }));

            let duplicate = request(&mut client, Request::new(1, Command::Status)).await;
            assert!(matches!(
                duplicate.outcome,
                ResponseOutcome::Failure {
                    error: RpcError {
                        code: RpcErrorCode::InvalidRequest,
                        ..
                    }
                }
            ));

            let repeated = request(&mut client, Request::new(2, handshake())).await;
            assert!(matches!(
                repeated.outcome,
                ResponseOutcome::Failure {
                    error: RpcError {
                        code: RpcErrorCode::InvalidRequest,
                        ..
                    }
                }
            ));
            let _ = request(&mut client, Request::new(3, Command::Shutdown)).await;
        };

        let (server_result, ()) = tokio::join!(server, client_flow);
        server_result.expect("sidecar exits cleanly");
    }

    #[tokio::test]
    async fn zero_request_id_is_a_fatal_protocol_error() {
        let (mut client, server) = duplex(8 * 1024);
        let (server_read, server_write) = split(server);
        let server = run_sidecar(server_read, server_write);
        let client_flow = async move {
            client
                .write_all(
                    &encode_frame(&Request::new(0, Command::Status)).expect("encode request"),
                )
                .await
                .expect("write request");
            client.flush().await.expect("flush request");
        };

        let (server_result, ()) = tokio::join!(server, client_flow);
        assert!(matches!(
            server_result,
            Err(SidecarError::Protocol(IpcError::InvalidRequestId))
        ));
    }

    fn stateless_runtime(directory: &std::path::Path) -> Runtime {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("fixed account key");
        let device = MarmotDevice::open(MarmotDeviceConfig::new(
            directory.join("actions.sqlite3"),
            MarmotDatabaseKey::new([0x55; 32]),
            keys.clone(),
        ))
        .expect("open action-test device");
        let signed = EventBuilder::new(Kind::Custom(445), "opaque ciphertext")
            .tag(Tag::parse(["h", &"77".repeat(32)]).expect("h tag"))
            .sign_with_keys(&keys)
            .expect("sign exact action event");
        let message = NostrTransportEvent::from_nostr_event(&signed)
            .expect("transport event")
            .to_transport_message()
            .expect("transport message");
        let mut effects = EffectDriver::new("wss://relay.example".into());
        effects.work.push_back(DriverWork::Stateless { message });
        Runtime {
            device,
            account_keys: keys.clone(),
            account_public_key: keys.public_key().to_hex(),
            effects,
            projections: ProjectionStore::default(),
        }
    }

    fn action_endpoint(action: &NativeAction) -> (&str, &str) {
        match action {
            NativeAction::PublishExactEvent {
                action_id,
                relay_endpoints,
                ..
            } => (
                action_id,
                relay_endpoints.first().expect("one endpoint").as_str(),
            ),
        }
    }

    #[tokio::test]
    async fn ambiguous_completion_retries_the_exact_signed_action() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut runtime = stateless_runtime(directory.path());
        let action = runtime
            .next_action()
            .await
            .expect("prepare action")
            .expect("one action");
        let action_id = action.action_id().to_string();

        let retried = runtime
            .complete_action(&action_id, ActionCompletion::Ambiguous)
            .await
            .expect("ambiguous completion retains exact action")
            .expect("same action remains pending");

        assert_eq!(retried, action);
    }

    #[tokio::test]
    async fn definite_reports_must_match_the_action_endpoint_exactly() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut runtime = stateless_runtime(directory.path());
        let action = runtime
            .next_action()
            .await
            .expect("prepare action")
            .expect("one action");
        let (action_id, _) = action_endpoint(&action);

        let error = runtime
            .complete_action(
                action_id,
                ActionCompletion::Definite {
                    endpoint_reports: vec![RelayPublishReport {
                        relay_endpoint: "wss://different.example".into(),
                        outcome: RelayPublishOutcome::Accepted,
                    }],
                },
            )
            .await
            .expect_err("mismatched endpoint must fail closed");

        assert!(matches!(error, ActionDriverError::InvalidCompletion));
        assert_eq!(runtime.next_action().await.expect("retry"), Some(action));
    }

    #[tokio::test]
    async fn accepted_stateless_action_completes_and_stale_ack_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut runtime = stateless_runtime(directory.path());
        let action = runtime
            .next_action()
            .await
            .expect("prepare action")
            .expect("one action");
        let (action_id, endpoint) = action_endpoint(&action);
        let action_id = action_id.to_string();
        let endpoint = endpoint.to_string();
        let completion = ActionCompletion::Definite {
            endpoint_reports: vec![RelayPublishReport {
                relay_endpoint: endpoint,
                outcome: RelayPublishOutcome::Accepted,
            }],
        };

        assert!(runtime
            .complete_action(&action_id, completion)
            .await
            .expect("accepted action")
            .is_none());
        assert!(!runtime.recovery_required());
        assert!(matches!(
            runtime
                .complete_action(&action_id, ActionCompletion::Ambiguous)
                .await,
            Err(ActionDriverError::InvalidCompletion)
        ));
    }

    #[tokio::test]
    async fn invalid_prepared_work_is_requeued_instead_of_lost() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut runtime = stateless_runtime(directory.path());
        let Some(DriverWork::Stateless { message }) = runtime.effects.work.front_mut() else {
            panic!("test runtime contains stateless work");
        };
        message.payload.clear();

        assert!(matches!(
            runtime.next_action().await,
            Err(ActionDriverError::InvalidPreparedEvent)
        ));
        assert!(runtime.effects.active.is_none());
        assert_eq!(runtime.effects.work.len(), 1);
        assert!(matches!(
            runtime.effects.work.front(),
            Some(DriverWork::Stateless { .. })
        ));
    }

    fn domain_runtime(
        database_path: PathBuf,
        database_key: [u8; 32],
        account_secret: &str,
    ) -> Runtime {
        let account_keys = Keys::parse(account_secret).expect("fixed test account key");
        let device = MarmotDevice::open(MarmotDeviceConfig::new(
            database_path,
            MarmotDatabaseKey::new(database_key),
            account_keys.clone(),
        ))
        .expect("open domain-test device");
        Runtime {
            device,
            account_public_key: account_keys.public_key().to_hex(),
            account_keys,
            effects: EffectDriver::new("wss://relay.example".into()),
            projections: ProjectionStore::default(),
        }
    }

    fn exact_event(action: &NativeAction) -> SignedNostrEvent {
        match action {
            NativeAction::PublishExactEvent { event, .. } => event.clone(),
        }
    }

    async fn accept_exact_action(runtime: &mut Runtime, action: &NativeAction) {
        let (action_id, endpoint) = action_endpoint(action);
        let action_id = action_id.to_owned();
        let endpoint = endpoint.to_owned();
        runtime
            .complete_action(
                &action_id,
                ActionCompletion::Definite {
                    endpoint_reports: vec![RelayPublishReport {
                        relay_endpoint: endpoint,
                        outcome: RelayPublishOutcome::Accepted,
                    }],
                },
            )
            .await
            .expect("accept exact action");
    }

    #[tokio::test]
    async fn domain_commands_complete_key_package_create_send_ingest_and_list_flow() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut alice = domain_runtime(
            directory.path().join("alice-domain.sqlite3"),
            [0xA1; 32],
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
        let mut bob = domain_runtime(
            directory.path().join("bob-domain.sqlite3"),
            [0xB2; 32],
            "0000000000000000000000000000000000000000000000000000000000000002",
        );

        bob.publish_key_package()
            .await
            .expect("Bob queues a canonical KeyPackage");
        let key_package_action = bob
            .next_action()
            .await
            .expect("prepare Bob KeyPackage action")
            .expect("one Bob KeyPackage action");
        let key_package_event = exact_event(&key_package_action);
        assert_eq!(key_package_event.kind, 30_443);
        assert_eq!(key_package_event.pubkey, bob.account_public_key);
        let key_package = key_package_event
            .to_verified_nostr_event()
            .expect("valid signed KeyPackage event");
        MarmotKeyPackage::from_signed_key_package_event(&key_package)
            .expect("canonical KeyPackage tags and metadata");
        let d_tag = key_package_event
            .tags
            .iter()
            .find(|tag| tag.first().is_some_and(|name| name == "d"))
            .and_then(|tag| tag.get(1));
        let i_tag = key_package_event
            .tags
            .iter()
            .find(|tag| tag.first().is_some_and(|name| name == "i"))
            .and_then(|tag| tag.get(1));
        assert_eq!(d_tag, i_tag);
        assert!(key_package_event
            .tags
            .iter()
            .all(|tag| tag.first().is_none_or(|name| name != "encoding")));
        accept_exact_action(&mut bob, &key_package_action).await;

        let pending = alice
            .create_conversation(
                "desktop encrypted".into(),
                "domain boundary round trip".into(),
                vec![key_package_event],
            )
            .await
            .expect("Alice stages encrypted conversation");
        assert!(pending.conversation_id.starts_with(CONVERSATION_ID_PREFIX));
        assert!(matches!(
            pending.state,
            ConversationState::PendingPublication
        ));
        assert_eq!(pending.member_count, 2);

        let welcome_action = alice
            .next_action()
            .await
            .expect("prepare Welcome action")
            .expect("one Welcome action");
        let welcome_event = exact_event(&welcome_action);
        assert_eq!(welcome_event.kind, 1059);
        accept_exact_action(&mut alice, &welcome_action).await;
        let alice_conversations = alice.projections.list_conversations(8);
        assert_eq!(alice_conversations.len(), 1);
        assert!(matches!(
            alice_conversations[0].state,
            ConversationState::Ready
        ));

        let (welcome_outcome, welcome_update) = bob
            .ingest_event(welcome_event)
            .await
            .expect("Bob ingests Welcome");
        assert!(matches!(welcome_outcome, IpcIngestOutcome::Processed));
        let joined = bob.joined_conversations(&welcome_update);
        assert_eq!(joined.len(), 1);
        assert!(joined[0]
            .conversation_id
            .starts_with(CONVERSATION_ID_PREFIX));
        assert!(matches!(joined[0].state, ConversationState::Ready));
        let bob_conversation_id = joined[0].conversation_id.clone();
        assert_eq!(
            welcome_update.changed_conversation_ids,
            vec![bob_conversation_id.clone()]
        );

        let (outgoing, queued_behind_transition) = alice
            .send_message(
                &pending.conversation_id,
                1_700_000_001,
                "hello over Marmot".into(),
            )
            .await
            .expect("Alice queues encrypted text");
        assert!(!queued_behind_transition);
        assert_eq!(outgoing.conversation_id, pending.conversation_id);
        assert_eq!(outgoing.author_public_key, alice.account_public_key);
        assert_eq!(outgoing.delivery, MessageDeliveryState::PendingPublication);
        assert_eq!(
            alice
                .projections
                .list_messages(&pending.conversation_id, 8)
                .expect("known Alice conversation"),
            vec![outgoing]
        );
        let message_action = alice
            .next_action()
            .await
            .expect("prepare group message")
            .expect("one group message action");
        let message_event = exact_event(&message_action);
        assert_eq!(message_event.kind, 445);
        assert!(!message_event.content.contains("hello over Marmot"));
        let alice_plan = alice.subscription_plan().expect("Alice route plan");
        let bob_plan = bob.subscription_plan().expect("Bob route plan");
        assert_eq!(alice_plan.len(), 1);
        assert_eq!(bob_plan.len(), 1);
        assert_ne!(alice_plan[0].conversation_id, bob_plan[0].conversation_id);
        assert_eq!(alice_plan[0].route, bob_plan[0].route);
        assert!(message_event.tags.iter().any(|tag| {
            tag.first().is_some_and(|name| name == "h")
                && tag
                    .get(1)
                    .is_some_and(|value| value == &alice_plan[0].route)
        }));
        accept_exact_action(&mut alice, &message_action).await;

        let (message_outcome, message_update) = bob
            .ingest_event(message_event.clone())
            .await
            .expect("Bob decrypts group message");
        assert!(matches!(message_outcome, IpcIngestOutcome::Processed));
        assert_eq!(message_update.delivered_messages, 1);
        assert_eq!(message_update.rejected_messages, 0);
        assert_eq!(message_update.changed_message_ids.len(), 1);
        let messages = bob
            .projections
            .list_messages(&bob_conversation_id, 8)
            .expect("known Bob conversation");
        assert_eq!(messages.len(), 1);
        assert!(messages[0].message_id.starts_with(MESSAGE_ID_PREFIX));
        assert_eq!(messages[0].content, "hello over Marmot");
        assert_eq!(messages[0].author_public_key, alice.account_public_key);
        assert_eq!(messages[0].delivery, MessageDeliveryState::Received);
        assert_eq!(
            message_update.changed_message_ids,
            vec![messages[0].message_id.clone()]
        );

        let (duplicate_outcome, duplicate_update) = bob
            .ingest_event(message_event)
            .await
            .expect("duplicate event is classifiable");
        assert!(matches!(
            duplicate_outcome,
            IpcIngestOutcome::Stale {
                reason: IpcStaleReason::AlreadySeen
            }
        ));
        assert_eq!(duplicate_update.delivered_messages, 0);
        assert_eq!(
            bob.projections
                .list_messages(&bob_conversation_id, 8)
                .expect("known Bob conversation")
                .len(),
            1
        );
    }
}
