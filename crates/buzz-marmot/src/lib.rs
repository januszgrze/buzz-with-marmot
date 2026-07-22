//! Native Marmot account-device runtime for Buzz.
//!
//! This crate is a deliberately narrow boundary around upstream MDK. It owns
//! platform wiring (Nostr account identity, encrypted database configuration,
//! and the Nostr transport peeler), while MDK continues to own MLS state and
//! protocol transitions.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::{
    fmt,
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::key_package::key_package_metadata;
use cgka_session::{
    AccountDeviceSession, IngestEffects, PublishWork, QueuedIntentRef, SessionConfig,
    SessionEffects,
};
use cgka_traits::{
    app_components::{
        decode_nostr_routing_v1, default_group_components, encode_nostr_routing_v1,
        AppComponentData, NostrRoutingV1, NOSTR_ROUTING_COMPONENT_ID,
    },
    app_event::{MarmotAppEvent, MARMOT_APP_EVENT_KIND_CHAT},
    engine::{CreateGroupRequest, GroupEvent, KeyPackage, SendIntent},
    engine_state::PendingStateRef,
    ingest::IngestOutcome,
    types::GroupId,
};
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr::base64::Engine as _;
use nostr::{Event, Keys};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use storage_sqlite::{open_hardened_sqlcipher, SqlCipherHardening, SqlCipherKey};
use transport_nostr_peeler::{NostrMlsPeeler, NostrPeelerError, NostrTransportEvent};
use zeroize::Zeroizing;

/// Errors produced while opening or using a native Marmot device.
#[derive(Debug, thiserror::Error)]
pub enum MarmotError {
    /// The SQLCipher key could not be constructed.
    #[error("invalid Marmot database key: {0}")]
    DatabaseKey(String),
    /// The configured database path is not a safe native file target.
    #[error("invalid Marmot database path: {0}")]
    DatabasePath(String),
    /// An existing encrypted database predates the required account binding.
    #[error("existing Marmot database is missing its account binding")]
    AccountBindingMissing,
    /// The encrypted database belongs to a different Nostr account.
    #[error("Marmot database belongs to a different account")]
    AccountBindingMismatch,
    /// The encrypted account binding could not be read or persisted.
    #[error("Marmot database account binding: {0}")]
    AccountBinding(String),
    /// MDK could not open or restore the account-device session.
    #[error("Marmot session: {0}")]
    Session(#[from] cgka_session::SessionError),
    /// MDK could not perform an MLS operation.
    #[error("Marmot engine: {0}")]
    Engine(#[from] cgka_traits::error::EngineError),
    /// A Marmot inner application event was malformed.
    #[error("Marmot application event: {0}")]
    ApplicationEvent(#[from] cgka_traits::app_event::MarmotAppEventError),
    /// A Marmot Nostr transport event was malformed.
    #[error("Marmot Nostr transport: {0}")]
    Transport(#[from] NostrPeelerError),
    /// The requested Marmot group configuration was invalid.
    #[error("invalid Marmot group configuration: {0}")]
    GroupConfiguration(String),
    /// A relay-fetched Marmot KeyPackage event failed closed validation.
    #[error("invalid Marmot KeyPackage event: {0}")]
    KeyPackageEvent(String),
    /// Persisted group-id bytes were empty, oversized, or unknown to MDK.
    #[error("invalid persisted Marmot group id: {0}")]
    GroupIdentifier(String),
}

/// A 256-bit key used to encrypt the local MDK SQLCipher database.
///
/// This key must be generated independently from the user's Nostr secret and
/// stored using the operating system keyring. Its debug representation is
/// always redacted and its in-memory bytes are zeroized on drop.
pub struct MarmotDatabaseKey(Zeroizing<[u8; 32]>);

impl MarmotDatabaseKey {
    /// Wrap an independently generated 256-bit database key.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn to_sqlcipher_key(&self) -> Result<SqlCipherKey, MarmotError> {
        SqlCipherKey::new(hex::encode(self.0.as_ref()))
            .map_err(|error| MarmotError::DatabaseKey(error.to_string()))
    }
}

impl fmt::Debug for MarmotDatabaseKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MarmotDatabaseKey")
            .field(&"<redacted>")
            .finish()
    }
}

/// Configuration needed to open one desktop Marmot account-device.
///
/// The account key is used only for Marmot's Nostr account identity proof and
/// NIP-59 Welcome handling. MDK generates and persists independent MLS keys.
pub struct MarmotDeviceConfig {
    database_path: PathBuf,
    database_key: MarmotDatabaseKey,
    account_keys: Keys,
}

impl MarmotDeviceConfig {
    /// Create a device configuration backed by an encrypted database file.
    #[must_use]
    pub fn new(
        database_path: impl Into<PathBuf>,
        database_key: MarmotDatabaseKey,
        account_keys: Keys,
    ) -> Self {
        Self {
            database_path: database_path.into(),
            database_key,
            account_keys,
        }
    }
}

/// A native MDK account-device session.
///
/// Callers must serialize state-advancing operations on this value. Relay
/// publication and publish-before-apply resolution will be added above this
/// boundary; no transport publication occurs inside this initial adapter.
pub struct MarmotDevice {
    account_public_key: [u8; 32],
    session: AccountDeviceSession,
}

impl MarmotDevice {
    /// Open or restore the encrypted MDK account-device session.
    pub fn open(config: MarmotDeviceConfig) -> Result<Self, MarmotError> {
        let database_path = normalize_database_path(&config.database_path)?;
        let account_public_key = config.account_keys.public_key().to_bytes();
        let database_key = config.database_key.to_sqlcipher_key()?;
        bind_database_to_account(&database_path, &database_key, &account_public_key)?;
        let proof_signer = Arc::new(NostrAccountIdentityProofSigner {
            keys: config.account_keys.clone(),
        });
        let peeler = NostrMlsPeeler::new().with_welcome_signer(config.account_keys);

        let mut supported_components = default_group_components();
        supported_components.insert(NOSTR_ROUTING_COMPONENT_ID);

        let session = AccountDeviceSession::open(
            SessionConfig::new(
                database_path,
                database_key,
                account_public_key.to_vec(),
                Box::new(peeler),
            )
            .account_identity_proof_signer(proof_signer)
            .supported_app_components(supported_components),
        )?;

        Ok(Self {
            account_public_key,
            session,
        })
    }

    /// Return the Nostr account public key bound to this MDK device.
    #[must_use]
    pub fn account_public_key(&self) -> [u8; 32] {
        self.account_public_key
    }

    /// Drain effects emitted while opening or hydrating the persisted session.
    ///
    /// Call this immediately after [`Self::open`] so quarantined-group and
    /// recovery notifications are not deferred until the next operation.
    #[must_use]
    pub fn drain_effects(&mut self) -> MarmotEffects {
        MarmotEffects(self.session.drain())
    }

    /// Generate and persist a fresh Marmot MLS KeyPackage.
    ///
    /// The returned public bytes are suitable for a Marmot kind `30443`
    /// publication. MDK keeps the corresponding private init key in the
    /// encrypted device database.
    pub async fn fresh_key_package(&mut self) -> Result<MarmotKeyPackage, MarmotError> {
        let key_package: KeyPackage = self.session.fresh_key_package().await?;
        Ok(MarmotKeyPackage {
            bytes: key_package.bytes().to_vec(),
            source_event_id: None,
        })
    }

    /// Reconstruct a group id only after the open MDK session confirms that it
    /// names a live group hydrated from this account's encrypted database.
    ///
    /// This is the safe restart boundary for an id persisted by the desktop
    /// application. It does not accept an arbitrary opaque id merely because
    /// its byte representation is syntactically non-empty.
    pub fn restore_group_id(&self, persisted_bytes: &[u8]) -> Result<MarmotGroupId, MarmotError> {
        const MAX_PERSISTED_GROUP_ID_BYTES: usize = 1024;
        if persisted_bytes.is_empty() {
            return Err(MarmotError::GroupIdentifier(
                "group id must not be empty".into(),
            ));
        }
        if persisted_bytes.len() > MAX_PERSISTED_GROUP_ID_BYTES {
            return Err(MarmotError::GroupIdentifier(
                "group id exceeds the native lookup limit".into(),
            ));
        }

        let group_id = GroupId::new(persisted_bytes.to_vec());
        self.session.group_record(&group_id).map_err(|_| {
            MarmotError::GroupIdentifier("group is not present in the active MDK session".into())
        })?;
        Ok(MarmotGroupId(group_id))
    }

    /// Read MLS-authenticated group metadata and Nostr routing after restart.
    ///
    /// The id must come from [`Self::restore_group_id`]. MDK remains the source
    /// of truth for both the group record and its signed app-component state.
    pub fn group_snapshot(
        &self,
        group_id: &MarmotGroupId,
    ) -> Result<MarmotGroupSnapshot, MarmotError> {
        let group = self.session.group_record(&group_id.0)?;
        let routing_bytes = self
            .session
            .app_component(&group_id.0, NOSTR_ROUTING_COMPONENT_ID)?
            .ok_or_else(|| {
                MarmotError::GroupConfiguration(
                    "hydrated group is missing its required Nostr routing component".into(),
                )
            })?;
        let routing =
            decode_nostr_routing_v1(&routing_bytes).map_err(MarmotError::GroupConfiguration)?;

        Ok(MarmotGroupSnapshot {
            group_id: group_id.clone(),
            name: group.name,
            description: group.description,
            epoch: group.epoch.0,
            member_ids: group
                .members
                .into_iter()
                .map(|member| member.id.into_bytes())
                .collect(),
            nostr_group_id: routing.nostr_group_id,
            relays: routing.relays,
        })
    }

    /// Create a Marmot group and stage its initial MLS state.
    ///
    /// Each member KeyPackage must have been published first and carry the
    /// resulting Nostr event id. The returned effects contain the Welcome
    /// publication and its pending state handle. Callers must publish every
    /// item and resolve every pending transition; the adapter deliberately
    /// does not discard auxiliary events, queued intents, or convergence work.
    pub async fn create_group(
        &mut self,
        config: MarmotGroupConfig,
        members: Vec<MarmotKeyPackage>,
    ) -> Result<MarmotGroupCreation, MarmotError> {
        let routing = NostrRoutingV1::new(config.nostr_group_id, config.relays)
            .map_err(MarmotError::GroupConfiguration)?;
        let routing = AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: encode_nostr_routing_v1(&routing).map_err(MarmotError::GroupConfiguration)?,
        };
        let members = members
            .into_iter()
            .map(MarmotKeyPackage::into_mdk_key_package)
            .collect::<Result<Vec<_>, _>>()?;
        let created = self
            .session
            .create_group(CreateGroupRequest {
                name: config.name,
                description: config.description,
                members,
                required_features: vec![],
                app_components: vec![routing],
                initial_admins: vec![],
            })
            .await?;

        Ok(MarmotGroupCreation {
            group_id: MarmotGroupId(created.group_id),
            effects: MarmotEffects(created.effects),
        })
    }

    /// Mark a staged Marmot state transition as durably published.
    ///
    /// Confirmation can itself release buffered input, queued sends, automatic
    /// proposals, and convergence work. The complete effect set must therefore
    /// be processed just like the result of any other state-advancing call.
    pub async fn confirm_published(
        &mut self,
        pending: MarmotPendingPublication,
    ) -> Result<MarmotEffects, MarmotError> {
        // Publication has already escaped to at least one relay by the time
        // this method runs. A transient backend lock must therefore not leave
        // this device behind an epoch its peers can ingest. Upstream
        // `marmot-account` applies the same bounded retry policy, and MDK keeps
        // the in-memory transition retry-safe until its durable transaction
        // commits.
        const MAX_CONFIRM_ATTEMPTS: u32 = 4;
        let mut attempt = 0;
        loop {
            match self.session.confirm_published(pending.0).await {
                Ok(effects) => return Ok(MarmotEffects(effects)),
                Err(error) if error.is_transient() && attempt + 1 < MAX_CONFIRM_ATTEMPTS => {
                    attempt += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Roll back a staged Marmot transition after its publication fails.
    ///
    /// The returned effects may contain newly released queued work and must be
    /// processed by the caller.
    pub async fn publication_failed(
        &mut self,
        pending: MarmotPendingPublication,
    ) -> Result<MarmotEffects, MarmotError> {
        Ok(MarmotEffects(self.session.publish_failed(pending.0).await?))
    }

    /// Advance deterministic fork convergence for one group.
    ///
    /// Call this for each group reported by
    /// [`MarmotEffects::pending_convergence_groups`] and continue processing
    /// returned effects until no convergence work remains.
    pub async fn advance_convergence(
        &mut self,
        group_id: &MarmotGroupId,
    ) -> Result<MarmotEffects, MarmotError> {
        Ok(MarmotEffects(
            self.session.advance_convergence(&group_id.0).await?,
        ))
    }

    /// Ingest a NIP-59 Marmot Welcome.
    ///
    /// Inspect [`MarmotIngestResult::outcome`] before acting on the event and
    /// process every returned effect. A successful Welcome normally includes
    /// a [`GroupEvent::GroupJoined`] event, available through
    /// [`MarmotEffects::joined_group_ids`].
    pub async fn accept_welcome(
        &mut self,
        welcome: NostrTransportEvent,
    ) -> Result<MarmotIngestResult, MarmotError> {
        let message = welcome.to_transport_message()?;
        let ingested = self.session.ingest(message).await?;
        Ok(MarmotIngestResult::from_mdk(ingested))
    }

    /// Encrypt one text message and return MDK's complete effect set.
    ///
    /// An immediately sendable message appears as
    /// [`PublishWork::ApplicationMessage`], whose outer event signer is an
    /// upstream-generated one-time ephemeral Nostr key. If the group is
    /// temporarily unstable, MDK may instead return a queued intent.
    pub async fn send_text(
        &mut self,
        group_id: &MarmotGroupId,
        created_at: u64,
        content: impl Into<String>,
    ) -> Result<MarmotEffects, MarmotError> {
        let event = MarmotAppEvent::new(
            hex::encode(self.session.self_id().as_slice()),
            created_at,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            content,
        );
        let effects = self
            .session
            .send(SendIntent::AppMessage {
                group_id: group_id.0.clone(),
                payload: event.encode()?,
            })
            .await?;
        Ok(MarmotEffects(effects))
    }

    /// Ingest one kind `445` event and return its complete MDK result.
    ///
    /// MDK authenticates the MLS sender. This adapter additionally verifies
    /// that the inner Nostr-shaped event's `pubkey` matches that sender before
    /// returning plaintext from
    /// [`MarmotEffects::decoded_application_messages`]. Protocol events and
    /// mandatory publication/state work remain available even if an inner app
    /// event fails validation.
    pub async fn ingest_group_event(
        &mut self,
        event: NostrTransportEvent,
    ) -> Result<MarmotIngestResult, MarmotError> {
        let message = event.to_transport_message()?;
        let ingested = self.session.ingest(message).await?;
        Ok(MarmotIngestResult::from_mdk(ingested))
    }
}

const ACCOUNT_BINDING_TABLE: &str = "buzz_marmot_account_binding";
const ACCOUNT_BINDING_SCHEMA_VERSION: i64 = 1;

fn normalize_database_path(path: &Path) -> Result<PathBuf, MarmotError> {
    if !path.is_absolute() {
        return Err(MarmotError::DatabasePath(
            "database path must be absolute".into(),
        ));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| MarmotError::DatabasePath("database path must name a file".into()))?;
    let parent = path.parent().ok_or_else(|| {
        MarmotError::DatabasePath("database path must have a parent directory".into())
    })?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        MarmotError::DatabasePath(format!("database parent is unavailable: {error}"))
    })?;
    let normalized = canonical_parent.join(file_name);

    match std::fs::symlink_metadata(&normalized) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(MarmotError::DatabasePath(
            "database file must not be a symbolic link".into(),
        )),
        Ok(metadata) if !metadata.is_file() => Err(MarmotError::DatabasePath(
            "database path is not a regular file".into(),
        )),
        Ok(_) => Ok(normalized),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(normalized),
        Err(error) => Err(MarmotError::DatabasePath(format!(
            "database file metadata is unavailable: {error}"
        ))),
    }
}

fn bind_database_to_account(
    path: &Path,
    key: &SqlCipherKey,
    account_public_key: &[u8; 32],
) -> Result<(), MarmotError> {
    let existed_with_data = match std::fs::metadata(path) {
        Ok(metadata) => metadata.len() > 0,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            options.open(path).map_err(|open_error| {
                MarmotError::DatabasePath(format!("could not create database file: {open_error}"))
            })?;
            false
        }
        Err(error) => {
            return Err(MarmotError::DatabasePath(format!(
                "could not inspect database file: {error}"
            )));
        }
    };

    let mut connection =
        Connection::open(path).map_err(|error| MarmotError::AccountBinding(error.to_string()))?;
    open_hardened_sqlcipher(&connection, key, SqlCipherHardening::live_cache())
        .map_err(|error| MarmotError::AccountBinding(error.to_string()))?;

    let table_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1 LIMIT 1",
            [ACCOUNT_BINDING_TABLE],
            |_| Ok(()),
        )
        .optional()
        .map_err(|error| MarmotError::AccountBinding(error.to_string()))?
        .is_some();

    if table_exists {
        let mut statement = connection
            .prepare(&format!(
                "SELECT schema_version, account_public_key FROM {ACCOUNT_BINDING_TABLE} \
                 WHERE singleton = 1"
            ))
            .map_err(|error| MarmotError::AccountBinding(error.to_string()))?;
        let binding = statement
            .query_row([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .optional()
            .map_err(|error| MarmotError::AccountBinding(error.to_string()))?;
        let Some((schema_version, stored_public_key)) = binding else {
            return Err(MarmotError::AccountBinding(
                "binding table does not contain its singleton row".into(),
            ));
        };
        if schema_version != ACCOUNT_BINDING_SCHEMA_VERSION || stored_public_key.len() != 32 {
            return Err(MarmotError::AccountBinding(
                "binding row has an unsupported shape".into(),
            ));
        }
        if stored_public_key.as_slice() != account_public_key {
            return Err(MarmotError::AccountBindingMismatch);
        }
        return Ok(());
    }

    let existing_user_tables = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| MarmotError::AccountBinding(error.to_string()))?;
    if existed_with_data || existing_user_tables != 0 {
        return Err(MarmotError::AccountBindingMissing);
    }

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| MarmotError::AccountBinding(error.to_string()))?;
    transaction
        .execute_batch(&format!(
            "CREATE TABLE {ACCOUNT_BINDING_TABLE} (\
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
                 schema_version INTEGER NOT NULL,\
                 account_public_key BLOB NOT NULL CHECK (length(account_public_key) = 32)\
             ) STRICT;"
        ))
        .map_err(|error| MarmotError::AccountBinding(error.to_string()))?;
    transaction
        .execute(
            &format!(
                "INSERT INTO {ACCOUNT_BINDING_TABLE} \
                 (singleton, schema_version, account_public_key) VALUES (1, ?1, ?2)"
            ),
            rusqlite::params![
                ACCOUNT_BINDING_SCHEMA_VERSION,
                account_public_key.as_slice()
            ],
        )
        .map_err(|error| MarmotError::AccountBinding(error.to_string()))?;
    transaction
        .commit()
        .map_err(|error| MarmotError::AccountBinding(error.to_string()))?;
    Ok(())
}

/// Nostr routing and display metadata for a new Marmot group.
pub struct MarmotGroupConfig {
    name: String,
    description: String,
    nostr_group_id: [u8; 32],
    relays: Vec<String>,
}

impl MarmotGroupConfig {
    /// Build a group configuration with an explicit random Nostr routing id.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        nostr_group_id: [u8; 32],
        relays: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            nostr_group_id,
            relays,
        }
    }
}

/// Opaque MLS group identifier owned by upstream MDK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotGroupId(GroupId);

impl MarmotGroupId {
    /// Borrow the encoded MLS group id.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// MLS-authenticated group metadata projected for the desktop sidecar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotGroupSnapshot {
    group_id: MarmotGroupId,
    name: String,
    description: String,
    epoch: u64,
    member_ids: Vec<Vec<u8>>,
    nostr_group_id: [u8; 32],
    relays: Vec<String>,
}

impl MarmotGroupSnapshot {
    /// Return the opaque MLS group id.
    #[must_use]
    pub fn group_id(&self) -> &MarmotGroupId {
        &self.group_id
    }

    /// Return the signed group name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the signed group description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Return the current MLS epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Return stable Marmot member identifiers from the hydrated group record.
    #[must_use]
    pub fn member_ids(&self) -> &[Vec<u8>] {
        &self.member_ids
    }

    /// Return the random Nostr `h`-tag route id from signed group state.
    #[must_use]
    pub fn nostr_group_id(&self) -> [u8; 32] {
        self.nostr_group_id
    }

    /// Return the validated Nostr relay URLs from signed group state.
    #[must_use]
    pub fn relays(&self) -> &[String] {
        &self.relays
    }
}

/// Initial group state and its complete set of MDK effects.
#[derive(Debug)]
pub struct MarmotGroupCreation {
    group_id: MarmotGroupId,
    effects: MarmotEffects,
}

impl MarmotGroupCreation {
    /// Return the newly allocated MLS group id.
    #[must_use]
    pub fn group_id(&self) -> &MarmotGroupId {
        &self.group_id
    }

    /// Return every effect produced while creating the group.
    #[must_use]
    pub fn effects(&self) -> &MarmotEffects {
        &self.effects
    }

    /// Consume this result into its group id and complete effect set.
    #[must_use]
    pub fn into_parts(self) -> (MarmotGroupId, MarmotEffects) {
        (self.group_id, self.effects)
    }
}

/// Opaque handle for MDK's publish-before-apply state transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarmotPendingPublication(PendingStateRef);

impl MarmotPendingPublication {
    /// Wrap a pending handle returned by one of the exposed MDK publication
    /// work variants.
    #[must_use]
    pub fn from_mdk(pending: PendingStateRef) -> Self {
        Self(pending)
    }

    /// Return MDK's process-local pending transition identifier.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.0.as_u64()
    }

    /// Return the native MDK pending handle.
    #[must_use]
    pub fn into_mdk(self) -> PendingStateRef {
        self.0
    }
}

/// The complete side effects produced by one MDK state-advancing operation.
///
/// Callers must handle all four collections. In particular, publication work
/// can contain automatic proposals in addition to the item directly requested,
/// and confirming a pending publication can produce another non-empty effect
/// set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotEffects(SessionEffects);

impl MarmotEffects {
    /// Return ordered, MLS-authenticated application and group-state events.
    #[must_use]
    pub fn events(&self) -> &[GroupEvent] {
        &self.0.events
    }

    /// Return every transport publication MDK requires the caller to perform.
    #[must_use]
    pub fn publish_work(&self) -> &[PublishWork] {
        &self.0.publish
    }

    /// Return sends MDK durably queued behind an in-flight state transition.
    #[must_use]
    pub fn queued_intents(&self) -> &[QueuedIntentRef] {
        &self.0.queued
    }

    /// Return groups whose stored forks require deterministic convergence.
    #[must_use]
    pub fn pending_convergence_groups(&self) -> Vec<MarmotGroupId> {
        self.0
            .pending_convergence
            .iter()
            .cloned()
            .map(MarmotGroupId)
            .collect()
    }

    /// Whether MDK produced no observable or follow-up work.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return all MLS groups joined by the operation.
    #[must_use]
    pub fn joined_group_ids(&self) -> Vec<MarmotGroupId> {
        self.0
            .events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::GroupJoined { group_id, .. } => Some(MarmotGroupId(group_id.clone())),
                _ => None,
            })
            .collect()
    }

    /// Decode and sender-validate every received Marmot application message.
    ///
    /// The underlying effects remain owned by this value if decoding fails, so
    /// callers can still process unrelated protocol events and mandatory
    /// follow-up work without treating malformed plaintext as a chat message.
    pub fn decoded_application_messages(
        &self,
    ) -> Result<Vec<MarmotApplicationMessage>, MarmotError> {
        self.decoded_application_message_results()
            .into_iter()
            .collect()
    }

    /// Decode each MLS-authenticated application payload independently.
    ///
    /// The returned vector preserves the order of `MessageReceived` effects.
    /// A malformed inner event is represented by one `Err` entry and therefore
    /// cannot suppress valid sibling messages from the same MDK operation.
    #[must_use]
    pub fn decoded_application_message_results(
        &self,
    ) -> Vec<Result<MarmotApplicationMessage, MarmotError>> {
        self.0
            .events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived {
                    group_id,
                    sender,
                    epoch,
                    payload,
                } => Some((group_id, sender, epoch, payload)),
                _ => None,
            })
            .map(|(group_id, sender, epoch, payload)| {
                let event = MarmotAppEvent::decode(payload)?;
                event.validate_sender(&hex::encode(sender.as_slice()))?;
                Ok(MarmotApplicationMessage {
                    group_id: MarmotGroupId(group_id.clone()),
                    sender: sender.as_slice().to_vec(),
                    epoch: epoch.0,
                    event_id: event.id,
                    author_public_key: event.pubkey,
                    created_at: event.created_at,
                    kind: event.kind,
                    tags: event.tags,
                    content: event.content,
                })
            })
            .collect()
    }

    /// Consume the wrapper and return MDK's full native effect value.
    #[must_use]
    pub fn into_mdk(self) -> SessionEffects {
        self.0
    }

    /// Consume this value into events, publication work, queued intents, and
    /// pending convergence groups, in that order.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<GroupEvent>,
        Vec<PublishWork>,
        Vec<QueuedIntentRef>,
        Vec<GroupId>,
    ) {
        (
            self.0.events,
            self.0.publish,
            self.0.queued,
            self.0.pending_convergence,
        )
    }
}

/// The classified outcome and complete effects from one inbound transport
/// message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotIngestResult {
    outcome: IngestOutcome,
    effects: MarmotEffects,
}

impl MarmotIngestResult {
    fn from_mdk(ingested: IngestEffects) -> Self {
        Self {
            outcome: ingested.outcome,
            effects: MarmotEffects(ingested.effects),
        }
    }

    /// Return whether MDK processed, buffered, or classified the message as
    /// stale.
    #[must_use]
    pub fn outcome(&self) -> &IngestOutcome {
        &self.outcome
    }

    /// Return all events and mandatory follow-up work caused by the message.
    #[must_use]
    pub fn effects(&self) -> &MarmotEffects {
        &self.effects
    }

    /// Consume this result into its classified outcome and complete effects.
    #[must_use]
    pub fn into_parts(self) -> (IngestOutcome, MarmotEffects) {
        (self.outcome, self.effects)
    }
}

/// One MLS-authenticated and decrypted Marmot application message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotApplicationMessage {
    group_id: MarmotGroupId,
    sender: Vec<u8>,
    epoch: u64,
    event_id: String,
    author_public_key: String,
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
}

impl MarmotApplicationMessage {
    /// Return the MLS group that authenticated this message.
    #[must_use]
    pub fn group_id(&self) -> &MarmotGroupId {
        &self.group_id
    }

    /// Return the MLS-authenticated sender public key bytes.
    #[must_use]
    pub fn sender(&self) -> &[u8] {
        &self.sender
    }

    /// Return the MLS epoch in which the message was received.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Return the canonical id of the inner Nostr-shaped event.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Return the inner event author after validation against the MLS sender.
    #[must_use]
    pub fn author_public_key(&self) -> &str {
        &self.author_public_key
    }

    /// Return the sender-authenticated inner event timestamp.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Return the inner Marmot application event kind.
    #[must_use]
    pub fn kind(&self) -> u64 {
        self.kind
    }

    /// Return the inner Marmot application event tags.
    #[must_use]
    pub fn tags(&self) -> &[Vec<String>] {
        &self.tags
    }

    /// Return the decrypted application event content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
}

/// Public MLS KeyPackage bytes prepared by MDK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotKeyPackage {
    bytes: Vec<u8>,
    source_event_id: Option<[u8; 32]>,
}

impl MarmotKeyPackage {
    /// Validate a full signed Marmot kind `30443` event and attach its event id
    /// as Welcome provenance.
    ///
    /// This verifies the NIP-01 id and signature before trusting any field,
    /// enforces the current Marmot tag/base64 shape, validates the decoded MLS
    /// KeyPackage and account-identity proof through pinned MDK, and requires
    /// both the outer author and `i` tag to match decoded KeyPackage metadata.
    pub fn from_signed_key_package_event(event: &Event) -> Result<Self, MarmotError> {
        event.verify().map_err(|_| {
            MarmotError::KeyPackageEvent("NIP-01 id or signature verification failed".into())
        })?;
        if event.kind.as_u16() != 30_443 {
            return Err(MarmotError::KeyPackageEvent(
                "event kind must be 30443".into(),
            ));
        }

        let transport = NostrTransportEvent::from_nostr_event(event)?;
        validate_key_package_tags(&transport)?;
        let bytes = BASE64_STANDARD
            .decode(transport.content.as_bytes())
            .map_err(|_| MarmotError::KeyPackageEvent("content is not standard base64".into()))?;
        if bytes.is_empty() || BASE64_STANDARD.encode(&bytes) != transport.content {
            return Err(MarmotError::KeyPackageEvent(
                "content is empty or non-canonical base64".into(),
            ));
        }

        let key_package = KeyPackage::with_source_event_id(
            bytes.clone(),
            cgka_traits::types::MessageId::new(event.id.as_bytes().to_vec()),
        );
        let metadata = key_package_metadata(&key_package).map_err(|_| {
            MarmotError::KeyPackageEvent("content is not a valid Marmot MLS KeyPackage".into())
        })?;
        if metadata.credential_identity_hex != event.pubkey.to_hex() {
            return Err(MarmotError::KeyPackageEvent(
                "event author does not match the KeyPackage account identity".into(),
            ));
        }
        if metadata.key_package_ref_hex != exact_single_tag(&transport, "i", is_lower_hex_32)? {
            return Err(MarmotError::KeyPackageEvent(
                "i tag does not match the decoded KeyPackageRef".into(),
            ));
        }

        Ok(Self {
            bytes,
            source_event_id: Some(event.id.to_bytes()),
        })
    }

    /// Borrow the encoded MLS KeyPackage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper and return the encoded MLS KeyPackage.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn into_mdk_key_package(self) -> Result<KeyPackage, MarmotError> {
        let event_id = self.source_event_id.ok_or_else(|| {
            MarmotError::GroupConfiguration(
                "invitee KeyPackage is missing its kind 30443 event id".into(),
            )
        })?;
        Ok(KeyPackage::with_source_event_id(
            self.bytes,
            cgka_traits::types::MessageId::new(event_id.to_vec()),
        ))
    }
}

const KEY_PACKAGE_TAGS: [&str; 7] = [
    "d",
    "mls_protocol_version",
    "i",
    "mls_ciphersuite",
    "mls_extensions",
    "mls_proposals",
    "app_components",
];

fn validate_key_package_tags(event: &NostrTransportEvent) -> Result<(), MarmotError> {
    if event.tags.iter().any(|tag| {
        tag.first()
            .is_none_or(|name| !KEY_PACKAGE_TAGS.contains(&name.as_str()))
    }) {
        return Err(MarmotError::KeyPackageEvent(
            "event contains an unsupported tag".into(),
        ));
    }

    exact_single_tag(event, "d", |value| !value.is_empty())?;
    exact_single_tag(event, "mls_protocol_version", |value| value == "1.0")?;
    exact_single_tag(event, "i", is_lower_hex_32)?;
    validate_id_list_tag(event, "mls_ciphersuite", None)?;
    validate_id_list_tag(event, "mls_extensions", Some("0xf2f1"))?;
    validate_id_list_tag(event, "mls_proposals", None)?;
    validate_id_list_tag(event, "app_components", None)?;
    Ok(())
}

fn exact_single_tag<'a>(
    event: &'a NostrTransportEvent,
    name: &str,
    predicate: impl FnOnce(&str) -> bool,
) -> Result<&'a str, MarmotError> {
    let mut matches = event
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|candidate| candidate == name));
    let tag = matches
        .next()
        .ok_or_else(|| MarmotError::KeyPackageEvent(format!("event is missing its {name} tag")))?;
    if matches.next().is_some()
        || tag.len() != 2
        || !tag.get(1).is_some_and(|value| predicate(value))
    {
        return Err(MarmotError::KeyPackageEvent(format!(
            "event has an invalid {name} tag"
        )));
    }
    Ok(&tag[1])
}

fn validate_id_list_tag(
    event: &NostrTransportEvent,
    name: &str,
    required: Option<&str>,
) -> Result<(), MarmotError> {
    let mut matches = event
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|candidate| candidate == name));
    let tag = matches
        .next()
        .ok_or_else(|| MarmotError::KeyPackageEvent(format!("event is missing its {name} tag")))?;
    if matches.next().is_some() || tag.len() < 2 {
        return Err(MarmotError::KeyPackageEvent(format!(
            "event has an invalid {name} tag"
        )));
    }
    let values = &tag[1..];
    if values.iter().any(|value| !is_canonical_u16_id(value)) {
        return Err(MarmotError::KeyPackageEvent(format!(
            "event has a non-canonical {name} id"
        )));
    }
    let unique = values.iter().collect::<std::collections::BTreeSet<_>>();
    if unique.len() != values.len()
        || required.is_some_and(|value| !values.iter().any(|v| v == value))
    {
        return Err(MarmotError::KeyPackageEvent(format!(
            "event has an invalid {name} id list"
        )));
    }
    Ok(())
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_u16_id(value: &str) -> bool {
    value.len() == 6
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone)]
struct NostrAccountIdentityProofSigner {
    keys: Keys,
}

impl AccountIdentityProofSigner for NostrAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err(
                "identity-proof request does not match the configured Nostr account".into(),
            );
        }

        let event = request.proof_event().and_then(|event| {
            event
                .sign_with_keys(&self.keys)
                .map_err(|error| error.to_string())
        })?;
        request.signature_from_signed_event(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Kind, Tag};
    use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP};

    fn account_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("fixed test secret is a valid Nostr key")
    }

    fn second_account_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000002")
            .expect("fixed test secret is a valid Nostr key")
    }

    fn signed_key_package_event(keys: &Keys, key_package: &MarmotKeyPackage) -> Event {
        let metadata = key_package_metadata(&KeyPackage::new(key_package.as_bytes().to_vec()))
            .expect("fresh MDK KeyPackage has valid metadata");
        EventBuilder::new(
            Kind::Custom(30_443),
            BASE64_STANDARD.encode(key_package.as_bytes()),
        )
        .tags([
            Tag::parse([
                "d",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ])
            .expect("d tag"),
            Tag::parse(["mls_protocol_version", "1.0"]).expect("version tag"),
            Tag::parse(["i", metadata.key_package_ref_hex.as_str()]).expect("i tag"),
            Tag::parse(["mls_ciphersuite", "0x0001"]).expect("ciphersuite tag"),
            Tag::parse(["mls_extensions", "0xf2f1"]).expect("extensions tag"),
            Tag::parse(["mls_proposals", "0x0001"]).expect("proposals tag"),
            Tag::parse(["app_components", "0x0001"]).expect("components tag"),
        ])
        .sign_with_keys(keys)
        .expect("sign kind 30443 event")
    }

    #[tokio::test]
    async fn opens_real_mdk_session_and_persists_key_packages() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database_path = directory.path().join("marmot.sqlite3");
        let expected_public_key = account_keys().public_key().to_bytes();

        let mut device = MarmotDevice::open(MarmotDeviceConfig::new(
            &database_path,
            MarmotDatabaseKey::new([0xA5; 32]),
            account_keys(),
        ))
        .expect("open encrypted MDK session");
        assert_eq!(device.account_public_key(), expected_public_key);

        let first = device
            .fresh_key_package()
            .await
            .expect("generate KeyPackage with upstream MDK");
        assert!(!first.as_bytes().is_empty());
        drop(device);

        let mut reopened = MarmotDevice::open(MarmotDeviceConfig::new(
            database_path,
            MarmotDatabaseKey::new([0xA5; 32]),
            account_keys(),
        ))
        .expect("restore encrypted MDK session");
        let second = reopened
            .fresh_key_package()
            .await
            .expect("generate KeyPackage after restart");

        assert!(!second.as_bytes().is_empty());
        assert_ne!(first, second, "MDK must generate a fresh KeyPackage");
    }

    #[tokio::test]
    async fn encrypted_database_is_bound_to_exactly_one_nostr_account() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database_path = directory.path().join("marmot.sqlite3");
        let database_key = [0xC3; 32];

        let mut first_account = MarmotDevice::open(MarmotDeviceConfig::new(
            &database_path,
            MarmotDatabaseKey::new(database_key),
            account_keys(),
        ))
        .expect("open database for its first account");
        first_account
            .fresh_key_package()
            .await
            .expect("persist real account-scoped MDK state");
        drop(first_account);

        let wrong_account = MarmotDevice::open(MarmotDeviceConfig::new(
            &database_path,
            MarmotDatabaseKey::new(database_key),
            second_account_keys(),
        ));
        assert!(matches!(
            wrong_account,
            Err(MarmotError::AccountBindingMismatch)
        ));

        let mut reopened = MarmotDevice::open(MarmotDeviceConfig::new(
            database_path,
            MarmotDatabaseKey::new(database_key),
            account_keys(),
        ))
        .expect("the bound account can still reopen after the rejected attempt");
        reopened
            .fresh_key_package()
            .await
            .expect("bound account state remains usable");
    }

    #[test]
    fn database_key_debug_output_is_redacted() {
        let key = MarmotDatabaseKey::new([0x42; 32]);
        let rendered = format!("{key:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("42"));
    }

    #[tokio::test]
    async fn group_creation_rejects_an_unpublished_invitee_key_package() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut alice = MarmotDevice::open(MarmotDeviceConfig::new(
            directory.path().join("alice.sqlite3"),
            MarmotDatabaseKey::new([0xA1; 32]),
            account_keys(),
        ))
        .expect("open Alice's real MDK session");
        let mut bob = MarmotDevice::open(MarmotDeviceConfig::new(
            directory.path().join("bob.sqlite3"),
            MarmotDatabaseKey::new([0xB2; 32]),
            second_account_keys(),
        ))
        .expect("open Bob's real MDK session");
        let unpublished = bob
            .fresh_key_package()
            .await
            .expect("Bob creates an upstream MLS KeyPackage");

        let error = alice
            .create_group(
                MarmotGroupConfig::new(
                    "private",
                    "must bind the Welcome to the published KeyPackage event",
                    [0x77; 32],
                    vec!["wss://relay.example".into()],
                ),
                vec![unpublished],
            )
            .await
            .expect_err("an unpublished KeyPackage must fail before group creation");

        assert!(matches!(
            error,
            MarmotError::GroupConfiguration(message)
                if message.contains("missing its kind 30443 event id")
        ));
    }

    #[tokio::test]
    async fn signed_key_package_event_is_fully_validated_before_invitation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let owner_keys = account_keys();
        let mut owner = MarmotDevice::open(MarmotDeviceConfig::new(
            directory.path().join("owner.sqlite3"),
            MarmotDatabaseKey::new([0x61; 32]),
            owner_keys.clone(),
        ))
        .expect("open owner device");
        let local = owner
            .fresh_key_package()
            .await
            .expect("generate real KeyPackage");
        let signed = signed_key_package_event(&owner_keys, &local);

        let validated = MarmotKeyPackage::from_signed_key_package_event(&signed)
            .expect("accept fully valid kind 30443 event");
        assert_eq!(validated.as_bytes(), local.as_bytes());

        let wrong_author = signed_key_package_event(&second_account_keys(), &local);
        assert!(matches!(
            MarmotKeyPackage::from_signed_key_package_event(&wrong_author),
            Err(MarmotError::KeyPackageEvent(message))
                if message.contains("author does not match")
        ));

        let mut tampered = signed.clone();
        tampered.content.push('A');
        assert!(matches!(
            MarmotKeyPackage::from_signed_key_package_event(&tampered),
            Err(MarmotError::KeyPackageEvent(message))
                if message.contains("signature verification failed")
        ));

        let metadata = key_package_metadata(&KeyPackage::new(local.as_bytes().to_vec()))
            .expect("valid KeyPackage metadata");
        let wrong_ref = EventBuilder::new(
            Kind::Custom(30_443),
            BASE64_STANDARD.encode(local.as_bytes()),
        )
        .tags([
            Tag::parse(["d", "slot"]).expect("d tag"),
            Tag::parse(["mls_protocol_version", "1.0"]).expect("version tag"),
            Tag::parse(["i", &"00".repeat(32)]).expect("i tag"),
            Tag::parse(["mls_ciphersuite", "0x0001"]).expect("ciphersuite tag"),
            Tag::parse(["mls_extensions", "0xf2f1"]).expect("extensions tag"),
            Tag::parse(["mls_proposals", "0x0001"]).expect("proposals tag"),
            Tag::parse(["app_components", "0x0001"]).expect("components tag"),
        ])
        .sign_with_keys(&owner_keys)
        .expect("sign mismatched i-tag event");
        assert_ne!(metadata.key_package_ref_hex, "00".repeat(32));
        assert!(matches!(
            MarmotKeyPackage::from_signed_key_package_event(&wrong_ref),
            Err(MarmotError::KeyPackageEvent(message)) if message.contains("i tag does not match")
        ));
    }

    #[test]
    fn per_message_decode_results_preserve_valid_siblings() {
        let group_id = GroupId::new(vec![0x44; 32]);
        let sender = cgka_traits::types::MemberId::new(vec![0x55; 32]);
        let valid_payload = MarmotAppEvent::new(
            hex::encode(sender.as_slice()),
            1_700_000_001,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            "valid sibling",
        )
        .encode()
        .expect("encode valid inner app event");
        let effects = MarmotEffects(SessionEffects {
            events: vec![
                GroupEvent::MessageReceived {
                    group_id: group_id.clone(),
                    sender: sender.clone(),
                    epoch: cgka_traits::types::EpochId(7),
                    payload: b"not a Marmot app event".to_vec(),
                },
                GroupEvent::MessageReceived {
                    group_id,
                    sender,
                    epoch: cgka_traits::types::EpochId(7),
                    payload: valid_payload,
                },
            ],
            publish: vec![],
            queued: vec![],
            pending_convergence: vec![],
        });

        let decoded = effects.decoded_application_message_results();
        assert_eq!(decoded.len(), 2);
        assert!(decoded[0].is_err());
        assert_eq!(
            decoded[1].as_ref().expect("valid sibling").content(),
            "valid sibling"
        );
    }

    #[tokio::test]
    async fn two_buzz_devices_complete_same_revision_mdk_round_trip() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let alice_keys = account_keys();
        let bob_keys = second_account_keys();
        let alice_public_key = alice_keys.public_key().to_hex();
        let bob_public_key = bob_keys.public_key().to_bytes();

        let alice_database_path = directory.path().join("alice.sqlite3");
        let mut alice = MarmotDevice::open(MarmotDeviceConfig::new(
            &alice_database_path,
            MarmotDatabaseKey::new([0xA1; 32]),
            alice_keys,
        ))
        .expect("open Alice's real MDK session");
        let mut bob = MarmotDevice::open(MarmotDeviceConfig::new(
            directory.path().join("bob.sqlite3"),
            MarmotDatabaseKey::new([0xB2; 32]),
            bob_keys,
        ))
        .expect("open Bob's real MDK session");

        let bob_local_key_package = bob
            .fresh_key_package()
            .await
            .expect("Bob creates an upstream MLS KeyPackage");
        let bob_key_package_event =
            signed_key_package_event(&second_account_keys(), &bob_local_key_package);
        let bob_key_package =
            MarmotKeyPackage::from_signed_key_package_event(&bob_key_package_event)
                .expect("Bob's signed kind 30443 event validates");
        let nostr_group_id = [0x77; 32];
        let creation = alice
            .create_group(
                MarmotGroupConfig::new(
                    "round-trip",
                    "same-revision MDK round trip through the Buzz adapter",
                    nostr_group_id,
                    vec!["wss://relay.example".into()],
                ),
                vec![bob_key_package],
            )
            .await
            .expect("Alice creates a real MLS group for Bob");
        let (alice_group_id, creation_effects) = creation.into_parts();
        let (creation_events, mut publication_work, queued, convergence) =
            creation_effects.into_parts();
        assert!(creation_events.is_empty());
        assert!(queued.is_empty());
        assert!(convergence.is_empty());
        assert_eq!(publication_work.len(), 1);
        let (pending, welcomes) = match publication_work.pop().expect("one publication batch") {
            PublishWork::GroupCreated { pending, welcomes } => (pending, welcomes),
            other => panic!("group creation returned unexpected publication: {other:?}"),
        };
        let mut welcomes = welcomes
            .iter()
            .map(NostrTransportEvent::from_transport_message)
            .collect::<Result<Vec<_>, _>>()
            .expect("MDK Welcome publication converts to Nostr");
        assert_eq!(welcomes.len(), 1);
        let welcome = welcomes.pop().expect("one Welcome");
        assert_eq!(welcome.kind, KIND_NIP59_GIFT_WRAP);
        assert_eq!(
            welcome.tag_value("p"),
            Some(hex::encode(bob_public_key).as_str())
        );

        let confirmed = alice
            .confirm_published(MarmotPendingPublication::from_mdk(pending))
            .await
            .expect("Alice applies the published group creation");
        let (confirmed_events, confirmed_publish, confirmed_queued, confirmed_convergence) =
            confirmed.into_parts();
        assert!(confirmed_events.iter().any(
            |event| matches!(event, GroupEvent::GroupCreated { group_id } if group_id == &alice_group_id.0)
        ));
        assert!(confirmed_publish.is_empty());
        assert!(confirmed_queued.is_empty());
        assert!(confirmed_convergence.is_empty());

        let welcome_result = bob
            .accept_welcome(welcome)
            .await
            .expect("Bob decrypts the NIP-59 Welcome and joins");
        assert_eq!(welcome_result.outcome(), &IngestOutcome::Processed);
        let joined = welcome_result.effects().joined_group_ids();
        assert_eq!(joined.len(), 1);
        let bob_group_id = joined[0].clone();
        assert_eq!(alice_group_id, bob_group_id);
        assert!(welcome_result.effects().publish_work().is_empty());
        assert!(welcome_result.effects().queued_intents().is_empty());
        assert!(welcome_result
            .effects()
            .pending_convergence_groups()
            .is_empty());

        let alice_send = alice
            .send_text(&alice_group_id, 1_700_000_001, "hello from Alice")
            .await
            .expect("Alice encrypts a Marmot application message");
        let (alice_send_events, mut alice_publish, alice_queued, alice_convergence) =
            alice_send.into_parts();
        assert!(alice_send_events.is_empty());
        assert!(alice_queued.is_empty());
        assert!(alice_convergence.is_empty());
        assert_eq!(alice_publish.len(), 1);
        let alice_message = match alice_publish.pop().expect("one Alice publication") {
            PublishWork::ApplicationMessage { msg } => msg,
            other => panic!("Alice send returned unexpected publication: {other:?}"),
        };
        let alice_outer = NostrTransportEvent::from_transport_message(&alice_message)
            .expect("Alice's MDK publication converts to Nostr");
        assert_eq!(alice_outer.kind, KIND_MARMOT_GROUP_MESSAGE);
        assert_eq!(
            alice_outer.tag_value("h"),
            Some(hex::encode(nostr_group_id).as_str())
        );
        assert_ne!(alice_outer.pubkey, alice_public_key);
        assert!(!alice_outer.content.contains("hello from Alice"));
        alice_outer
            .to_verified_nostr_event()
            .expect("upstream emitted a valid ephemeral Nostr signature");

        let alice_ingest = bob
            .ingest_group_event(alice_outer)
            .await
            .expect("Bob unwraps and MLS-decrypts Alice's event");
        assert_eq!(alice_ingest.outcome(), &IngestOutcome::Processed);
        assert!(alice_ingest.effects().publish_work().is_empty());
        assert!(alice_ingest.effects().queued_intents().is_empty());
        assert!(alice_ingest
            .effects()
            .pending_convergence_groups()
            .is_empty());
        let alice_plaintext = alice_ingest
            .effects()
            .decoded_application_messages()
            .expect("Alice's inner event is valid and sender-bound");
        assert_eq!(alice_plaintext.len(), 1);
        assert_eq!(alice_plaintext[0].group_id(), &bob_group_id);
        assert_eq!(alice_plaintext[0].sender(), alice.account_public_key());
        assert_eq!(alice_plaintext[0].author_public_key(), alice_public_key);
        assert_eq!(alice_plaintext[0].kind(), MARMOT_APP_EVENT_KIND_CHAT);
        assert_eq!(alice_plaintext[0].content(), "hello from Alice");

        let bob_send = bob
            .send_text(&bob_group_id, 1_700_000_002, "ack from Bob")
            .await
            .expect("Bob encrypts a reply with the joined MLS state");
        let (bob_send_events, mut bob_publish, bob_queued, bob_convergence) = bob_send.into_parts();
        assert!(bob_send_events.is_empty());
        assert!(bob_queued.is_empty());
        assert!(bob_convergence.is_empty());
        assert_eq!(bob_publish.len(), 1);
        let bob_message = match bob_publish.pop().expect("one Bob publication") {
            PublishWork::ApplicationMessage { msg } => msg,
            other => panic!("Bob send returned unexpected publication: {other:?}"),
        };
        let bob_outer = NostrTransportEvent::from_transport_message(&bob_message)
            .expect("Bob's MDK publication converts to Nostr");
        assert_eq!(bob_outer.kind, KIND_MARMOT_GROUP_MESSAGE);
        assert!(!bob_outer.content.contains("ack from Bob"));

        let bob_ingest = alice
            .ingest_group_event(bob_outer)
            .await
            .expect("Alice decrypts Bob's independent MDK reply");
        assert_eq!(bob_ingest.outcome(), &IngestOutcome::Processed);
        assert!(bob_ingest.effects().publish_work().is_empty());
        assert!(bob_ingest.effects().queued_intents().is_empty());
        assert!(bob_ingest.effects().pending_convergence_groups().is_empty());
        let bob_plaintext = bob_ingest
            .effects()
            .decoded_application_messages()
            .expect("Bob's inner event is valid and sender-bound");
        assert_eq!(bob_plaintext.len(), 1);
        assert_eq!(bob_plaintext[0].group_id(), &alice_group_id);
        assert_eq!(bob_plaintext[0].sender(), bob_public_key);
        assert_eq!(bob_plaintext[0].content(), "ack from Bob");

        let persisted_group_id = alice_group_id.as_bytes().to_vec();
        drop(alice);
        let reopened = MarmotDevice::open(MarmotDeviceConfig::new(
            alice_database_path,
            MarmotDatabaseKey::new([0xA1; 32]),
            account_keys(),
        ))
        .expect("reopen Alice's encrypted MDK session");
        let restored = reopened
            .restore_group_id(&persisted_group_id)
            .expect("confirm persisted group id against hydrated MDK state");
        let snapshot = reopened
            .group_snapshot(&restored)
            .expect("read authenticated group and routing state after restart");
        assert_eq!(snapshot.group_id(), &alice_group_id);
        assert_eq!(snapshot.name(), "round-trip");
        assert_eq!(
            snapshot.description(),
            "same-revision MDK round trip through the Buzz adapter"
        );
        assert_eq!(snapshot.member_ids().len(), 2);
        assert_eq!(snapshot.nostr_group_id(), nostr_group_id);
        assert_eq!(snapshot.relays(), &["wss://relay.example".to_owned()]);
        assert!(matches!(
            reopened.restore_group_id(&[0xFF; 32]),
            Err(MarmotError::GroupIdentifier(_))
        ));
    }
}
