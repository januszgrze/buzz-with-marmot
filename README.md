<h1 align="center">Buzz + Marmot</h1>

<p align="center">
  A small, local desktop demo of public Nostr messages and Marmot-encrypted group chat.
</p>

<p align="center">
  <img src="docs/assets/screenshots/channel-thread.png" alt="Buzz desktop chat interface" width="760">
</p>

This demo lets two local desktop identities—Alice and Bob—talk through one
local Nostr relay. Normal Buzz channel messages are readable by the relay.
Marmot group messages are encrypted before publication, so the relay stores
only ciphertext.

> **Demo only.** This is a desktop, text-only proof of concept. Read the
> [Security](#security) section before using it.

## Run the local demo

### Prerequisites

Docker Desktop must be installed and running. The local relay uses Docker for
Postgres and Redis.

For a new checkout, bootstrap once:

```bash
. ./bin/activate-hermit
just setup
```

Confirm Docker is available:

```bash
docker info
docker compose version
```

`just relay` starts and health-checks the Docker services automatically. If
needed, they can also be started manually:

```bash
docker compose up -d
docker compose ps
```

### 1. Start the relay

Open a terminal at the repository root:

```bash
. ./bin/activate-hermit
just relay
```

Leave it running. The local relay listens on `ws://localhost:3000`, runs
migrations, and seeds the local development community.

### 2. Start Alice

In a second terminal:

```bash
. ./bin/activate-hermit
just desktop-preview-alice
```

Wait until Alice's desktop window opens and complete the local profile setup
if it is shown.

### 3. Start Bob

In a third terminal:

```bash
. ./bin/activate-hermit
just desktop-preview-bob
```

Alice and Bob have separate desktop identities, keychains, and Marmot state,
but connect to the same local relay. Leave both windows open for a few seconds
so each can publish its profile and Marmot KeyPackage.

## Send a public message

1. In Alice, open **Browse channels** → **Create a new channel**.
2. Name it something like `public-test`; leave **Encrypted** off.
3. Send `public test: relay can read this`.
4. In Bob, browse to and open `#public-test`, then send a reply.

These are normal Buzz stream-message events. The relay stores their message
body in plaintext.

## Create and use an encrypted chat

1. In Alice, open **Browse channels** → **Create a new channel**.
2. Choose a name and optional description, then enable **Encrypted**.
3. Select Bob as the invitee and create the channel. This preview currently
   supports exactly one invitee during creation.
4. Wait for `Publishing…` to finish. The conversation appears under the
   **Encrypted** sidebar section.
5. Wait for Bob to receive the invitation in Bob's **Encrypted** section. Keep
   both clients open briefly while the live relay subscription catches up. This
   preview does not yet promise recovery after either client restarts.
6. Send `encrypted test: relay cannot read this` from Alice.
7. Reply from Bob.

The encrypted preview is text-only. It does not yet support encrypted media
and never falls back to a plaintext Buzz message.

## Inspect the relay database

Run these in another terminal while Docker is still running. They query the
local Postgres container that backs the relay.

### Public events and plaintext messages

```bash
docker exec -it buzz-postgres psql -U buzz -d buzz -P pager=off -c "
  SELECT
    encode(id, 'hex') AS event_id,
    kind,
    created_at,
    content
  FROM events
  WHERE kind IN (9, 40002)
    AND deleted_at IS NULL
  ORDER BY created_at DESC
  LIMIT 20;
"
```

Kinds `9` and `40002` are normal Buzz stream messages. `content` contains the
exact public message text.

To inspect one event again, replace `<PUBLIC_EVENT_ID>`:

```bash
docker exec -it buzz-postgres psql -U buzz -d buzz -P pager=off -c "
  SELECT encode(id, 'hex') AS event_id, kind, created_at, tags, content
  FROM events
  WHERE encode(id, 'hex') = '<PUBLIC_EVENT_ID>';
"
```

### Marmot encrypted events and ciphertext

```bash
docker exec -it buzz-postgres psql -U buzz -d buzz -P pager=off -c "
  SELECT
    encode(id, 'hex') AS event_id,
    kind,
    created_at,
    tags,
    left(content, 240) AS ciphertext_preview
  FROM events
  WHERE kind = 445
    AND deleted_at IS NULL
  ORDER BY created_at DESC
  LIMIT 20;
"
```

Kind `445` is the Marmot group-message transport envelope. `tags` contains
relay-routing metadata, while `content` is opaque ciphertext—not the message
you typed.

To view one complete encrypted envelope, replace `<ENCRYPTED_EVENT_ID>`:

```bash
docker exec -it buzz-postgres psql -U buzz -d buzz -P pager=off -c "
  SELECT encode(id, 'hex') AS event_id, kind, created_at, tags, content
  FROM events
  WHERE encode(id, 'hex') = '<ENCRYPTED_EVENT_ID>';
"
```

The relay database cannot decrypt the content. Alice and Bob decrypt it only
within their local Marmot state.

## Reset or stop

Reset one desktop profile while retaining relay data:

```bash
. ./bin/activate-hermit
just desktop-preview-reset-alice
just desktop-preview-reset-bob
```

Stop Docker services while retaining their data:

```bash
just down
```

`just reset` deletes all development state after confirmation.

## Contributing

This is a small example built quickly with agent assistance—yes, it is vibe
coded. It is not looking for contributions, feature requests, or production
hardening work.

## Security

**Do not use this demo to protect real secrets or sensitive conversations.**
It has not received a security audit and likely contains bugs. It is a
desktop-only, text-only experiment with intentionally limited recovery and
device support. Treat it as a way to observe Marmot transport behavior, not as
a production secure-messaging product.

Encryption hides message bodies, not routing identifiers, timing, or traffic
volume. The desktop also passes the active account secret to its local native
sidecar over a private process pipe, so use disposable demo identities only.

## License

Buzz is licensed under [Apache License 2.0](LICENSE). The Marmot and MDK code
used by this demo is licensed under the MIT License.
