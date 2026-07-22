# Security

**Do not use this demo to protect real secrets or sensitive conversations.**
It has not received a security audit and likely contains bugs. It is a
desktop-only, text-only experiment with intentionally limited recovery and
device support. Treat it as a way to observe Marmot transport behavior, not as
a production secure-messaging product.

Encryption hides message bodies, not routing identifiers, timing, or traffic
volume. The desktop also passes the active account secret to its local native
sidecar over a private process pipe, so use disposable demo identities only.
