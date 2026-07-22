import assert from "node:assert/strict";
import test from "node:test";

import {
  ENCRYPTED_CHANNEL_CREATION_UNAVAILABLE,
  applyEncryptedChannelSelection,
  buildCreateChannelSubmission,
  canOfferEncryptedChannels,
  createChannelFormResetPolicy,
  dispatchCreateChannelSubmission,
} from "./createChannelFormPolicy.ts";

test("encrypted controls are capability-gated and stream-only", () => {
  assert.equal(canOfferEncryptedChannels("stream"), false);
  assert.equal(canOfferEncryptedChannels("forum", true), false);
  assert.equal(canOfferEncryptedChannels("stream", true), true);
});

test("reset restores the plaintext ongoing defaults after encryption", () => {
  const encrypted = applyEncryptedChannelSelection(
    {
      encrypted: false,
      ephemeral: true,
      selectedTemplateId: "template-1",
      typePopoverOpen: true,
      visibility: "open",
    },
    true,
  );

  assert.equal(encrypted.encrypted, true);
  assert.deepEqual(createChannelFormResetPolicy(), {
    encrypted: false,
    ephemeral: false,
    selectedTemplateId: null,
    typePopoverOpen: false,
    visibility: "open",
  });
});

test("selecting encryption forces private ongoing semantics and clears templates", () => {
  assert.deepEqual(
    applyEncryptedChannelSelection(
      {
        encrypted: false,
        ephemeral: true,
        selectedTemplateId: "template-1",
        typePopoverOpen: true,
        visibility: "open",
      },
      true,
    ),
    {
      encrypted: true,
      ephemeral: false,
      selectedTemplateId: null,
      typePopoverOpen: false,
      visibility: "private",
    },
  );
});

test("encrypted submission cannot retain stale plaintext-only fields", () => {
  assert.deepEqual(
    buildCreateChannelSubmission({
      description: "  secret planning  ",
      encrypted: true,
      ephemeral: true,
      inviteePubkey: "b".repeat(64),
      name: "  leadership  ",
      selectedTemplateId: "template-1",
      visibility: "open",
    }),
    {
      mode: "encrypted",
      input: {
        name: "leadership",
        description: "secret planning",
        inviteePubkey: "b".repeat(64),
        visibility: "private",
        encryption: "marmot",
      },
    },
  );
});

test("encrypted submission fails closed when no encrypted callback is supplied", async () => {
  let plaintextCalls = 0;
  const submission = buildCreateChannelSubmission({
    description: "",
    encrypted: true,
    ephemeral: false,
    inviteePubkey: "b".repeat(64),
    name: "leadership",
    selectedTemplateId: null,
    visibility: "private",
  });

  await assert.rejects(
    dispatchCreateChannelSubmission(submission, {
      onCreate: async () => {
        plaintextCalls += 1;
      },
    }),
    new Error(ENCRYPTED_CHANNEL_CREATION_UNAVAILABLE),
  );
  assert.equal(plaintextCalls, 0);
});

test("encrypted submission uses only the explicit encrypted callback", async () => {
  let plaintextCalls = 0;
  let encryptedCalls = 0;
  const submission = buildCreateChannelSubmission({
    description: "",
    encrypted: true,
    ephemeral: false,
    inviteePubkey: "b".repeat(64),
    name: "leadership",
    selectedTemplateId: null,
    visibility: "private",
  });

  await dispatchCreateChannelSubmission(submission, {
    onCreate: async () => {
      plaintextCalls += 1;
    },
    onCreateEncrypted: async () => {
      encryptedCalls += 1;
    },
  });

  assert.equal(plaintextCalls, 0);
  assert.equal(encryptedCalls, 1);
});

test("plaintext submission keeps the existing callback and channel options", async () => {
  let received = null;
  const submission = buildCreateChannelSubmission({
    description: "  project room  ",
    encrypted: false,
    ephemeral: true,
    inviteePubkey: "",
    name: "  project  ",
    selectedTemplateId: "template-1",
    visibility: "private",
  });

  await dispatchCreateChannelSubmission(submission, {
    onCreate: async (input) => {
      received = input;
    },
    onCreateEncrypted: async () => {
      assert.fail("plaintext submission must not invoke encrypted creation");
    },
  });

  assert.deepEqual(received, {
    name: "project",
    description: "project room",
    visibility: "private",
    ttlSeconds: 604800,
    templateId: "template-1",
  });
});
