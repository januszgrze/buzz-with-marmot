import { DEFAULT_EPHEMERAL_TTL_SECONDS } from "@/features/channels/lib/ephemeralChannel";
import type { ChannelVisibility } from "@/shared/api/types";

export type CreateChannelInput = {
  name: string;
  description?: string;
  visibility: ChannelVisibility;
  ttlSeconds?: number;
  templateId?: string;
};

export type CreateEncryptedChannelInput = {
  name: string;
  description?: string;
  /** Exactly one second member for the bounded desktop preview. */
  inviteePubkey: string;
  /** Encrypted channels are always invite-only. */
  visibility: "private";
  encryption: "marmot";
};

export type EncryptedMemberOption = {
  pubkey: string;
  label: string;
};

export type CreateChannelFormPolicyState = {
  encrypted: boolean;
  ephemeral: boolean;
  selectedTemplateId: string | null;
  typePopoverOpen: boolean;
  visibility: ChannelVisibility;
};

export type CreateChannelSubmission =
  | { mode: "plaintext"; input: CreateChannelInput }
  | { mode: "encrypted"; input: CreateEncryptedChannelInput };

export const ENCRYPTED_CHANNEL_CREATION_UNAVAILABLE =
  "Encrypted channel creation is not available yet.";

export function canOfferEncryptedChannels(
  channelKind: "stream" | "forum",
  supportsEncryptedChannels = false,
): boolean {
  return channelKind === "stream" && supportsEncryptedChannels;
}

export function createChannelFormResetPolicy(): CreateChannelFormPolicyState {
  return {
    encrypted: false,
    ephemeral: false,
    selectedTemplateId: null,
    typePopoverOpen: false,
    visibility: "open",
  };
}

export function applyEncryptedChannelSelection(
  state: CreateChannelFormPolicyState,
  encrypted: boolean,
): CreateChannelFormPolicyState {
  if (!encrypted) {
    return { ...state, encrypted: false };
  }

  return {
    encrypted: true,
    ephemeral: false,
    selectedTemplateId: null,
    typePopoverOpen: false,
    visibility: "private",
  };
}

export function buildCreateChannelSubmission({
  description,
  encrypted,
  ephemeral,
  inviteePubkey,
  name,
  selectedTemplateId,
  visibility,
}: {
  description: string;
  encrypted: boolean;
  ephemeral: boolean;
  inviteePubkey: string;
  name: string;
  selectedTemplateId: string | null;
  visibility: ChannelVisibility;
}): CreateChannelSubmission {
  const trimmedDescription = description.trim() || undefined;

  if (encrypted) {
    if (!inviteePubkey) {
      throw new Error("Select one member for the encrypted channel.");
    }
    return {
      mode: "encrypted",
      input: {
        name: name.trim(),
        description: trimmedDescription,
        inviteePubkey,
        visibility: "private",
        encryption: "marmot",
      },
    };
  }

  return {
    mode: "plaintext",
    input: {
      name: name.trim(),
      description: trimmedDescription,
      visibility,
      ttlSeconds: ephemeral ? DEFAULT_EPHEMERAL_TTL_SECONDS : undefined,
      templateId: selectedTemplateId ?? undefined,
    },
  };
}

export async function dispatchCreateChannelSubmission(
  submission: CreateChannelSubmission,
  callbacks: {
    onCreate: (input: CreateChannelInput) => Promise<void>;
    onCreateEncrypted?: (input: CreateEncryptedChannelInput) => Promise<void>;
  },
): Promise<void> {
  if (submission.mode === "encrypted") {
    if (!callbacks.onCreateEncrypted) {
      throw new Error(ENCRYPTED_CHANNEL_CREATION_UNAVAILABLE);
    }
    await callbacks.onCreateEncrypted(submission.input);
    return;
  }

  await callbacks.onCreate(submission.input);
}
