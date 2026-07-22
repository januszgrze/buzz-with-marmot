import { ClockFading, Hash, type LucideIcon } from "lucide-react";
import * as React from "react";

import { useChannelTemplatesQuery } from "@/features/channel-templates/hooks";
import {
  applyEncryptedChannelSelection,
  buildCreateChannelSubmission,
  canOfferEncryptedChannels,
  createChannelFormResetPolicy,
  dispatchCreateChannelSubmission,
  type CreateChannelInput,
  type CreateEncryptedChannelInput,
  type EncryptedMemberOption,
} from "@/features/sidebar/lib/createChannelFormPolicy";
import type { ChannelTemplate, ChannelVisibility } from "@/shared/api/types";

export type {
  CreateChannelInput,
  CreateEncryptedChannelInput,
  EncryptedMemberOption,
} from "@/features/sidebar/lib/createChannelFormPolicy";

export type CreateChannelKind = "stream" | "forum";

type UseCreateChannelFormOptions = {
  channelKind: CreateChannelKind;
  /**
   * When this flips to `true` the form resets its fields (and applies
   * `initialName`). Pass the dialog/mode's open state.
   */
  active: boolean;
  initialName?: string;
  isCreating: boolean;
  onCreate: (input: CreateChannelInput) => Promise<void>;
  onCreateEncrypted?: (input: CreateEncryptedChannelInput) => Promise<void>;
  onCreated?: () => void;
  autoFocusName?: boolean;
  /**
   * Surfaces Marmot creation controls. Defaults to false until a caller has
   * an encrypted creation implementation to supply.
   */
  supportsEncryptedChannels?: boolean;
  encryptedMemberOptions?: EncryptedMemberOption[];
};

export type CreateChannelFormState = {
  channelKind: CreateChannelKind;
  kindLabel: string;
  name: string;
  setName: (value: string) => void;
  description: string;
  setDescription: (value: string) => void;
  visibility: ChannelVisibility;
  setVisibility: (value: ChannelVisibility) => void;
  encrypted: boolean;
  setEncrypted: (value: boolean) => void;
  supportsEncryptedChannels: boolean;
  encryptedCreationReady: boolean;
  encryptedMemberOptions: EncryptedMemberOption[];
  inviteePubkey: string;
  setInviteePubkey: (value: string) => void;
  ephemeral: boolean;
  setEphemeral: (value: boolean) => void;
  durationLabel: string;
  DurationIcon: LucideIcon;
  typePopoverOpen: boolean;
  setTypePopoverOpen: (open: boolean) => void;
  errorMessage: string | null;
  selectedTemplateId: string | null;
  handleTemplateChange: (templateId: string) => void;
  templates: ChannelTemplate[];
  nameInputRef: React.RefObject<HTMLInputElement | null>;
  isCreating: boolean;
  canSubmit: boolean;
  handleSubmit: (event: React.FormEvent<HTMLFormElement>) => void;
};

/**
 * Shared state + submit logic for the create-channel form. Powers both the
 * standalone `CreateChannelDialog` and the create mode of the unified
 * "Add channel" browser dialog, so the two stay behaviorally identical.
 */
export function useCreateChannelForm({
  channelKind,
  active,
  initialName,
  isCreating,
  onCreate,
  onCreateEncrypted,
  onCreated,
  autoFocusName = true,
  supportsEncryptedChannels = false,
  encryptedMemberOptions = [],
}: UseCreateChannelFormOptions): CreateChannelFormState {
  const [name, setName] = React.useState(initialName ?? "");
  const [description, setDescription] = React.useState("");
  const [visibility, setVisibility] = React.useState<ChannelVisibility>("open");
  const [encrypted, setEncrypted] = React.useState(false);
  const [inviteePubkey, setInviteePubkey] = React.useState("");
  const [ephemeral, setEphemeral] = React.useState(false);
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null);
  const [selectedTemplateId, setSelectedTemplateId] = React.useState<
    string | null
  >(null);
  const [typePopoverOpen, setTypePopoverOpen] = React.useState(false);
  const nameInputRef = React.useRef<HTMLInputElement>(null);
  const visibilityTouchedRef = React.useRef(false);

  const templatesQuery = useChannelTemplatesQuery();
  const templates = templatesQuery.data ?? [];

  const kindLabel = channelKind === "forum" ? "forum" : "channel";
  const encryptionSupported = canOfferEncryptedChannels(
    channelKind,
    supportsEncryptedChannels,
  );
  const durationLabel = ephemeral ? "Temporary" : "Ongoing";
  const DurationIcon = ephemeral ? ClockFading : Hash;

  React.useEffect(() => {
    if (!active) return;

    setName(initialName ?? "");
    setDescription("");
    const resetPolicy = createChannelFormResetPolicy();
    setVisibility(resetPolicy.visibility);
    setEncrypted(resetPolicy.encrypted);
    setInviteePubkey("");
    setEphemeral(resetPolicy.ephemeral);
    setErrorMessage(null);
    setSelectedTemplateId(resetPolicy.selectedTemplateId);
    setTypePopoverOpen(resetPolicy.typePopoverOpen);
    visibilityTouchedRef.current = false;

    if (!autoFocusName) return;

    // Small delay to let the dialog animation start before focusing.
    const timerId = globalThis.setTimeout(() => {
      const activeElement = document.activeElement;
      if (
        activeElement instanceof HTMLElement &&
        activeElement.closest("#create-channel-form")
      ) {
        return;
      }
      const input = nameInputRef.current;
      if (!input) return;
      input.focus();
      // Place the caret at the end of any prefilled name.
      const end = input.value.length;
      input.setSelectionRange(end, end);
    }, 50);
    return () => globalThis.clearTimeout(timerId);
  }, [active, autoFocusName, initialName]);

  React.useEffect(() => {
    if (encryptionSupported || !encrypted) return;
    setEncrypted(false);
  }, [encrypted, encryptionSupported]);

  const handleTemplateChange = React.useCallback(
    (templateId: string) => {
      if (encrypted) return;

      if (!templateId) {
        setSelectedTemplateId(null);
        setDescription("");
        if (!visibilityTouchedRef.current) setVisibility("open");
        setErrorMessage(null);
        return;
      }

      const template = templates.find(
        (t: ChannelTemplate) => t.id === templateId,
      );
      if (!template) return;

      setSelectedTemplateId(templateId);
      setDescription(template.description ?? "");
      if (!visibilityTouchedRef.current) setVisibility(template.visibility);
      setErrorMessage(null);
    },
    [encrypted, templates],
  );

  const handleSubmit = React.useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();

      const trimmedName = name.trim();
      if (!trimmedName) return;

      setErrorMessage(null);

      void (async () => {
        try {
          const submission = buildCreateChannelSubmission({
            name: trimmedName,
            description,
            encrypted,
            ephemeral,
            inviteePubkey,
            selectedTemplateId,
            visibility,
          });
          await dispatchCreateChannelSubmission(submission, {
            onCreate,
            onCreateEncrypted,
          });
          onCreated?.();
        } catch (error) {
          setErrorMessage(
            error instanceof Error
              ? error.message
              : `Failed to create ${kindLabel}.`,
          );
        }
      })();
    },
    [
      description,
      encrypted,
      ephemeral,
      inviteePubkey,
      kindLabel,
      name,
      onCreate,
      onCreateEncrypted,
      onCreated,
      selectedTemplateId,
      visibility,
    ],
  );

  return {
    channelKind,
    kindLabel,
    name,
    setName: (value: string) => {
      setName(value);
      setErrorMessage(null);
    },
    description,
    setDescription: (value: string) => {
      setDescription(value);
      setErrorMessage(null);
    },
    visibility,
    setVisibility: (value: ChannelVisibility) => {
      visibilityTouchedRef.current = true;
      setVisibility(encrypted ? "private" : value);
      setErrorMessage(null);
    },
    encrypted,
    setEncrypted: (value: boolean) => {
      if (value && !encryptionSupported) return;
      const nextPolicy = applyEncryptedChannelSelection(
        {
          encrypted,
          ephemeral,
          selectedTemplateId,
          typePopoverOpen,
          visibility,
        },
        value,
      );
      if (value) visibilityTouchedRef.current = true;
      setEncrypted(nextPolicy.encrypted);
      if (!value) setInviteePubkey("");
      setEphemeral(nextPolicy.ephemeral);
      setSelectedTemplateId(nextPolicy.selectedTemplateId);
      setTypePopoverOpen(nextPolicy.typePopoverOpen);
      setVisibility(nextPolicy.visibility);
      setErrorMessage(null);
    },
    supportsEncryptedChannels: encryptionSupported,
    encryptedCreationReady: Boolean(onCreateEncrypted),
    encryptedMemberOptions,
    inviteePubkey,
    setInviteePubkey: (value: string) => {
      setInviteePubkey(value);
      setErrorMessage(null);
    },
    ephemeral,
    setEphemeral: (value: boolean) => {
      setEphemeral(encrypted ? false : value);
      setErrorMessage(null);
    },
    durationLabel,
    DurationIcon,
    typePopoverOpen,
    setTypePopoverOpen: (open: boolean) => {
      setTypePopoverOpen(encrypted ? false : open);
    },
    errorMessage,
    selectedTemplateId,
    handleTemplateChange,
    templates,
    nameInputRef,
    isCreating,
    canSubmit:
      name.trim().length > 0 &&
      !isCreating &&
      (!encrypted || (Boolean(onCreateEncrypted) && inviteePubkey.length > 0)),
    handleSubmit,
  };
}
