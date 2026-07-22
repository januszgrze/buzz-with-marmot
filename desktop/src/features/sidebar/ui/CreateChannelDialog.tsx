import { ChooserDialogContent } from "@/shared/ui/chooser-dialog-content";
import { Dialog } from "@/shared/ui/dialog";

import {
  type CreateChannelInput,
  type CreateEncryptedChannelInput,
  type EncryptedMemberOption,
  useCreateChannelForm,
} from "@/features/sidebar/lib/useCreateChannelForm";
import {
  CREATE_CHANNEL_FORM_ID,
  CreateChannelFormFields,
  CreateChannelFormFooter,
} from "@/features/sidebar/ui/CreateChannelFormFields";

type ChannelKind = "stream" | "forum";

type CreateChannelDialogProps = {
  /** Which kind of channel to create, or null when closed. */
  channelKind: ChannelKind | null;
  isCreating: boolean;
  onOpenChange: (open: boolean) => void;
  onCreate: (input: CreateChannelInput) => Promise<void>;
  onCreateEncrypted?: (input: CreateEncryptedChannelInput) => Promise<void>;
  supportsEncryptedChannels?: boolean;
  encryptedMemberOptions?: EncryptedMemberOption[];
};

export function CreateChannelDialog({
  channelKind,
  isCreating,
  onOpenChange,
  onCreate,
  onCreateEncrypted,
  supportsEncryptedChannels = false,
  encryptedMemberOptions = [],
}: CreateChannelDialogProps) {
  const open = channelKind !== null;

  const form = useCreateChannelForm({
    channelKind: channelKind ?? "stream",
    active: open,
    isCreating,
    onCreate,
    onCreateEncrypted,
    onCreated: () => onOpenChange(false),
    supportsEncryptedChannels,
    encryptedMemberOptions,
  });

  const kindLabel = channelKind === "forum" ? "forum" : "channel";

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen && isCreating) return;
        onOpenChange(nextOpen);
      }}
    >
      <ChooserDialogContent
        className="max-w-lg"
        contentClassName="pt-3"
        data-testid="create-channel-dialog"
        footerClassName="border-t-0 pt-0"
        headerClassName="pb-2"
        title={`Create a new ${kindLabel}`}
        description={
          channelKind === "forum"
            ? "Forums organize threaded discussions around a topic."
            : "Channels are real-time streams for team conversation."
        }
        footer={<CreateChannelFormFooter form={form} />}
      >
        <form
          className="space-y-5"
          id={CREATE_CHANNEL_FORM_ID}
          onSubmit={form.handleSubmit}
        >
          <CreateChannelFormFields form={form} />
        </form>
      </ChooserDialogContent>
    </Dialog>
  );
}
