import { LockKeyhole, Users } from "lucide-react";
import * as React from "react";

import { ChatHeader } from "@/features/chat/ui/ChatHeader";
import { useCommunities } from "@/features/communities/useCommunities";
import {
  useMarmotBridgeStatusQuery,
  useMarmotConversationsQuery,
  useMarmotMessagesQuery,
  useSendMarmotMessageMutation,
} from "@/features/marmot/hooks";
import { formatTime } from "@/features/messages/lib/dateFormatters";
import type { TimelineMessage } from "@/features/messages/types";
import { MessageComposer } from "@/features/messages/ui/MessageComposer";
import { MessageTimeline } from "@/features/messages/ui/MessageTimeline";
import { useComposerHeightPadding } from "@/features/messages/ui/useComposerHeightPadding";
import {
  mergeCurrentProfileIntoLookup,
  resolveUserLabel,
  type UserProfileLookup,
} from "@/features/profile/lib/identity";
import { useProfileQuery, useUsersBatchQuery } from "@/features/profile/hooks";
import { useIdentityQuery } from "@/shared/api/hooks";
import { normalizePubkey } from "@/shared/lib/pubkey";
import { Button } from "@/shared/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/shared/ui/tooltip";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const EMPTY_PROFILES: UserProfileLookup = {};

function EncryptedBadge() {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-border/70 bg-muted/50 px-2 py-0.5 text-2xs font-medium text-muted-foreground">
      <LockKeyhole aria-hidden className="h-3 w-3" />
      Encrypted
    </span>
  );
}

function EncryptedMemberCount({ count }: { count: number }) {
  return (
    <Tooltip disableHoverableContent>
      <TooltipTrigger asChild>
        <div
          aria-label={`${count} encrypted channel members`}
          className="flex h-8 items-center gap-2 rounded-md border border-input bg-background px-2.5 text-sm font-medium tabular-nums"
          role="status"
        >
          <Users aria-hidden className="h-4 w-4" />
          <span>{count}</span>
        </div>
      </TooltipTrigger>
      <TooltipContent>Encrypted channel members</TooltipContent>
    </Tooltip>
  );
}

function MarmotEncryptionBanner() {
  return (
    <div className="relative z-0 mx-5 -mb-3 flex items-center gap-2 rounded-t-2xl border border-b-0 border-border/60 bg-muted/55 px-4 pb-5 pt-2.5 text-sm leading-5 text-muted-foreground backdrop-blur-sm">
      <LockKeyhole aria-hidden className="h-4 w-4 shrink-0" />
      <span>
        Messages are end-to-end encrypted before they reach the relay.
      </span>
    </div>
  );
}

export function MarmotConversationScreen({
  conversationId,
}: {
  conversationId: string;
}) {
  const communities = useCommunities();
  const scope = communities.activeCommunity?.id ?? "no-community";
  const statusQuery = useMarmotBridgeStatusQuery(scope);
  const enabled = statusQuery.data?.enabled === true;
  const conversationsQuery = useMarmotConversationsQuery(scope, enabled);
  const messagesQuery = useMarmotMessagesQuery(conversationId, scope, enabled);
  const identityQuery = useIdentityQuery();
  const profileQuery = useProfileQuery();
  const sendMutation = useSendMarmotMessageMutation(scope, conversationId);
  const timelineScrollRef = React.useRef<HTMLDivElement>(null);
  const composerWrapperRef = React.useRef<HTMLDivElement>(null);
  const conversation = conversationsQuery.data?.find(
    (item) => item.conversationId === conversationId,
  );
  const messages = messagesQuery.data ?? [];
  const authorPubkeys = React.useMemo(
    () => [...new Set(messages.map((message) => message.authorPublicKey))],
    [messages],
  );
  const profilesQuery = useUsersBatchQuery(authorPubkeys, {
    enabled: enabled && authorPubkeys.length > 0,
  });
  const profiles = React.useMemo(
    () =>
      mergeCurrentProfileIntoLookup(
        profilesQuery.data?.profiles ?? EMPTY_PROFILES,
        profileQuery.data,
      ) ?? EMPTY_PROFILES,
    [profileQuery.data, profilesQuery.data?.profiles],
  );
  const currentPubkey = identityQuery.data?.pubkey;
  const timelineMessages = React.useMemo<TimelineMessage[]>(
    () =>
      messages.map((message) => {
        const pubkey = normalizePubkey(message.authorPublicKey);
        const profile = profiles[pubkey];
        return {
          id: message.messageId,
          createdAt: message.createdAt,
          pubkey,
          author: resolveUserLabel({
            pubkey,
            currentPubkey,
            preferResolvedSelfLabel: true,
            profiles,
          }),
          avatarUrl: profile?.avatarUrl ?? null,
          time: formatTime(message.createdAt),
          body: message.content,
          depth: 0,
          encrypted: true,
          isAgent: profile?.isAgent === true,
        };
      }),
    [currentPubkey, messages, profiles],
  );

  useComposerHeightPadding(
    timelineScrollRef,
    composerWrapperRef,
    conversationId,
    "css-variable",
  );

  const sendMessage = sendMutation.mutateAsync;
  const handleSend = React.useCallback(
    async (content: string) => {
      await sendMessage(content);
    },
    [sendMessage],
  );

  if (
    statusQuery.isPending ||
    (enabled &&
      (conversationsQuery.isPending ||
        (conversationsQuery.isFetching && !conversation)))
  ) {
    return <ViewLoadingFallback includeHeader kind="channel" />;
  }

  if (!enabled) {
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="max-w-md text-center">
          <LockKeyhole className="mx-auto h-8 w-8 text-muted-foreground" />
          <h1 className="mt-4 text-lg font-semibold">
            Encrypted messaging unavailable
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Start a desktop profile with Marmot messaging enabled.
          </p>
        </div>
      </div>
    );
  }

  if (!conversation) {
    if (conversationsQuery.error) {
      return (
        <div className="flex h-full items-center justify-center p-8">
          <div className="max-w-md text-center">
            <LockKeyhole className="mx-auto h-8 w-8 text-muted-foreground" />
            <h1 className="mt-4 text-lg font-semibold">
              Could not load encrypted conversation
            </h1>
            <p className="mt-2 text-sm text-destructive">
              {conversationsQuery.error instanceof Error
                ? conversationsQuery.error.message
                : "The encrypted conversation list could not be loaded."}
            </p>
            <Button
              className="mt-4"
              onClick={() => void conversationsQuery.refetch()}
              type="button"
              variant="outline"
            >
              Try again
            </Button>
          </div>
        </div>
      );
    }
    return (
      <div className="flex h-full items-center justify-center p-8 text-sm text-muted-foreground">
        This encrypted conversation is not available in the current profile.
      </div>
    );
  }

  const error = messagesQuery.error ?? sendMutation.error;
  const description = conversation.description.trim();

  return (
    <TooltipProvider delayDuration={200}>
      <section
        aria-label="Encrypted channel messages and composer"
        className="relative flex h-full min-h-0 min-w-0 flex-1 flex-col overflow-hidden bg-background"
      >
        <ChatHeader
          actions={<EncryptedMemberCount count={conversation.memberCount} />}
          belowSystemChrome
          description={
            description || "End-to-end encrypted · relay sees ciphertext only"
          }
          statusBadge={<EncryptedBadge />}
          title={conversation.name}
          visibility="private"
        />

        <MessageTimeline
          channelId={conversationId}
          channelIntro={{
            channelKindLabel: "encrypted channel",
            channelName: conversation.name,
            hideIntroText: !description,
            icon: <LockKeyhole aria-hidden className="h-7 w-7" />,
            introText: description,
          }}
          channelIntroClassName="pb-4 pt-8"
          channelName={conversation.name}
          channelType="stream"
          currentPubkey={currentPubkey}
          emptyDescription="Send the first encrypted message to start the conversation."
          emptyTitle="No encrypted messages yet"
          hasComposerOverlay
          hasOlderMessages={false}
          historyExhausted
          isLoading={messagesQuery.isPending}
          messages={timelineMessages}
          profiles={profiles}
          scrollContainerRef={timelineScrollRef}
        />

        <div
          className="pointer-events-none absolute inset-x-0 bottom-0 z-40 isolate before:absolute before:inset-x-0 before:bottom-0 before:-z-10 before:h-24 before:bg-gradient-to-b before:from-transparent before:to-background before:content-[''] after:absolute after:inset-x-0 after:bottom-0 after:-z-10 after:h-12 after:bg-background after:content-['']"
          data-testid="marmot-composer-overlay"
          ref={composerWrapperRef}
        >
          <div className="composer-overlay-corner-masks pointer-events-auto">
            {error ? (
              <p className="mx-5 mb-2 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error instanceof Error
                  ? error.message
                  : "Encrypted message failed."}
              </p>
            ) : null}
            <MarmotEncryptionBanner />
            <MessageComposer
              attachmentsEnabled={false}
              channelId={null}
              channelName={conversation.name}
              channelType="stream"
              containerClassName="px-5"
              disabled={
                conversation.state !== "ready" || sendMutation.isPending
              }
              draftKey={conversationId}
              isSending={sendMutation.isPending}
              onSend={handleSend}
              placeholder={
                conversation.state === "ready"
                  ? `Message #${conversation.name}`
                  : "Publishing encrypted conversation…"
              }
              profiles={profiles}
              showTopBorder={false}
            />
            <div className="min-h-8 bg-background px-5 pb-1.5" />
          </div>
        </div>
      </section>
    </TooltipProvider>
  );
}
