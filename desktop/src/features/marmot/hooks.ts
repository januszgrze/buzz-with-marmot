import { listen } from "@tauri-apps/api/event";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";

import {
  type CreateMarmotConversationInput,
  type MarmotChangedPayload,
  type MarmotConversation,
  MARMOT_CONVERSATION_CHANGED_EVENT,
  MARMOT_MESSAGE_CHANGED_EVENT,
  createMarmotConversation,
  getMarmotBridgeStatus,
  listMarmotConversations,
  listMarmotMessages,
  sendMarmotMessage,
} from "@/features/marmot/api";

export const marmotStatusQueryKey = (scope: string) =>
  ["marmot", scope, "status"] as const;
export const marmotConversationsQueryKey = (scope: string) =>
  ["marmot", scope, "conversations"] as const;
export const marmotMessagesQueryKey = (scope: string, conversationId: string) =>
  ["marmot", scope, "messages", conversationId] as const;

export function useMarmotBridgeStatusQuery(scope: string) {
  return useQuery({
    queryKey: marmotStatusQueryKey(scope),
    queryFn: getMarmotBridgeStatus,
    refetchInterval: (query) =>
      query.state.data?.reasonCode === "native_preview_unavailable"
        ? 5_000
        : false,
    staleTime: Number.POSITIVE_INFINITY,
  });
}

export function useMarmotConversationsQuery(scope: string, enabled: boolean) {
  return useQuery({
    enabled,
    queryKey: marmotConversationsQueryKey(scope),
    queryFn: listMarmotConversations,
  });
}

export function useMarmotMessagesQuery(
  conversationId: string,
  scope: string,
  enabled = true,
) {
  return useQuery({
    enabled,
    queryKey: marmotMessagesQueryKey(scope, conversationId),
    queryFn: () => listMarmotMessages(conversationId),
  });
}

export function useCreateMarmotConversationMutation(scope: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateMarmotConversationInput) =>
      createMarmotConversation(input),
    onSuccess: async (conversation) => {
      queryClient.setQueryData<MarmotConversation[]>(
        marmotConversationsQueryKey(scope),
        (current = []) => [
          conversation,
          ...current.filter(
            (item) => item.conversationId !== conversation.conversationId,
          ),
        ],
      );
      await queryClient.invalidateQueries({
        queryKey: marmotConversationsQueryKey(scope),
      });
    },
  });
}

export function useSendMarmotMessageMutation(
  scope: string,
  conversationId: string,
) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (content: string) =>
      sendMarmotMessage({ conversationId, content }),
    onSettled: async () => {
      await queryClient.invalidateQueries({
        queryKey: marmotMessagesQueryKey(scope, conversationId),
      });
    },
  });
}

/** Keeps sanitized native projection events aligned with React Query. */
export function useMarmotProjectionEvents(scope: string, enabled: boolean) {
  const queryClient = useQueryClient();

  React.useEffect(() => {
    if (!enabled) return;

    let disposed = false;
    const unlistenCallbacks: Array<() => void> = [];

    const register = async () => {
      const unlistenConversation = await listen<MarmotChangedPayload>(
        MARMOT_CONVERSATION_CHANGED_EVENT,
        () => {
          void queryClient.invalidateQueries({
            queryKey: marmotConversationsQueryKey(scope),
          });
        },
      );
      if (disposed) {
        unlistenConversation();
        return;
      }
      unlistenCallbacks.push(unlistenConversation);

      const unlistenMessage = await listen<MarmotChangedPayload>(
        MARMOT_MESSAGE_CHANGED_EVENT,
        ({ payload }) => {
          if (payload.conversationId) {
            void queryClient.invalidateQueries({
              queryKey: marmotMessagesQueryKey(scope, payload.conversationId),
            });
          }
          void queryClient.invalidateQueries({
            queryKey: marmotConversationsQueryKey(scope),
          });
        },
      );
      if (disposed) {
        unlistenMessage();
        return;
      }
      unlistenCallbacks.push(unlistenMessage);

      // Native catch-up can join a conversation immediately after the bridge
      // becomes ready, before React finishes installing these async listeners.
      // Re-read once after registration so an event in that gap cannot leave
      // the sidebar stuck on its pre-catch-up empty cache.
      await queryClient.invalidateQueries({
        queryKey: marmotConversationsQueryKey(scope),
      });
    };

    void register();
    return () => {
      disposed = true;
      for (const unlisten of unlistenCallbacks) unlisten();
    };
  }, [enabled, queryClient, scope]);
}
