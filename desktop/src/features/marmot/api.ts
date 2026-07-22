import { invokeTauri } from "@/shared/api/tauri";

export const MARMOT_CONVERSATION_CHANGED_EVENT =
  "marmot-conversation-changed" as const;
export const MARMOT_MESSAGE_CHANGED_EVENT = "marmot-message-changed" as const;

export type MarmotBridgeStatus = {
  apiVersion: number;
  enabled: boolean;
  reasonCode: string;
};

export type MarmotConversation = {
  conversationId: string;
  name: string;
  description: string;
  epoch: number;
  memberCount: number;
  state: "pending_publication" | "ready";
};

export type MarmotMessage = {
  messageId: string;
  conversationId: string;
  authorPublicKey: string;
  createdAt: number;
  content: string;
  delivery: "pending_publication" | "received";
};

export type CreateMarmotConversationInput = {
  name: string;
  description?: string;
  inviteePubkey: string;
};

export type SendMarmotMessageInput = {
  conversationId: string;
  content: string;
};

export type MarmotSendResult = {
  conversationId: string;
  queuedBehindTransition: boolean;
};

export type MarmotChangedPayload = {
  conversationId?: string;
};

export function getMarmotBridgeStatus(): Promise<MarmotBridgeStatus> {
  return invokeTauri("get_marmot_bridge_status");
}

export function createMarmotConversation(
  input: CreateMarmotConversationInput,
): Promise<MarmotConversation> {
  return invokeTauri("create_marmot_preview_conversation", { input });
}

export function listMarmotConversations(): Promise<MarmotConversation[]> {
  return invokeTauri("list_marmot_preview_conversations", {
    input: { limit: 32 },
  });
}

export function listMarmotMessages(
  conversationId: string,
): Promise<MarmotMessage[]> {
  return invokeTauri("list_marmot_preview_messages", {
    input: { conversationId, limit: 8 },
  });
}

export function sendMarmotMessage(
  input: SendMarmotMessageInput,
): Promise<MarmotSendResult> {
  return invokeTauri("send_marmot_preview_message", { input });
}
