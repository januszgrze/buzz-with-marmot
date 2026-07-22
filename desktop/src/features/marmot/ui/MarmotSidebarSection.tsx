import { LockKeyhole } from "lucide-react";

import type { MarmotConversation } from "@/features/marmot/api";
import { cn } from "@/shared/lib/cn";
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/shared/ui/sidebar";

export function MarmotSidebarSection({
  conversations,
  onSelectConversation,
  selectedConversationId,
}: {
  conversations: MarmotConversation[];
  onSelectConversation: (conversationId: string) => void;
  selectedConversationId: string | null;
}) {
  if (conversations.length === 0) return null;

  return (
    <SidebarGroup data-testid="encrypted-conversation-section">
      <SidebarGroupLabel className="text-xs text-sidebar-foreground/55">
        Encrypted
      </SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu data-testid="encrypted-conversation-list">
          {conversations.map((conversation) => {
            const selected =
              selectedConversationId === conversation.conversationId;
            return (
              <SidebarMenuItem key={conversation.conversationId}>
                <SidebarMenuButton
                  className={cn(
                    "gap-2 text-sidebar-foreground/75",
                    selected &&
                      "bg-sidebar-accent text-sidebar-accent-foreground",
                  )}
                  data-active={selected}
                  data-testid={`encrypted-conversation-${conversation.name}`}
                  onClick={() =>
                    onSelectConversation(conversation.conversationId)
                  }
                  tooltip={conversation.name}
                >
                  <LockKeyhole className="h-4 w-4 shrink-0" />
                  <span className="truncate text-sm">{conversation.name}</span>
                  {conversation.state !== "ready" ? (
                    <span className="ml-auto text-2xs text-muted-foreground">
                      Publishing…
                    </span>
                  ) : null}
                </SidebarMenuButton>
              </SidebarMenuItem>
            );
          })}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}
