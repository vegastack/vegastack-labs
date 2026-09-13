"use client";

import { AlertDialog } from "@base-ui/react/alert-dialog";
import type { ReactElement } from "react";
import { Button } from "@/components/ui/button";

export function RunRecoveryDialog({ trigger, title, description, confirmLabel, destructive = false, pending = false, onConfirm }: { trigger: ReactElement; title: string; description: string; confirmLabel: string; destructive?: boolean; pending?: boolean; onConfirm: () => Promise<void> | void }) {
  return <AlertDialog.Root>
    <AlertDialog.Trigger render={trigger} />
    <AlertDialog.Portal>
      <AlertDialog.Backdrop className="fixed inset-0 z-(--z-overlay) bg-overlay transition-opacity data-[starting-style]:opacity-0 data-[ending-style]:opacity-0" />
      <AlertDialog.Viewport className="fixed inset-0 z-(--z-overlay) grid place-items-center overflow-y-auto p-4">
        <AlertDialog.Popup className="w-full max-w-md rounded-lg border border-border bg-card p-5 text-card-foreground outline-none shadow-lg">
          <AlertDialog.Title className="text-lg font-semibold">{title}</AlertDialog.Title>
          <AlertDialog.Description className="mt-2 text-sm leading-relaxed text-muted-foreground">{description}</AlertDialog.Description>
          <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <AlertDialog.Close render={<Button variant="outline">Keep inspecting</Button>} />
            <AlertDialog.Close render={<Button loading={pending} variant={destructive ? "destructive" : "default"} onClick={() => void onConfirm()}>{confirmLabel}</Button>} />
          </div>
        </AlertDialog.Popup>
      </AlertDialog.Viewport>
    </AlertDialog.Portal>
  </AlertDialog.Root>;
}
