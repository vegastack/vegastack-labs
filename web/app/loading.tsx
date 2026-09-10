import { AppShellSkeleton } from "@/components/ui/app-shell";

export default function Loading() {
  return <AppShellSkeleton navItemCount={5} statCardCount={3} className="h-svh" />;
}
