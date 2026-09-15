"use client";

import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";

export function ReadPagination({
  label,
  hasPrevious,
  hasNext,
  onPrevious,
  onNext,
  busy,
}: {
  label: string;
  hasPrevious: boolean;
  hasNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
  busy: boolean;
}) {
  if (!hasPrevious && !hasNext) return null;
  return (
    <nav aria-label={`${label} pages`} className="flex flex-wrap items-center justify-end gap-2">
      <Button variant="outline" size="sm" disabled={!hasPrevious || busy} onClick={onPrevious}>
        <ChevronLeft aria-hidden />
        Previous
      </Button>
      <Button variant="outline" size="sm" disabled={!hasNext || busy} onClick={onNext}>
        Next
        <ChevronRight aria-hidden />
      </Button>
    </nav>
  );
}
