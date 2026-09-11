"use client";

import { Button } from "@/components/ui/button";

export function ReadPagination({ label, hasPrevious, hasNext, onPrevious, onNext, busy }: { label: string; hasPrevious: boolean; hasNext: boolean; onPrevious: () => void; onNext: () => void; busy: boolean }) {
  return <nav aria-label={`${label} pages`} className="flex flex-wrap justify-end gap-2"><Button className="min-h-11" variant="outline" disabled={!hasPrevious || busy} onClick={onPrevious}>Previous {label.toLowerCase()} page</Button><Button className="min-h-11" variant="outline" disabled={!hasNext || busy} onClick={onNext}>Next {label.toLowerCase()} page</Button></nav>;
}
