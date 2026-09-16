import * as React from "react";
import { cn, surfaceInteractive } from "@vegastack/design";
import { TableScrollRegion } from "@/components/ui/table-scroll-region";

/** Props for `Table` — a native `<table>` rendered inside an overflow container. */
export interface TableProps extends React.ComponentProps<"table"> {
  /**
   * Draw the full spreadsheet grid — a hairline on every cell's trailing edge in
   * addition to the row rules (Wave 2, the Attio data-table voice). Off by
   * default: simple tables keep row rules only.
   * @default false
   */
  grid?: boolean;
  /**
   * Header voice. `muted` (default) keeps the 12/500 `text-label-sm`
   * muted-foreground headers; `ink` switches to 14/500 foreground headers — the
   * denser "spreadsheet" read for data-heavy screens.
   * @default 'muted'
   */
  headerTone?: "muted" | "ink";
  /**
   * Row density. `default` keeps `py-2` cells; `compact` tightens to `py-1`
   * (~32px rows) for data-heavy screens.
   * @default 'default'
   */
  density?: "default" | "compact";
  /**
   * Accessible name for the scroll viewport that wraps the `<table>`. Defaults
   * to the table's own `aria-label`. When a name is available the viewport is
   * exposed as `role="region"`; pass one whenever the table can scroll, so the
   * region a keyboard user lands on announces what it holds.
   * @default the table's `aria-label`
   */
  scrollLabel?: string;
  /**
   * Props (including `ref`) forwarded to the scroll container element
   * (`data-slot="table-container"`, which owns `overflow-x-auto`). This is the
   * attachment point for sticky headers, fixed-height viewports, and
   * virtualization — the `<table>` itself cannot own a scroll viewport. Use the
   * `ref` to measure or drive the scroll viewport (e.g. a virtualizer's
   * `getScrollElement`).
   * @default undefined
   */
  containerProps?: React.ComponentProps<"div">;
}

/**
 * `Table` — a styled semantic `<table>` wrapped in a `TableScrollRegion` so wide
 * tables never overflow their parent and stay reachable by keyboard. Compose
 * with `TableHeader`, `TableBody`, `TableFooter`, `TableRow`, `TableHead`,
 * `TableCell`, and `TableCaption`.
 *
 * **Body cells wrap by default** (`overflow-wrap: anywhere` over a per-cell
 * minimum width). Scrolling is reserved for tables that are genuinely wide, not
 * forced by one long value; a column that must stay on one line (a figure, an
 * id, a timestamp) opts back in with `whitespace-nowrap`, which `DataList` and
 * `DataGrid` expose as `column.nowrap`.
 *
 * Pure presentational and server-safe — no hooks, no `'use client'`. The scroll
 * viewport is the family's single client leaf (`table-scroll-region.tsx`),
 * because deciding whether it is scrollable is a measurement.
 *
 * @example
 * <Table>
 *   <TableHeader>
 *     <TableRow>
 *       <TableHead>Name</TableHead>
 *       <TableHead>Role</TableHead>
 *     </TableRow>
 *   </TableHeader>
 *   <TableBody>
 *     <TableRow>
 *       <TableCell>Ada</TableCell>
 *       <TableCell>Engineer</TableCell>
 *     </TableRow>
 *   </TableBody>
 * </Table>
 */
function Table({
  className,
  grid = false,
  headerTone = "muted",
  density = "default",
  scrollLabel,
  containerProps,
  ref,
  ...props
}: TableProps) {
  return (
    <TableScrollRegion
      {...containerProps}
      label={scrollLabel ?? props["aria-label"]}
    >
      <table
        ref={ref}
        data-slot="table"
        data-grid={grid ? "" : undefined}
        data-header-tone={headerTone === "ink" ? "ink" : undefined}
        data-density={density === "compact" ? "compact" : undefined}
        // `group/table` lets head/cell parts react to the root's data flags without
        // React context — the whole family stays server-safe.
        className={cn(
          "group/table w-full caption-bottom text-base",
          // The floor a wrapping column may shrink to. `overflow-wrap: anywhere`
          // drops a cell's min-content width to a single character, so without a
          // floor one long value could squeeze every sibling column to nothing.
          // Retune it per table by overriding the property.
          "[--table-cell-min-width:calc(var(--spacing)*20)]",
          className,
        )}
        {...props}
      />
    </TableScrollRegion>
  );
}

/** Props for `TableHeader` — the `<thead>` group. */
export type TableHeaderProps = React.ComponentProps<"thead">;

/**
 * `TableHeader` — the `<thead>` group holding the header row(s).
 * Adds a bottom border to each contained row.

 *
 * @example
 * <TableHeader />
 */
function TableHeader({ className, ref, ...props }: TableHeaderProps) {
  return (
    <thead
      ref={ref}
      data-slot="table-header"
      className={cn(
        "[&_tr]:border-b [&_tr]:border-border",
        // A header row is not a row you can act on, so it does not take the row
        // hover. `TableRow` carries `surfaceInteractive` for every row it renders
        // — including the header row DataList/DataGrid build with it — and these
        // descendant selectors outrank it on specificity, which a class on the
        // row itself could not do (twMerge only resolves conflicts within ONE
        // `cn()` call, and these classes live on different elements).
        "[&_tr]:hover:bg-transparent [&_tr]:active:bg-transparent",
        className,
      )}
      {...props}
    />
  );
}

/** Props for `TableBody` — the `<tbody>` group. */
export type TableBodyProps = React.ComponentProps<"tbody">;

/**
 * `TableBody` — the `<tbody>` group holding the data rows.
 * Drops the border on the final row for a clean bottom edge.

 *
 * @example
 * <TableBody />
 */
function TableBody({ className, ref, ...props }: TableBodyProps) {
  return (
    <tbody
      ref={ref}
      data-slot="table-body"
      className={cn("[&_tr:last-child]:border-0", className)}
      {...props}
    />
  );
}

/** Props for `TableFooter` — the `<tfoot>` group. */
export type TableFooterProps = React.ComponentProps<"tfoot">;

/**
 * `TableFooter` — the `<tfoot>` group for summary rows (totals, counts).
 * Sits on a subtle muted background with a top border.

 *
 * @example
 * <TableFooter />
 */
function TableFooter({ className, ref, ...props }: TableFooterProps) {
  return (
    <tfoot
      ref={ref}
      data-slot="table-footer"
      className={cn(
        "border-t border-border bg-muted/(--alpha-wash) font-medium [&>tr]:last:border-b-0",
        className,
      )}
      {...props}
    />
  );
}

/** Props for `TableRow` — a single `<tr>`. */
export type TableRowProps = React.ComponentProps<"tr">;

/**
 * `TableRow` — a single `<tr>`. Lifts to the neutral `accent` fill on hover and
 * when selected (`data-selected` attribute), with a bottom border separating rows.

 *
 * @example
 * <TableRow />
 */
function TableRow({ className, ref, ...props }: TableRowProps) {
  return (
    <tr
      ref={ref}
      data-slot="table-row"
      className={cn(
        // A SELECTED row rests on the pressed rung, so hovering it steps DOWN to the hover rung and
        // pressing returns it to rest — otherwise `data-selected` simply outranks `hover:` at equal
        // specificity and a selected row reads dead under the cursor (SP-06).
        "border-b border-border data-selected:bg-surface-3",
        "data-selected:hover:bg-surface-2 data-selected:active:bg-surface-3",
        surfaceInteractive,
        className,
      )}
      {...props}
    />
  );
}

/** Props for `TableHead` — a header cell `<th>`. */
export type TableHeadProps = React.ComponentProps<"th">;

/**
 * `TableHead` — a header cell (`<th>`). A compact (32px, `--size-md`), start-aligned
 * `text-label-sm` (12/500) header in `muted-foreground`, rendered title-case as
 * authored (sortable + non-sortable match); collapses inline-end padding for a checkbox.

 *
 * @example
 * <TableHead />
 */
function TableHead({
  className,
  scope = "col",
  ref,
  ...props
}: TableHeadProps) {
  return (
    <th
      ref={ref}
      scope={scope}
      data-slot="table-head"
      className={cn(
        "h-(--size-md) min-w-(--table-cell-min-width) px-3 text-start align-middle text-label-sm text-muted-foreground",
        // A control column (the selection checkbox) is shrink-to-fit: it opts out
        // of the wrapping floor and tightens its trailing padding. `pe-2`, not
        // `pe-0`: a `sm` Checkbox is 14px with a `-inset-1.5` hit area, so 8px is
        // the least that keeps its 24px target inside its own cell. At `pe-0` the
        // overhang landed in the next header and the sort control owned it —
        // `docs/ledger/bugs.md`, 2026-09-09.
        "[&:has([role=checkbox])]:min-w-0 [&:has([role=checkbox])]:pe-2",
        // ink header voice (root data-header-tone=ink): body-size foreground headers.
        "group-data-[header-tone=ink]/table:text-label group-data-[header-tone=ink]/table:text-foreground",
        // spreadsheet grid (root data-grid): trailing hairline per column, none on the last.
        "group-data-[grid]/table:border-e group-data-[grid]/table:border-border group-data-[grid]/table:last:border-e-0",
        className,
      )}
      {...props}
    />
  );
}

/** Props for `TableCell` — a data cell `<td>`. */
export type TableCellProps = React.ComponentProps<"td">;

/**
 * `TableCell` — a data cell (`<td>`). Vertically centered with consistent
 * padding; tightens inline-end padding when it hosts a checkbox.

 *
 * @example
 * <TableCell />
 */
function TableCell({ className, ref, ...props }: TableCellProps) {
  return (
    <td
      ref={ref}
      data-slot="table-cell"
      className={cn(
        // Wrap by default (D18). A long value breaks inside the cell instead of
        // forcing the whole table to scroll; `--table-cell-min-width` keeps the
        // column readable, and `whitespace-nowrap` from the caller opts back out
        // for figures, ids and timestamps.
        "min-w-(--table-cell-min-width) px-3 py-2 align-middle wrap-anywhere",
        // See `TableHead` — `pe-2` keeps the checkbox's hit area inside its cell.
        "[&:has([role=checkbox])]:min-w-0 [&:has([role=checkbox])]:pe-2",
        "group-data-[density=compact]/table:py-1",
        "group-data-[grid]/table:border-e group-data-[grid]/table:border-border group-data-[grid]/table:last:border-e-0",
        className,
      )}
      {...props}
    />
  );
}

/** Props for `TableCaption` — the `<caption>` describing the table. */
export type TableCaptionProps = React.ComponentProps<"caption">;

/**
 * `TableCaption` — the `<caption>` describing the table for sighted and
 * assistive-technology users. Rendered below the table (`caption-bottom`).

 *
 * @example
 * <TableCaption />
 */
function TableCaption({ className, ref, ...props }: TableCaptionProps) {
  return (
    <caption
      ref={ref}
      data-slot="table-caption"
      className={cn("mt-4 text-base text-muted-foreground", className)}
      {...props}
    />
  );
}

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableRow,
  TableHead,
  TableCell,
  TableCaption,
};
