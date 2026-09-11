import * as React from "react";
import { cn } from "@vegastack/design";

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
   * Extra class names for the scroll container that wraps the `<table>`
   * (`data-slot="table-container"`, which owns `overflow-x-auto`). This is the
   * attachment point for sticky headers, fixed-height viewports, and
   * virtualization — the `<table>` itself cannot own a scroll viewport.
   * @default undefined
   */
  containerClassName?: string;
  /**
   * Props (including `ref`) forwarded to the scroll container element. Its
   * `className` merges after `containerClassName`. Use the `ref` to measure or
   * drive the scroll viewport (e.g. a virtualizer's `getScrollElement`).
   * @default undefined
   */
  containerProps?: React.ComponentProps<"div">;
}

/**
 * `Table` — a styled semantic `<table>` wrapped in a horizontally scrollable
 * container so wide tables never overflow their parent. Compose with
 * `TableHeader`, `TableBody`, `TableFooter`, `TableRow`, `TableHead`,
 * `TableCell`, and `TableCaption`.
 *
 * Pure presentational and server-safe — no hooks, no `'use client'`.
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
  containerClassName,
  containerProps,
  ref,
  ...props
}: TableProps) {
  const { className: containerPropsClassName, ...restContainerProps } =
    containerProps ?? {};
  return (
    <div
      {...restContainerProps}
      // Identity AFTER the spread — consumer containerProps must not be able
      // to overwrite the slot every selector and generated surface keys on.
      data-slot="table-container"
      className={cn(
        "relative w-full overflow-x-auto",
        containerClassName,
        containerPropsClassName,
      )}
    >
      <table
        ref={ref}
        data-slot="table"
        data-grid={grid ? "" : undefined}
        data-header-tone={headerTone === "ink" ? "ink" : undefined}
        data-density={density === "compact" ? "compact" : undefined}
        // `group/table` lets head/cell parts react to the root's data flags without
        // React context — the whole family stays server-safe.
        className={cn("group/table w-full caption-bottom text-base", className)}
        {...props}
      />
    </div>
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
      className={cn("[&_tr]:border-b [&_tr]:border-border", className)}
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
        "border-b border-border  hover:bg-accent data-selected:bg-accent",
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
        "h-(--size-md) px-3 text-start align-middle text-label-sm whitespace-nowrap text-muted-foreground [&:has([role=checkbox])]:pe-0",
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
 * padding; collapses inline-end padding when it hosts a checkbox.

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
        "px-3 py-2 align-middle whitespace-nowrap [&:has([role=checkbox])]:pe-0",
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
