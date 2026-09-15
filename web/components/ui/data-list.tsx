"use client";

import * as React from "react";
import { cn } from "@vegastack/design";
import {
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableRow,
  type TableProps,
} from "@/components/ui/table";
import {
  columnCellClass,
  cycleSort,
  EmptyRow,
  SelectAllHead,
  SelectionCell,
  SkeletonRows,
  SortableHead,
  useControlledState,
  useRowSelection,
  type DataTableColumnLayout,
  type SortDirection,
} from "@/components/ui/data-table-parts";

export type { SortDirection };

/** The active sort — which column and which direction. */
export interface SortState {
  /** `key` of the column being sorted. */
  key: string;
  /** Direction of the sort. */
  direction: SortDirection;
}

/**
 * Per-cell context passed as the optional third argument to a column `render`.
 * Existing two-argument render functions remain assignable unchanged.
 */
export interface DataListCellContext {
  /** Stable row id, as produced by `getRowId`. */
  rowId: string;
  /** The `key` of the column this cell belongs to. */
  columnKey: string;
  /** Whether the cell's row is currently selected. */
  selected: boolean;
}

/**
 * A single column definition for {@link DataList}. Generic over the row type `T`
 * so `render` receives a fully-typed row.
 */
export interface DataListColumn<T> extends DataTableColumnLayout {
  /** Header label. A string or any node for custom header layouts. */
  header: React.ReactNode;
  /**
   * Cell renderer. When omitted, the value at `row[key]` is rendered directly
   * (the column `key` is read as a property of the row). Provide `render` for
   * formatted, composed, or computed cells. Receives an optional third
   * {@link DataListCellContext} argument (row id, column key, selection state).
   *
   * Invoked as a **plain function inside `DataList`'s own render**, not mounted
   * as a component — hooks called directly in its body would become `DataList`'s
   * hooks and corrupt hook order when the loading/empty branch flips. Return a
   * component element (`<MyCell row={row} />`) when a cell needs hooks.
   */
  render?: (
    row: T,
    index: number,
    cell: DataListCellContext,
  ) => React.ReactNode;
  /**
   * Allow the user to sort by this column by clicking its header. Sorting is
   * controlled — the parent receives the next {@link SortState} via
   * `onSortChange` and re-orders `data` itself.
   * @default false
   */
  sortable?: boolean;
  /** Extra className applied to every body cell in this column. */
  className?: string;
  /**
   * Per-cell class hook, called for every body cell in this column and merged
   * after `className`. Use for value-dependent cell styling (a negative-amount
   * tint, a stale-row wash) without a custom `render`.
   * @default undefined
   */
  cellClassName?: (row: T, index: number) => string | undefined;
  /** Extra className applied to the header cell. */
  headerClassName?: string;
  /**
   * Marks this column's cells as containing their own interactive content
   * (a link, button, menu, …). When the **first** column is `interactive` and
   * `onRowClick` is set, `DataList` skips auto-injecting its first-cell row
   * activation button into that cell — so it never nests an interactive element
   * inside the row-activation control. Set this on the first column whenever its
   * `render` returns something focusable/clickable.
   * @default false
   */
  interactive?: boolean;
}

/**
 * Props accepted by `DataList`. Extends {@link TableProps} (minus `children`),
 * so the Table spreadsheet voice — `grid`, `headerTone`, `density` — and the
 * container hooks (`scrollLabel`, `containerProps`) type-check here and
 * flow straight through to the underlying `Table`.
 */
export interface DataListProps<T> extends Omit<TableProps, "children"> {
  /** Column definitions, left to right. */
  columns: DataListColumn<T>[];
  /** Row data, in display order. Sorting is the parent's responsibility (see `sort`). */
  data: T[];
  /**
   * Extract a stable, unique id from a row. Used as the React key and as the
   * selection identity. Defaults to the row index — pass a real id whenever rows
   * can re-order or the dataset can change.
   * @default (_, index) => String(index)
   */
  getRowId?: (row: T, index: number) => string;
  /**
   * Render a leading checkbox column with per-row selection and a header
   * select-all checkbox (tri-state when partially selected).
   * @default false
   */
  selectable?: boolean;
  /**
   * Controlled set of selected row ids. Pair with `onSelectionChange`. Omit for
   * uncontrolled selection (the component tracks its own state).

   * @default undefined
   */
  selectedIds?: Set<string>;
  /**
   * Called whenever the selection changes, with the next set of selected row ids.

   * @default undefined
   */
  onSelectionChange?: (selectedIds: Set<string>) => void;
  /**
   * Controlled active sort. Pair with `onSortChange`. Omit for uncontrolled
   * sorting (the component tracks which header is active, but you must still
   * order `data` yourself in `onSortChange`).

   * @default undefined
   */
  sort?: SortState | null;
  /**
   * Called when a sortable header is activated, with the next {@link SortState}
   * (or `null` when sorting is cleared). Cycles asc → desc → none per column.

   * @default undefined
   */
  onSortChange?: (sort: SortState | null) => void;
  /**
   * Show skeleton placeholder rows instead of data — the loading state.
   * @default false
   */
  loading?: boolean;
  /**
   * Number of skeleton rows to render while `loading`.
   * @default 5
   */
  loadingRows?: number;
  /**
   * Content shown when `data` is empty and not `loading`. Defaults to a built-in
   * {@link Empty}. Pass a node to fully customise it.

   * @default undefined
   */
  emptyState?: React.ReactNode;
  /**
   * Make rows activatable. When set, the row gets `data-clickable` and a
   * `cursor-pointer`, and a real, keyboard-focusable `<button>` is injected into
   * the **first** body cell as the accessible activation control — so the `<tr>`
   * keeps its native `role="row"` and the cells stay valid (no `role="button"`
   * on the row, which would break table semantics for assistive tech). Mouse
   * users get a row-wide `onClick`; keyboard / AT users tab to the first-cell
   * button and press Enter/Space. Activating a nested control (the selection
   * checkbox, a link, a button, …) is excluded — it keeps its own behaviour
   * without firing this. If the first column is `interactive` (its `render`
   * already returns a focusable control), set `column.interactive` on it so the
   * injected button is skipped for that cell — keyboard activation then comes
   * from a consumer-provided in-cell control. Purely *presentational*: the host
   * decides what activating a row does (navigate, open a drawer, …); `DataList`
   * still owns no data behaviour.

   * @default undefined
   */
  onRowClick?: (row: T, index: number) => void;
  /**
   * Slot rendered above the table — where the host drops its own search input,
   * filter bar, or bulk actions. Renders nothing when omitted (per the G7 split,
   * the search/filter *logic* lives in the host; this is just the mount point).

   * @default undefined
   */
  toolbar?: React.ReactNode;
  /**
   * Slot rendered below the table — where the host drops its own pagination,
   * load-more, or row-count footer. Renders nothing when omitted (the paging
   * *logic* lives in the host; this is just the mount point).

   * @default undefined
   */
  footer?: React.ReactNode;
}

/**
 * Interactive descendants that own their own click/keyboard activation. A click
 * or key press landing on one of these inside a clickable row must NOT also
 * activate the row (e.g. toggling the selection checkbox should not navigate).
 */
const INTERACTIVE_SELECTOR =
  'button, a, input, select, textarea, label, [role="button"], [role="checkbox"], [role="menuitem"], [role="link"]';

/**
 * True when a click event originated from an interactive descendant of the row
 * (a checkbox, nested button/link, form control, …) rather than the row itself.
 * Used to gate row activation so those controls keep their own behaviour without
 * also firing `onRowClick`. Robust at the root — works for any interactive
 * descendant, not just the selection checkbox.
 */
function isFromInteractiveDescendant(
  event: React.MouseEvent<HTMLElement>,
): boolean {
  const target = event.target as HTMLElement | null;
  if (!target) return false;
  if (target === event.currentTarget) return false;
  return target.closest(INTERACTIVE_SELECTOR) != null;
}

/**
 * `DataList<T>` — a generic, typed data table with row selection, sortable
 * columns, a skeleton loading state, and an empty state. Built on
 * {@link Table} plus the shared `data-table-parts` chrome it has in common with
 * `DataGrid`; every visual value is a semantic token.
 *
 * Selection and sort are both controllable — pass `selectedIds`/`onSelectionChange`
 * and `sort`/`onSortChange` to lift the state, or omit them for the built-in
 * uncontrolled behaviour. Sorting only *signals* intent via `onSortChange`; the
 * parent re-orders `data` (so server-side and client-side sorting share one API).
 *
 * For host composition it exposes presentational affordances — `onRowClick` (makes
 * rows activatable via click + Enter/Space), and the `toolbar` / `footer` slots
 * (mount points above/below the table for the host's own search bar / pagination).
 * These carry no data logic; the host still owns the query, filtering, and paging.
 *
 * **Scope (presentational core — G7 app-coupled split).** This is the *presentational*
 * data table: columns, render functions, row selection, sortable-header signalling,
 * skeleton loading, the empty state, activatable rows (`onRowClick`), and the
 * `toolbar`/`footer` composition slots. It deliberately does **not** own data-fetching
 * or app-coupled data-management behaviour. The platform's richer data surface is
 * either **composed by the host app** around this primitive (search/filtering,
 * pagination, view persistence — it owns the query, the URL/persisted view state, and
 * the filtered/paged `data` it passes in) or **shipped as sibling components**:
 * `SortableList` (reordering), `Board` (Kanban), and `DataGrid` (grouping, inline
 * editing, multi-key sort, virtualization). Drop the host's own search/filter controls into `toolbar`
 * and its pagination into `footer`; pass `DataList` the already-filtered, already-paged rows.
 *
 * @example
 * // Minimal, read-only
 * <DataList
 *   columns={[
 *     { key: 'name', header: 'Name' },
 *     { key: 'role', header: 'Role' },
 *   ]}
 *   data={users}
 *   getRowId={(u) => u.id}
 * />
 *
 * @example
 * // Selectable + sortable, controlled
 * const [selected, setSelected] = React.useState<Set<string>>(new Set());
 * const [sort, setSort] = React.useState<SortState | null>(null);
 * <DataList
 *   columns={[
 *     { key: 'name', header: 'Name', sortable: true },
 *     { key: 'email', header: 'Email' },
 *     { key: 'amount', header: 'Amount', align: 'end', sortable: true,
 *       render: (r) => <span className="font-mono">{r.amount}</span> },
 *   ]}
 *   data={sortRows(rows, sort)}
 *   getRowId={(r) => r.id}
 *   selectable
 *   selectedIds={selected}
 *   onSelectionChange={setSelected}
 *   sort={sort}
 *   onSortChange={setSort}
 * />
 *
 * @example
 * // Activatable rows + host-owned toolbar/footer slots
 * <DataList
 *   columns={columns}
 *   data={pageRows}
 *   getRowId={(r) => r.id}
 *   onRowClick={(row) => router.push(`/users/${row.id}`)}
 *   toolbar={<SearchInput value={q} onValueChange={setQ} />}
 *   footer={<Pagination page={page} onPageChange={setPage} />}
 * />
 */
export function DataList<T>({
  columns,
  data,
  getRowId = (_row, index) => String(index),
  selectable = false,
  selectedIds,
  onSelectionChange,
  sort,
  onSortChange,
  loading = false,
  loadingRows = 5,
  emptyState,
  onRowClick,
  toolbar,
  footer,
  className,
  "aria-busy": ariaBusy,
  "aria-describedby": ariaDescribedBy,
  ...tableProps
}: DataListProps<T>) {
  const loadingStatusId = React.useId();
  // Sort state — controlled when `sort` is provided (even as null), else internal.
  const [activeSort, commitSort] = useControlledState<SortState | null>(
    sort,
    null,
    onSortChange,
  );
  const handleSort = React.useCallback(
    (key: string) => {
      // One key at a time: DataList only SIGNALS intent, and a presentational
      // table that asked its host to honour a priority list would be pretending
      // to own ordering it does not own.
      commitSort(cycleSort(activeSort ? [activeSort] : [], key)[0] ?? null);
    },
    [activeSort, commitSort],
  );

  const rowIds = React.useMemo(
    () => data.map((row, i) => getRowId(row, i)),
    [data, getRowId],
  );

  const { selected, allSelected, indeterminate, toggleAll, toggleRow } =
    useRowSelection({ rowIds, selectedIds, onSelectionChange });

  // Mouse-pointer convenience: clicking anywhere in the row activates it. A
  // `<tr>` may carry an `onClick` without an ARIA role (it keeps `role="row"`),
  // so this does NOT break table semantics. Keyboard / AT activation comes from
  // the real `<button>` injected into the first cell (below), not from the row.
  // Guarded so a click that originated from an interactive descendant (the
  // selection checkbox, a nested button/link, a form control, AND the injected
  // first-cell button itself) does NOT *also* fire — that control owns its
  // behaviour, preventing double-activation. The checkbox cell's
  // stopPropagation below is kept as defence in depth.
  const handleRowClick = React.useCallback(
    (event: React.MouseEvent<HTMLTableRowElement>, row: T, index: number) => {
      if (isFromInteractiveDescendant(event)) return;
      onRowClick?.(row, index);
    },
    [onRowClick],
  );

  const colSpan = columns.length + (selectable ? 1 : 0);
  const tableDescribedBy = loading
    ? [ariaDescribedBy, loadingStatusId].filter(Boolean).join(" ")
    : ariaDescribedBy;

  const loadingStatus = loading ? (
    <div
      id={loadingStatusId}
      role="status"
      aria-live="polite"
      className="sr-only"
    >
      Loading rows
    </div>
  ) : null;

  const table = (
    <>
      {loadingStatus}
      <Table
        data-slot="data-list"
        className={className}
        aria-busy={loading ? true : ariaBusy}
        aria-describedby={tableDescribedBy || undefined}
        {...tableProps}
      >
        <TableHeader>
          <TableRow>
            {selectable && (
              <SelectAllHead
                checked={allSelected}
                indeterminate={indeterminate}
                onToggle={toggleAll}
                disabled={loading || rowIds.length === 0}
              />
            )}
            {columns.map((col) => (
              <SortableHead
                key={col.key}
                data-slot="data-list-head"
                column={col}
                direction={
                  activeSort?.key === col.key ? activeSort.direction : null
                }
                onSort={() => handleSort(col.key)}
              />
            ))}
          </TableRow>
        </TableHeader>

        <TableBody>
          {loading ? (
            <SkeletonRows
              columns={columns}
              rows={loadingRows}
              selectable={selectable}
              slot="data-list-skeleton-row"
            />
          ) : data.length === 0 ? (
            <EmptyRow colSpan={colSpan} slot="data-list-empty-row">
              {emptyState}
            </EmptyRow>
          ) : (
            data.map((row, index) => {
              const id = rowIds[index]!;
              const isSelected = selected.has(id);
              const clickable = !!onRowClick;
              // Inject the accessible row-activation button into the first cell —
              // but never when that first column is `interactive` (it already
              // renders its own focusable control, so wrapping would nest one
              // interactive element inside another).
              const injectRowButton =
                clickable && columns[0]?.interactive !== true;
              return (
                <TableRow
                  key={id}
                  data-slot="data-list-row"
                  data-selected={isSelected ? "" : undefined}
                  data-clickable={clickable ? "" : undefined}
                  onClick={
                    clickable ? (e) => handleRowClick(e, row, index) : undefined
                  }
                  className={cn(
                    clickable && "cursor-pointer",
                    // A checked row keeps a persistent neutral `accent` tint (the checkbox is
                    // the authoritative selection cue). Overrides the base Table row's
                    // hover-only `accent` so the tint stays through hover as well.
                    isSelected &&
                      // A selected row still has to move under the cursor (SP-06): it rests on the pressed
                      // rung, hovers DOWN one rung, and returns to rest while pressed.
                      "bg-surface-3 hover:bg-surface-2 active:bg-surface-3 data-selected:bg-surface-3 data-selected:hover:bg-surface-2",
                  )}
                >
                  {selectable && (
                    <SelectionCell
                      checked={isSelected}
                      onToggle={() => toggleRow(id)}
                      label={`Select row ${index + 1}`}
                    />
                  )}
                  {columns.map((col, colIdx) => {
                    const content = col.render
                      ? col.render(row, index, {
                          rowId: id,
                          columnKey: col.key,
                          selected: isSelected,
                        })
                      : ((row as Record<string, React.ReactNode>)[col.key] ??
                        null);
                    // First cell + activatable + not an interactive column → wrap
                    // the content in a real <button>. It lives INSIDE the <td>, so
                    // the cell keeps its `role="cell"` and the row its `role="row"`;
                    // this is the focusable, Enter/Space-activatable control for
                    // keyboard / AT users. The `data-list-row-action` button is
                    // matched by INTERACTIVE_SELECTOR, so the row's mouse onClick
                    // guard skips it — no double-activation.
                    const isActionCell = injectRowButton && colIdx === 0;
                    return (
                      <TableCell
                        key={col.key}
                        className={cn(
                          columnCellClass(col),
                          col.className,
                          col.cellClassName?.(row, index),
                        )}
                      >
                        {isActionCell ? (
                          <button
                            type="button"
                            data-slot="data-list-row-action"
                            onClick={() => onRowClick?.(row, index)}
                            className="-mx-1 -my-0.5 inline-flex max-w-full appearance-none items-center rounded-sm bg-transparent px-1 py-0.5 text-start text-inherit"
                          >
                            {content}
                          </button>
                        ) : (
                          content
                        )}
                      </TableCell>
                    );
                  })}
                </TableRow>
              );
            })
          )}
        </TableBody>
      </Table>
    </>
  );

  // Render the bare table when there are no composition slots, so existing
  // consumers (and `ref` to the `<table>`) are untouched. With a toolbar or
  // footer, wrap the three regions in a vertical stack.
  if (toolbar == null && footer == null) return table;

  return (
    <div data-slot="data-list-root" className="flex flex-col gap-3">
      {toolbar != null ? (
        <div data-slot="data-list-toolbar">{toolbar}</div>
      ) : null}
      {table}
      {footer != null ? <div data-slot="data-list-footer">{footer}</div> : null}
    </div>
  );
}

DataList.displayName = "DataList";
