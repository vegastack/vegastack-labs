import * as React from "react";
import { cn } from "@vegastack/design";

/* ------------------------------------------------------------------------------------------------
 * PropertyList — record-facts rows (Wave 2c, from the app-teardown facts-pane anatomy): an
 * icon + muted 12/500 label column beside a 14/500 value column, one row per attribute. Built as
 * a definition list (`<dl>/<dt>/<dd>`) so the label→value relationship is announced without extra
 * wiring. Server-safe, purely presentational — values are whatever you compose (text, a link,
 * a `TagGroup`, an `EmptyValue`). Verified NOT a `DataList` fit: DataList is a `<table>` renderer
 * for homogeneous collections; PropertyList is the heterogeneous key→value pane.
 * ----------------------------------------------------------------------------------------------*/

/** Native definition-list props for `PropertyList`. */
export type PropertyListProps = React.ComponentPropsWithRef<"dl">;

/**
 * `PropertyList` — the container. Rows stack with tight rhythm; the label
 * column is a shared fixed track so values align down the pane.
 *
 * @example
 * <PropertyList aria-label="Record details">
 *   <PropertyRow>
 *     <PropertyLabel icon={<Globe />}>Domains</PropertyLabel>
 *     <PropertyValue><a className="text-info-text" href="…">attio.com</a></PropertyValue>
 *   </PropertyRow>
 *   <PropertyRow>
 *     <PropertyLabel icon={<Users />}>Team</PropertyLabel>
 *     <PropertyValue><EmptyValue>Set a value…</EmptyValue></PropertyValue>
 *   </PropertyRow>
 * </PropertyList>
 */
export function PropertyList({ className, ...props }: PropertyListProps) {
  return (
    <dl
      data-slot="property-list"
      className={cn(
        // Named container: rows stack or sit side by side according to the PANE's
        // width, not the viewport's — the same facts pane is a narrow sidebar on a
        // wide screen as often as it is a wide column on a narrow one.
        "@container/property-list m-0 flex min-w-0 flex-col gap-1",
        className,
      )}
      {...props}
    />
  );
}

/** Native container props for one property row. */
export type PropertyRowProps = React.ComponentPropsWithRef<"div">;

/** `PropertyRow` — one label→value row. @example <PropertyRow><PropertyLabel>Name</PropertyLabel><PropertyValue>VegaStack</PropertyValue></PropertyRow> */
export function PropertyRow({ className, ...props }: PropertyRowProps) {
  return (
    <div
      data-slot="property-row"
      className={cn(
        // Below @xs the pane is too narrow for two tracks: the row stacks, so the
        // value gets the full width instead of being squeezed into a sliver.
        "grid min-h-(--size-sm) grid-cols-1 items-start gap-x-2 gap-y-0.5",
        // At @xs and up the label track SHRINKS TO ITS CONTENT above a 20-unit
        // (80px) floor, instead of the old fixed 112px: short labels stop wasting
        // the value column's width, and long ones are no longer clipped by a
        // track that never negotiated with them.
        "@xs/property-list:min-h-(--size-sm) @xs/property-list:grid-cols-[minmax(calc(var(--spacing)*20),max-content)_minmax(0,1fr)] @xs/property-list:items-center @xs/property-list:gap-y-2",
        className,
      )}
      {...props}
    />
  );
}

/** Props for the term/label cell in a property row. */
export interface PropertyLabelProps extends React.ComponentPropsWithRef<"dt"> {
  /** Leading inline-role icon (decorative — the text carries the meaning). @default undefined */
  icon?: React.ReactNode;
}

/** `PropertyLabel` — the muted label cell. @example <PropertyLabel>Name</PropertyLabel> */
export function PropertyLabel({
  className,
  icon,
  children,
  ...props
}: PropertyLabelProps) {
  return (
    <dt
      data-slot="property-label"
      className={cn(
        "flex min-w-0 items-center gap-1.5 text-label-sm text-muted-foreground",
        "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-(--icon-inline)",
        className,
      )}
      {...props}
    >
      {icon ? (
        <span aria-hidden className="shrink-0">
          {icon}
        </span>
      ) : null}
      <span className="min-w-0 truncate">{children}</span>
    </dt>
  );
}

/** Native description/value props for a property row. */
export type PropertyValueProps = React.ComponentPropsWithRef<"dd">;

/** `PropertyValue` — the value cell. @example <PropertyValue>VegaStack</PropertyValue> */
export function PropertyValue({ className, ...props }: PropertyValueProps) {
  return (
    <dd
      data-slot="property-value"
      className={cn(
        // Wraps rather than truncates (D18's rule applied outside the table): a
        // value is the point of the row, and `truncate` also meant `overflow:
        // hidden`, which CLIPPED the focus ring of any link inside it (SP-03).
        // Compose `TruncatedText` explicitly where a single line is genuinely
        // required.
        "m-0 min-w-0 text-base wrap-anywhere text-foreground",
        className,
      )}
      {...props}
    />
  );
}
