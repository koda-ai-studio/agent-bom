"use client";

import { Plus, X } from "lucide-react";

import { emptyRange, type ProductDraft, type RangeDraft } from "@/lib/operator-advisories";

import { Field, FieldError, inputClass, secondaryButtonClass } from "./advisory-form-fields";

const ECOSYSTEM_HINTS = ["generic", "npm", "pypi", "go", "maven", "cargo", "nuget", "rubygems", "deb", "rpm", "apk"];

/** One `affected[]` entry: package or CPE identity, version ranges and exact versions. */
export function AffectedProductFields({
  index,
  product,
  errorFor,
  onChange,
  onRemove,
}: {
  index: number;
  product: ProductDraft;
  errorFor: (field: string) => string | undefined;
  onChange: (next: ProductDraft) => void;
  onRemove?: (() => void) | undefined;
}) {
  const at = `affected.${index}`;
  const idBase = `advisory-affected-${index}`;
  const set = (patch: Partial<ProductDraft>) => onChange({ ...product, ...patch });
  const setRange = (rangeIndex: number, patch: Partial<RangeDraft>) =>
    set({ ranges: product.ranges.map((range, i) => (i === rangeIndex ? { ...range, ...patch } : range)) });
  const legend = `Affected product ${index + 1}`;
  const productError = errorFor(at);

  return (
    <fieldset aria-label={legend} className="min-w-0 space-y-3 rounded-xl border border-outline bg-surface p-3 sm:p-4">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-medium text-foreground">{legend}</h3>
        {onRemove ? (
          <button type="button" onClick={onRemove} className={secondaryButtonClass} aria-label={`Remove ${legend.toLowerCase()}`}>
            <X className="h-3.5 w-3.5" aria-hidden /> Remove
          </button>
        ) : null}
      </div>
      <div role="radiogroup" aria-label={`${legend} identity`} className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-secondary">
        <label className="inline-flex items-center gap-1.5">
          <input type="radio" name={`${idBase}-identity`} checked={product.identity === "package"} onChange={() => set({ identity: "package" })} />
          Package (ecosystem + name)
        </label>
        <label className="inline-flex items-center gap-1.5">
          <input type="radio" name={`${idBase}-identity`} checked={product.identity === "cpe"} onChange={() => set({ identity: "cpe" })} />
          CPE product
        </label>
      </div>
      {product.identity === "package" ? (
        <div className="grid gap-3 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">
          <Field id={`${idBase}-ecosystem`} label="Ecosystem" error={errorFor(`${at}.ecosystem`)}>
            {props => <input {...props} list={`${idBase}-ecosystems`} className={inputClass} value={product.ecosystem} onChange={e => set({ ecosystem: e.target.value })} placeholder="npm" />}
          </Field>
          <datalist id={`${idBase}-ecosystems`}>{ECOSYSTEM_HINTS.map(value => <option key={value} value={value}>{value}</option>)}</datalist>
          <Field id={`${idBase}-name`} label="Package name" error={errorFor(`${at}.name`)}>
            {props => <input {...props} className={inputClass} value={product.name} onChange={e => set({ name: e.target.value })} placeholder="lodash" />}
          </Field>
        </div>
      ) : (
        <Field id={`${idBase}-cpe`} label="CPE product (vendor:product)" hint="Matches packages by CPE. Distro packages that ship this product are reported as possibly affected, never compared to upstream ranges." error={errorFor(`${at}.cpe_product`)}>
          {props => <input {...props} className={inputClass} value={product.cpe_product} onChange={e => set({ cpe_product: e.target.value })} placeholder="php:php" />}
        </Field>
      )}
      <div className="space-y-2">
        <p className="text-xs font-medium text-ink-secondary">Affected version ranges</p>
        {product.ranges.map((range, rangeIndex) => {
          const rangeId = `${idBase}-range-${rangeIndex}`;
          const rangeAt = `${at}.ranges.${rangeIndex}`;
          return (
            <div key={rangeIndex} className="grid items-start gap-2 sm:grid-cols-[minmax(0,1fr)_8.5rem_minmax(0,1fr)_auto]">
              <Field id={`${rangeId}-introduced`} label="Introduced" error={errorFor(`${rangeAt}.introduced`)}>
                {props => <input {...props} className={inputClass} value={range.introduced} onChange={e => setRange(rangeIndex, { introduced: e.target.value })} placeholder="8.3.0" />}
              </Field>
              <Field id={`${rangeId}-bound`} label="Range end">
                {props => (
                  <select {...props} className={inputClass} value={range.bound} onChange={e => setRange(rangeIndex, { bound: e.target.value as RangeDraft["bound"] })}>
                    <option value="fixed">fixed in</option>
                    <option value="last_affected">last affected</option>
                  </select>
                )}
              </Field>
              <Field id={`${rangeId}-end`} label={range.bound === "fixed" ? "Fixed" : "Last affected"} error={errorFor(`${rangeAt}.${range.bound}`) ?? errorFor(rangeAt)}>
                {props => <input {...props} className={inputClass} value={range.boundValue} onChange={e => setRange(rangeIndex, { boundValue: e.target.value })} placeholder={range.bound === "fixed" ? "8.3.36" : "8.3.35"} />}
              </Field>
              <button
                type="button"
                className={`${secondaryButtonClass} justify-self-start sm:mt-5`}
                aria-label={`Remove range ${rangeIndex + 1} of ${legend.toLowerCase()}`}
                disabled={product.ranges.length === 1}
                onClick={() => set({ ranges: product.ranges.filter((_, i) => i !== rangeIndex) })}
              >
                <X className="h-3.5 w-3.5" aria-hidden />
              </button>
            </div>
          );
        })}
        <button type="button" className={secondaryButtonClass} onClick={() => set({ ranges: [...product.ranges, emptyRange()] })}>
          <Plus className="h-3.5 w-3.5" aria-hidden /> Add range
        </button>
      </div>
      <Field id={`${idBase}-versions`} label="Exact affected versions" hint="Optional. Comma-separated, for versions outside any range." error={errorFor(`${at}.versions`)}>
        {props => <input {...props} className={inputClass} value={product.versions} onChange={e => set({ versions: e.target.value })} placeholder="8.3.31, 8.3.32" />}
      </Field>
      <FieldError id={`${idBase}-error`} message={productError} />
    </fieldset>
  );
}
