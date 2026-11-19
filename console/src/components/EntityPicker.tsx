import { useEffect, useId, useRef, useState } from "react";

export interface PickerGroup {
  label: string;
  options: string[];
}

interface Props {
  /** Visible label; also the select's accessible name. */
  label: string;
  value: string;
  onChange: (value: string) => void;
  /** Ungrouped choices, shown first. */
  options?: string[];
  /** Choices under labeled <optgroup>s, after `options`. */
  groups?: PickerGroup[];
  /** The list is still loading. */
  loading?: boolean;
  /** The list failed to load: say why and accept typed values instead. */
  error?: string | null;
  /** A leading choice meaning the empty value, e.g. "(account)" or "Any agent". */
  emptyLabel?: string;
  /** Offer "Other…" to type a value that isn't listed. */
  allowOther?: boolean;
  /** Placeholder for the typed value. */
  placeholder?: string;
  /** Why a value can't be used, or null. Shown under the field. */
  problem?: string | null;
  /** A short note under the field (e.g. "more keys exist than are listed"). */
  note?: string;
  /** What a missing choice is called in the menu, e.g. "a key". */
  noun?: string;
  disabled?: boolean;
  inline?: boolean;
}

const OTHER = "\u0000other";

/**
 * A select of known agents, keys or repositories, with an explicit
 * "Other…" for values that legitimately aren't listed yet. A value that
 * isn't in the list (a replayed request, a removed agent) opens as Other so
 * it is never silently replaced. If the list can't load, it says so and
 * falls back to a text field.
 */
export function EntityPicker({ label, value, onChange, options = [], groups = [], loading = false, error = null, emptyLabel, allowOther = false, placeholder, problem = null, note, noun = "one", disabled = false, inline = false }: Props) {
  const id = useId();
  const all = [...options, ...groups.flatMap((g) => g.options)];
  const listed = (emptyLabel !== undefined && value === "") || all.includes(value);
  // "Other…" was chosen and the user is typing. A value set from outside
  // (the action changed, a replay) ends it.
  const [otherMode, setOtherMode] = useState(false);
  const typed = useRef<string | null>(null);
  useEffect(() => {
    if (otherMode && value !== typed.current) setOtherMode(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  const freeText = !!error;
  const showInput = freeText || (!loading && (otherMode || (value !== "" && !listed)));
  const type = (v: string) => {
    typed.current = v;
    onChange(v);
  };
  const cls = `field picker${inline ? " inline" : ""}`;

  if (freeText) {
    return (
      <div className={cls}>
        <label htmlFor={id}>{label}</label>
        <input id={id} value={value} placeholder={placeholder} disabled={disabled} onChange={(e) => type(e.target.value.trim())} />
        <span className="builder-warning">Couldn't load the list: {error}. Type a value instead.</span>
        {problem && value && <span className="field-hint">{problem}</span>}
      </div>
    );
  }

  return (
    <div className={cls}>
      <label htmlFor={id}>{label}</label>
      <select
        id={id}
        value={loading ? value : showInput ? OTHER : value}
        disabled={disabled || loading}
        onChange={(e) => {
          const v = e.target.value;
          if (v === OTHER) {
            typed.current = "";
            setOtherMode(true);
            onChange("");
            return;
          }
          setOtherMode(false);
          onChange(v);
        }}
      >
        {loading && <option value={value}>{value || "loading…"}</option>}
        {!loading && (
          <>
            {emptyLabel !== undefined && <option value="">{emptyLabel}</option>}
            {emptyLabel === undefined && value === "" && !showInput && (
              <option value="" disabled>
                {all.length ? `choose ${noun}…` : `no ${noun === "one" ? "choices" : noun.replace(/^an? /, "") + "s"} listed`}
              </option>
            )}
            {options.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
            {groups
              .filter((g) => g.options.length > 0)
              .map((g) => (
                <optgroup key={g.label} label={g.label}>
                  {g.options.map((o) => (
                    <option key={o} value={o}>
                      {o}
                    </option>
                  ))}
                </optgroup>
              ))}
            {(allowOther || (value !== "" && !listed)) && <option value={OTHER}>Other…</option>}
          </>
        )}
      </select>
      {showInput && (
        <input aria-label={`${label}: other value`} value={value} placeholder={placeholder} disabled={disabled} autoFocus={otherMode} onChange={(e) => type(e.target.value.trim())} />
      )}
      {problem && (value || showInput) && <span className="field-hint">{problem}</span>}
      {note && <span className="muted small picker-note">{note}</span>}
    </div>
  );
}
