import { useEffect, useId, useRef, useState, type ReactNode } from "react";

/**
 * A destructive button that asks inline before acting (never a blocking
 * browser dialog). `impact` explains what will change.
 */
export function ConfirmButton({ label, confirmLabel, impact, onConfirm, className = "link-button", ariaLabel }: {
  label: ReactNode;
  confirmLabel: string;
  impact?: ReactNode;
  onConfirm: () => void;
  className?: string;
  ariaLabel?: string;
}) {
  const [asking, setAsking] = useState(false);
  if (!asking) {
    return (
      <button type="button" className={className} aria-label={ariaLabel} onClick={() => setAsking(true)}>
        {label}
      </button>
    );
  }
  return (
    <span className="confirm" role="group" aria-label="Confirm">
      {impact && <span className="confirm-impact">{impact}</span>}
      <button
        type="button"
        className="button small danger"
        autoFocus
        onClick={() => {
          setAsking(false);
          onConfirm();
        }}
      >
        {confirmLabel}
      </button>
      <button type="button" className="button small" onClick={() => setAsking(false)}>
        Cancel
      </button>
    </span>
  );
}

export interface ToastState {
  text: string;
  undo?: boolean;
}

/** A dismissible status line with an optional Undo action. */
export function Toast({ toast, onUndo, onClose }: { toast: ToastState | null; onUndo: () => void; onClose: () => void }) {
  if (!toast) return null;
  return (
    <div className="toast" role="status">
      <span>{toast.text}</span>
      {toast.undo && (
        <button
          type="button"
          className="button small"
          onClick={() => {
            onUndo();
            onClose();
          }}
        >
          Undo
        </button>
      )}
      <button type="button" className="icon-button" aria-label="Dismiss" onClick={onClose}>
        ×
      </button>
    </div>
  );
}

/**
 * A modal confirmation: the rest of the page can't be used until one of the
 * actions (or Cancel / Escape) is chosen. A native <dialog> opened with
 * showModal(), never a blocking browser alert.
 */
export function ConfirmDialog({ title, children, actions, onCancel }: {
  title: string;
  children: ReactNode;
  /** The choices, most likely first; the first gets focus. */
  actions: { label: string; onClick: () => void; tone?: "danger" | "default"; disabled?: boolean }[];
  onCancel: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
    return () => d?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className="confirm-dialog"
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        onCancel();
      }}
    >
      <h2 id={titleId}>{title}</h2>
      <div className="confirm-dialog-body">{children}</div>
      <div className="row confirm-dialog-actions">
        {actions.map((a, i) => (
          <button key={a.label} type="button" className={`button${a.tone === "danger" ? " danger" : ""}`} autoFocus={i === 0} disabled={a.disabled} onClick={a.onClick}>
            {a.label}
          </button>
        ))}
        <button type="button" className="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </dialog>
  );
}

/** A modal that only informs: closed with its button or Escape. */
export function InfoDialog({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
    return () => d?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className="confirm-dialog"
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <h2 id={titleId}>{title}</h2>
      <div className="confirm-dialog-body">{children}</div>
      <div className="row confirm-dialog-actions">
        <button type="button" className="button" autoFocus onClick={onClose}>
          Close
        </button>
      </div>
    </dialog>
  );
}
