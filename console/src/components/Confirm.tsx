import { useState, type ReactNode } from "react";

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
