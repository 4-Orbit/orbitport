const time = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

/** Local time, compact, e.g. "Oct 6, 19:55:08". The full ISO timestamp goes in a title attribute. */
export function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : time.format(d);
}
