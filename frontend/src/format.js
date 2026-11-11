export function formatTime(iso) {
  return iso ? new Date(iso).toLocaleTimeString([], { hour12: false }) : '—';
}
