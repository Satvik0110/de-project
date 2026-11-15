export const fmtNum = (v, digits = 0) =>
  v == null || Number.isNaN(v) ? '—' : Number(v).toLocaleString(undefined, { maximumFractionDigits: digits })

export const fmtMs = (v) => {
  if (v == null) return '—'
  if (v >= 10000) return `${(v / 1000).toFixed(1)} s`
  return `${Math.round(v)} ms`
}

export const fmtPct = (v) => (v == null ? '—' : `${Math.round(v * 100)}%`)

export const fmtTime = (iso) =>
  iso ? new Date(iso).toLocaleTimeString([], { hour12: false }) : '—'

export const fmtBytes = (b) => {
  if (b == null) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  while (b >= 1024 && i < units.length - 1) {
    b /= 1024
    i++
  }
  return `${b.toFixed(i ? 1 : 0)} ${units[i]}`
}

export const fmtSpan = (from, to) => {
  if (!from || !to) return '—'
  const s = Math.max(0, (new Date(to) - new Date(from)) / 1000)
  return s < 60 ? `${Math.round(s)} s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`
}

// Seconds → "350 ms" below one second, otherwise "4.2 s" / "68 s".
export const fmtSec = (s) => {
  if (s == null) return '—'
  if (s < 1) return `${Math.round(s * 1000)} ms`
  return `${fmtNum(s, s < 10 ? 1 : 0)} s`
}

// When an alert first fired (falls back to detected_at for older payloads).
export const firstDetected = (a) => a.first_detected_at ?? a.detected_at
