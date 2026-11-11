import { useEffect, useRef, useState } from 'react'

export const API_BASE = 'http://localhost:8003'
const WS_URL = 'ws://localhost:8003/ws/live'

export async function getJSON(path) {
  const res = await fetch(API_BASE + path)
  if (!res.ok) throw new Error(`${res.status} ${path}`)
  return res.json()
}

// Polls `path` every `ms`; refetches immediately when `refreshKey` changes.
// Keeps the last good value on failure so a backend blip doesn't blank the screen.
export function usePoll(path, ms, refreshKey) {
  const [data, setData] = useState(null)
  useEffect(() => {
    let alive = true
    const load = () =>
      getJSON(path).then((d) => alive && setData(d)).catch(() => {})
    load()
    const id = setInterval(load, ms)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [path, ms, refreshKey])
  return data
}

// Live WebSocket with capped exponential back-off. Returns connection status.
export function useLive(onMessage, onOpen) {
  const handlers = useRef({ onMessage, onOpen })
  handlers.current = { onMessage, onOpen }
  const [status, setStatus] = useState('connecting')

  useEffect(() => {
    let ws
    let timer
    let delay = 1000
    let closed = false
    const connect = () => {
      setStatus('connecting')
      ws = new WebSocket(WS_URL)
      ws.onopen = () => {
        delay = 1000
        setStatus('live')
        handlers.current.onOpen?.()
      }
      ws.onmessage = (e) => {
        try {
          handlers.current.onMessage(JSON.parse(e.data))
        } catch {
          /* ignore malformed frames */
        }
      }
      ws.onclose = () => {
        if (closed) return
        setStatus('down')
        timer = setTimeout(connect, delay)
        delay = Math.min(delay * 2, 8000)
      }
    }
    connect()
    return () => {
      closed = true
      clearTimeout(timer)
      ws?.close()
    }
  }, [])
  return status
}
