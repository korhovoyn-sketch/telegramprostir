'use client'

import { useState, useCallback } from 'react'

const KEY = 'ob_v1'
const STEPS = ['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'] as const

function load(): Set<string> {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? new Set(JSON.parse(raw) as string[]) : new Set()
  } catch {
    return new Set()
  }
}

function save(seen: Set<string>) {
  try { localStorage.setItem(KEY, JSON.stringify([...seen])) } catch { /* quota */ }
}

export function useOnboarding(id: string) {
  const [isDone, setIsDone] = useState(() => load().has(id))

  const markDone = useCallback(() => {
    const seen = load()
    seen.add(id)
    save(seen)
    setIsDone(true)
  }, [id])

  return { isDone, markDone }
}

export function skipAllOnboarding() {
  const seen = load()
  STEPS.forEach(id => seen.add(id))
  save(seen)
}
