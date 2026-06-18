import { describe, it, expect, afterEach } from 'vitest'
import { openSessionGate, closeSessionGate, waitForSessionGate } from '@/lib/sessionGate'

// This contract is what the "nothing loads" regression depends on: a fast-path
// session restore must let navigation proceed immediately while still letting
// REST/Storage queries wait briefly for a real JWT. Two earlier fixes flip-
// flopped between blocking navigation (caused a splash stall) and not blocking
// queries at all (caused empty data) because neither separated the two concerns.

describe('sessionGate', () => {
  afterEach(() => {
    closeSessionGate()
  })

  it('resolves immediately when no gate has been opened', async () => {
    const start = Date.now()
    await waitForSessionGate()
    expect(Date.now() - start).toBeLessThan(20)
  })

  it('blocks waitForSessionGate until the timeout elapses when not closed', async () => {
    openSessionGate(40)
    let resolved = false
    waitForSessionGate().then(() => { resolved = true })

    await new Promise(r => setTimeout(r, 10))
    expect(resolved).toBe(false)

    await new Promise(r => setTimeout(r, 60))
    expect(resolved).toBe(true)
  })

  it('closeSessionGate resolves it immediately, before the timeout elapses', async () => {
    openSessionGate(5000)
    let resolved = false
    waitForSessionGate().then(() => { resolved = true })

    closeSessionGate()
    await Promise.resolve()
    await Promise.resolve()
    expect(resolved).toBe(true)
  })

  it('a new gate replaces a prior unclosed one instead of leaking it open forever', async () => {
    openSessionGate(5000)
    let firstResolved = false
    waitForSessionGate().then(() => { firstResolved = true })

    openSessionGate(20)
    await new Promise(r => setTimeout(r, 40))
    expect(firstResolved).toBe(true)
    await expect(waitForSessionGate()).resolves.toBeUndefined()
  })
})
