/**
 * Copy a link to the clipboard and report whether it actually succeeded.
 * Telegram's webview (and any non-secure context) may lack navigator.clipboard,
 * so we fall back to a hidden textarea + execCommand. Callers must branch the
 * toast on the returned boolean — never show "copied" unconditionally.
 */
export async function copyLink(url: string): Promise<boolean> {
  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(url)
      return true
    }
  } catch { /* fall through to legacy path */ }

  try {
    const ta = document.createElement('textarea')
    ta.value = url
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}
