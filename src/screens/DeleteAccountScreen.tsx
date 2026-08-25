'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import Header from '@/components/ui/Header'
import { IconTrash } from '@/components/Icons'
import { offlineGuard } from '@/lib/offline'
import { hapticNotify } from '@/lib/telegram'
import { scrollFocusedIntoView } from '@/lib/utils'

const PHRASE = 'ВИДАЛИТИ'

/**
 * Повноекранне видалення акаунта — останній `<Modal>` застосунку (фаза 5).
 *
 * Підтвердження тут ТИПІЗОВАНЕ, а не нативний `showPopup`: попап Telegram має
 * лише кнопки, а незворотна втрата всіх даних вимагає свідомого вводу слова.
 * Це те саме рішення, що діяло й у шиті, — переїзд на екран його не міняє.
 */
export default function DeleteAccountScreen() {
  const { back } = useAppStore()
  const { deleteAccount } = useAuth()
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)

  const armed = text.trim().toUpperCase() === PHRASE

  async function handleDelete() {
    if (!armed || busy || offlineGuard()) return
    setBusy(true)
    hapticNotify('warning')
    const ok = await deleteAccount()
    setBusy(false)
    // На успіху `deleteAccount` сам виводить із застосунку; лишаємось тут
    // тільки якщо не вийшло — тост про причину показує сам хук.
    if (!ok) return
  }

  return (
    <div className="scr bg-teal">
      <Header title="Видалити акаунт?" onBack={back} />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div className="del-warn glass-s">
          <IconTrash size={20} color="var(--err-fg)" />
          <p>
            Буде <b>НАЗАВЖДИ</b> видалено: усі бази та обʼєкти, фото й документи,
            платежі, підбірки й доступи. Відновити неможливо.
          </p>
        </div>

        <div className="fg glass-s">
          <div className="fr">
            <span className="fr-l">Впишіть <b style={{ color: 'var(--t1)' }}>{PHRASE}</b></span>
            <input
              className="fr-i"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={PHRASE}
              autoCapitalize="characters"
              aria-label="Підтвердження видалення"
            />
          </div>
        </div>

        <button
          className="mbtn err mbtn-flow"
          disabled={!armed || busy}
          aria-busy={busy}
          onClick={() => void handleDelete()}
        >
          Видалити акаунт
        </button>
      </div>
    </div>
  )
}
