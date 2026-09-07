'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import Header from '@/components/ui/Header'
import { IconTrash } from '@/components/Icons'
import { offlineGuard } from '@/lib/offline'
import { hapticNotify } from '@/lib/telegram'
import { scrollFocusedIntoView } from '@/lib/utils'
import { tx } from '@/lib/tx'
import { tr } from '@/lib/i18n'

const PHRASE = () => (tr('ВИДАЛИТИ'))

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

  const armed = text.trim().toUpperCase() === PHRASE()

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
      <Header title={tr('Видалити акаунт?')} onBack={back} />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div className="del-warn glass-s">
          <IconTrash size={20} color="var(--err-fg)" />
          <p>
            {tx('Буде {0} видалено: усі бази та обʼєкти, фото й документи, платежі, підбірки й доступи. Відновити неможливо.', <b>{tr('НАЗАВЖДИ')}</b>)}
          </p>
        </div>

        <div className="fg glass-s">
          <div className="fr">
            <span className="fr-l">{tr('Впишіть')}{' '}<b style={{ color: 'var(--t1)' }}>{PHRASE()}</b></span>
            <input
              className="fr-i"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={PHRASE()}
              autoCapitalize="characters"
              aria-label={tr('Підтвердження видалення')}
            />
          </div>
        </div>

        <button
          className="mbtn err mbtn-flow"
          disabled={!armed || busy}
          aria-busy={busy}
          onClick={() => void handleDelete()}
        >
          {tr('Видалити акаунт')}
        </button>
      </div>
    </div>
  )
}
