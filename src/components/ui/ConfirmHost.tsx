'use client'

import { useAppStore } from '@/store/appStore'
import Modal from '@/components/ui/Modal'

/**
 * Фолбек для `confirmAction()` там, де нативного попапа Telegram немає:
 * браузер, десктоп, старий клієнт, тести. Живе в layout поруч із тостом, бо
 * підтвердження просять із будь-якого екрана й навіть із іншої модалки.
 *
 * Текст той самий, що в нативному попапі — інакше при переході між платформами
 * розходились би формулювання незворотних дій.
 */
export default function ConfirmHost() {
  const req = useAppStore((s) => s.confirmRequest)
  const answer = useAppStore((s) => s.answerConfirm)
  if (!req) return null

  return (
    <Modal
      title={req.title}
      subtitle={req.message}
      onClose={() => answer(false)}
      actions={[
        {
          label: req.confirmLabel,
          variant: req.destructive === false ? 'primary' : 'danger',
          onClick: () => answer(true),
        },
        { label: 'Скасувати', variant: 'secondary', onClick: () => answer(false) },
      ]}
    />
  )
}
