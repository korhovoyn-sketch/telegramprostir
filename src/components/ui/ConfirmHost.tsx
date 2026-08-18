'use client'

import { useAppStore } from '@/store/appStore'
import ActionSheet from '@/components/ui/ActionSheet'
import { useLatch } from '@/lib/useLatch'

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
  // `answerConfirm` нулює `confirmRequest` в той самий рендер, що й відповідь —
  // без латча заголовок/текст зникли б РАНІШЕ за вихідну анімацію ActionSheet.
  const latched = useLatch(req)

  return (
    <ActionSheet
      open={!!req}
      title={latched?.title ?? ''}
      subtitle={latched?.message}
      onClose={() => answer(false)}
      actions={latched ? [
        {
          label: latched.confirmLabel,
          variant: latched.destructive === false ? 'primary' : 'danger',
          onClick: () => answer(true),
        },
        { label: 'Скасувати', variant: 'secondary', onClick: () => answer(false) },
      ] : []}
    />
  )
}
