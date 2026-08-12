'use client'

import Modal from '@/components/ui/Modal'

interface Props {
  title: string
  subtitle: string
  link: string
  onShare: () => void
  onCopy: () => void
  onClose: () => void
}

/**
 * Шит «посилання створено» — спільний для команди бази і гостьових лінків.
 * Обидва екрани мали ідентичну копію, включно з тим самим інлайновим обʼєктом
 * стилю моноспейс-блоку.
 */
export default function CreatedLinkSheet({ title, subtitle, link, onShare, onCopy, onClose }: Props) {
  // `buildDeepLink()` віддає рівно '#', коли не задано NEXT_PUBLIC_TELEGRAM_BOT_USERNAME
  // (статичний експорт запікає змінні у білд, тож дізнатись про це можна лише тут).
  // Без цього гарда шит спокійно пропонував «Скопіювати» та «У Telegram» для
  // мертвого '#': власник надсилав запрошення, яке нікуди не веде, і дізнавався
  // про це від одержувача. Цей клас уже давав прод-інцидент — неправильний
  // TELEGRAM_APP_NAME, коли всі шери 404-или. ShareSheet для відсутнього токена
  // теж не вдає, що посилання є.
  const usable = /^https?:\/\//.test(link)

  return (
    <Modal
      title={title}
      subtitle={subtitle}
      onClose={onClose}
      actions={[
        // Короткий підпис — не косметика: «Поділитись в Telegram» шириться за
        // половинну кнопку на 31px при 375px і вилазить за її край. Формулювання
        // збігається з ShareSheet, де ця дія вже зветься «У Telegram».
        { label: 'У Telegram', variant: 'primary', onClick: onShare, disabled: !usable },
        { label: 'Скопіювати', variant: 'secondary', onClick: onCopy, disabled: !usable },
      ]}
    >
      {usable ? (
        <div className="link-mono">{link}</div>
      ) : (
        <div className="link-mono">
          Посилання не сформувалось: у застосунку не налаштований юзернейм бота.
          Запрошення вже створене — надішліть його після налаштування.
        </div>
      )}
    </Modal>
  )
}
