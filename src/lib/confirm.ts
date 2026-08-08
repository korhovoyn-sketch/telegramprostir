'use client'

import { useAppStore } from '@/store/appStore'
import { hapticNotify } from '@/lib/telegram'

export interface ConfirmOptions {
  title: string
  message: string
  /** Підпис підтверджувальної кнопки, напр. «Видалити». */
  confirmLabel: string
  /** Червона кнопка в нативному попапі + `danger` у фолбек-модалці. */
  destructive?: boolean
}

/**
 * Підтвердження НЕЗВОРОТНОЇ дії.
 *
 * Гайдлайни Telegram: для критичних речей потрібен НАТИВНИЙ попап — він несе
 * авторитет платформи, тобто користувач бачить, що питає Telegram, а не
 * невідомий скрипт у webview. Тому спершу `showPopup`, і лише якщо його немає
 * (браузер, старий клієнт, тести) — наша скляна модалка з тим самим текстом.
 *
 * НЕ використовувати там, де підтвердження потребує введення: нативний попап
 * має лише кнопки. Видалення акаунта з набором слова «ВИДАЛИТИ» лишається на
 * власній модалці свідомо.
 */
export function confirmAction(opts: ConfirmOptions): Promise<boolean> {
  if (opts.destructive !== false) hapticNotify('warning')

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tg = (typeof window === 'undefined' ? undefined : window.Telegram?.WebApp) as any
  // initData непорожній лише в реальному контейнері Telegram: у браузері об'єкт
  // SDK може існувати, але попап не відкриється — і колбек не прийде ніколи.
  const native = typeof tg?.showPopup === 'function' && !!tg?.initData

  if (native) {
    return new Promise<boolean>((resolve) => {
      let settled = false
      const done = (ok: boolean) => { if (!settled) { settled = true; resolve(ok) } }
      try {
        tg.showPopup(
          {
            title: opts.title,
            // Нативний попап обрізає довгі тексти — тримаємо повідомлення коротким.
            message: opts.message,
            buttons: [
              { id: 'ok', type: opts.destructive ? 'destructive' : 'default', text: opts.confirmLabel },
              { id: 'cancel', type: 'cancel' },
            ],
          },
          // Закриття свайпом віддає null — трактуємо як відмову.
          (buttonId: string | null) => done(buttonId === 'ok'),
        )
      } catch {
        // Старі клієнти кидають на невідомому методі — тихо падаємо у фолбек.
        askInApp(opts).then(done)
      }
    })
  }

  return askInApp(opts)
}

/** Фолбек: скляна модалка застосунку (той самий текст і той самий підпис). */
function askInApp(opts: ConfirmOptions): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    useAppStore.getState().requestConfirm({ ...opts, resolve })
  })
}
