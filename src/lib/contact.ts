/**
 * Контакти користувача: одна перевірка на онбординг і Профіль.
 *
 * Доти email перевірявся регекспом лише на кроці онбордингу, а в Профілі той
 * самий email зберігався будь-яким — «abc» проходило. Телефон не перевірявся
 * ніде, а саме він за згодою власника показується незнайомцям на /v як
 * посилання `tel:`, тобто сміття в ньому — це мертва кнопка «Подзвонити».
 *
 * Межі довжини — з КОЛОНОК (`users.email` VARCHAR(254), `users.phone`
 * VARCHAR(32)). Поле без межі пропускало довший рядок до БД, і та відповідала
 * «value too long», яке користувач бачив як «Спробуйте ще раз».
 */
export const EMAIL_MAX = 254
export const PHONE_MAX = 32

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

export function isValidEmail(v: string): boolean {
  return EMAIL_RE.test(v.trim())
}

/** Цифри, пробіли, `+`, `-`, дужки — і щонайменше 7 цифр. */
export function isValidPhone(v: string): boolean {
  const t = v.trim()
  return /^\+?[\d\s()-]+$/.test(t) && t.replace(/\D/g, '').length >= 7
}
