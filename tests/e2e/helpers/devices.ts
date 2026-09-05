/**
 * ГЕОМЕТРІЇ ПРИСТРОЇВ — один список на всі спеки, що ходять поза 375×667.
 *
 * Виніс сюди, коли до `devices.spec.ts` додався `keyboard-devices.spec.ts`:
 * друга копія таблиці розійшлася б за два раунди, і «перевірено на пʼятьох
 * ширинах» перестало б означати те саме в двох файлах. Той самий урок, що вже
 * оплачений `TAP_DEBT` (він переїхав у `helpers/contrast.ts` із тієї ж
 * причини).
 */

export interface Device {
  name: string
  width: number
  height: number
  dsf: number
  /** iOS чи Android — впливає лише на UA, який читає код фолбеків. */
  ua: string
}

export const IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
export const ANDROID = 'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
export const IPAD = 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'

/**
 * 375×667 свідомо ВІДСУТНІЙ: це проєкт `iphone-se` з конфігу, тобто його
 * проходять усі решта тестів. Дублювати його тут означало б платити за
 * найдовший обхід двічі й нічого нового не дізнатись.
 */
export const DEVICES: Device[] = [
  // Найвужче, що реально трапляється. Саме тут ламаються підписи.
  { name: 'Galaxy S8 (360)', width: 360, height: 740, dsf: 3, ua: ANDROID },
  { name: 'iPhone 13/14 (390)', width: 390, height: 844, dsf: 3, ua: IOS },
  { name: 'Pixel 7 (412)', width: 412, height: 915, dsf: 2.6, ua: ANDROID },
  { name: 'iPhone 15 Pro Max (430)', width: 430, height: 932, dsf: 3, ua: IOS },
  // Планшет: мобільний лейаут, розтягнутий удвічі проти проєктного.
  { name: 'iPad mini (744)', width: 744, height: 1133, dsf: 2, ua: IPAD },
]

/** Контекст під конкретний пристрій — однаковий для всіх спеків. */
export const deviceContext = (dev: Device) => ({
  viewport: { width: dev.width, height: dev.height },
  deviceScaleFactor: dev.dsf,
  isMobile: true,
  hasTouch: true,
  userAgent: dev.ua,
})
