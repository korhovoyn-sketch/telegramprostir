'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { scrollFocusedIntoView } from '@/lib/utils'
import { layoutShrunkByKeyboard } from '@/lib/telegram'

// Mounted-modal stack: Escape must close only the TOPMOST modal (a confirm
// nested inside ShareSheet must not tear the sheet down too — backdrop taps
// never did).
const modalStack: symbol[] = []

// Первинна і небезпечна дії — скляні (див. .btn-glass); «Скасувати» лишається
// нейтральним склом .modal-btn.secondary.
const MODAL_BTN_GLASS: Record<string, string> = {
  primary: 'btn-glass info',
  danger: 'btn-glass err',
}

/**
 * Клас кнопки шита. Експортується, бо `.modal-btn.primary` сам по собі задає лише
 * КОЛІР тексту — заливку дає `btn-glass`, і донедавна її додавав виключно шлях
 * `actions`. Тому пара кнопок ShareSheet, написана руками як `modal-btn primary`,
 * виглядала слабшою за `secondary` поруч (у тієї заливка є). Кнопка поза
 * `actions` — легітимна, коли вона мусить стояти в потоці біля свого вмісту, а
 * не sticky на дні; рецепт для неї береться звідси, а не переписується.
 */
export function modalBtnClass(variant: 'primary' | 'danger' | 'secondary'): string {
  return `modal-btn ${variant} ${MODAL_BTN_GLASS[variant] ?? ''}`.trim()
}

// Консервативна висота клавіатури для платформ, які її НЕ повідомляють (iOS у
// Telegram часто не ресайзить webview: і viewportChanged, і visualViewport
// показують 0). Шит прив'язаний до низу екрана, тож без цього поля вводу
// опиняються ПІД клавіатурою. Ліфт застосовуємо тим самим `--keyboard-h`, лише
// локально на оверлеї — щоб працювали наявні клампи padding і max-height.
const KB_FALLBACK_PX = 320
// Скільком px звітованої висоти вже можна вірити (0–2px трапляються як шум).
const KB_TRUSTED_PX = 100
// Скільки чекати після фокуса, щоб клавіатура встигла відрапортуватись.
const KB_PROBE_MS = 350
// Другий, підтверджувальний замір ПІСЛЯ першої проби: на iOS-оверлеї (Telegram
// не ресайзить webview) звіт про клавіатуру йде через visualViewport.resize,
// який ІНОДІ приходить пізніше за 350мс. Одноразова проба рівно на цій межі
// ловила проміжний стан «клавіатури ще не видно» і вмикала фолбек 320px ПОВЕРХ
// реальної клавіатури, що вже починала з'являтися, — шит сіпався і за мить сам
// себе «виправляв», щойно приходив справжній розмір.
const KB_CONFIRM_MS = 200

interface ModalProps {
  title: string
  subtitle?: string
  onClose: () => void
  children?: React.ReactNode
  actions?: Array<{
    label: string
    variant: 'primary' | 'danger' | 'secondary'
    onClick: () => void
    disabled?: boolean
  }>
}

export default function Modal({ title, subtitle, onClose, children, actions }: ModalProps) {
  const idRef = useRef<symbol | null>(null)
  if (idRef.current === null) idRef.current = Symbol('modal')
  const titleId = useId()
  const descId = useId()
  const modalRef = useRef<HTMLDivElement>(null)
  const overlayRef = useRef<HTMLDivElement>(null)
  // Exit animation: dismiss gestures set `closing`, the slide-down/​fade plays,
  // then onClose actually unmounts us (open slid up but close used to just pop).
  const [closing, setClosing] = useState(false)
  const firedRef = useRef(false)
  // Portal target only exists in the browser (static export prerenders on Node).
  const [mounted, setMounted] = useState(false)
  useEffect(() => { setMounted(true) }, [])
  // Re-entry guard: a destructive action is usually async and leaves the modal
  // up while it flies, so a fast double-tap fired it twice (double DELETE).
  const [busy, setBusy] = useState(false)
  // Дзеркало `busy` у ref. Стан тут не годиться як джерело правди для гардів:
  // ефект Escape має `[]`-залежності й захоплює `requestClose` із першого
  // рендера, де `busy` ще false — тобто Escape обходив би гард закриття. Ref
  // читається завжди свіжим і заодно робить re-entry гард синхронним (стан
  // оновлюється асинхронно, тож два швидкі тапи могли проскочити обидва).
  const busyRef = useRef(false)
  // Ліфт шита, коли платформа не повідомляє висоту клавіатури (див. константи).
  const [kbFallback, setKbFallback] = useState(false)
  // Знімає transition на один кадр, коли ХИБНИЙ ліфт відкликається (див. CSS
  // `.kb-snap`). Стан, а не classList: обидва setState потрапляють в один рендер,
  // тож кадр, у якому падінг падає до нуля, вже має transition:none — імперативне
  // додавання класу перегони з рендером React не гарантує.
  const [kbSnap, setKbSnap] = useState(false)
  const kbProbeRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const kbConfirmRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const kbDropRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const kbFixRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  // Висота вікна на момент відкриття шита — базова лінія для детекту стискання.
  const baseInnerHRef = useRef(0)
  useEffect(() => { baseInnerHRef.current = window.innerHeight }, [])

  /**
   * Чи webview УЖЕ стиснувся під клавіатуру.
   *
   * `layoutShrunkByKeyboard()` питає про це Telegram (`viewportHeight` vs
   * `viewportStableHeight`), і саме на цьому ламалось: клієнт користувача
   * стискав webview, але цих значень не оновлював, тож гард казав «не
   * стиснувся», шит додавав СВОЇ 320px поверх уже врахованої клавіатури — і
   * відлітав у верх екрана з дірою під собою (скріншот: шит 26%, діра 31%,
   * клавіатура 43% — арифметика зійшлась точно).
   *
   * Тому другий, незалежний від Telegram сигнал: власне вікно просто стало
   * нижчим, ніж було на момент відкриття шита. Якщо клавіатура вже була
   * відкрита при монтуванні, база вже врахує її — і різниця буде нульовою або
   * відʼємною, тобто хибного спрацювання це дати не може.
   */
  function layoutCompressed(): boolean {
    if (layoutShrunkByKeyboard()) return true
    const base = baseInnerHRef.current
    return base > 0 && base - window.innerHeight >= KB_TRUSTED_PX
  }

  function reportedKeyboardPx(): number {
    const css = parseFloat(
      getComputedStyle(document.documentElement).getPropertyValue('--keyboard-h'),
    )
    const vv = window.visualViewport
    const measured = vv ? Math.max(0, Math.round(window.innerHeight - vv.height)) : 0
    return Math.max(Number.isFinite(css) ? css : 0, measured)
  }

  // Кнопки дій — sticky на дні тіла шита, тобто вміст ПРОЇЖДЖАЄ ПІД ними. Коли
  // клавіатура стискає шит, поле у фокусі опиняється саме там: користувач
  // друкує «під кнопками». scrollIntoView це не рятує — для нього поле в межах
  // контейнера вже «видиме». Тому дотягуємо тіло рівно на перекриття.
  function clearStickyActions(el: HTMLElement) {
    const body = el.closest('.modal-body')
    const actions = body?.querySelector('.modal-actions')
    if (!body || !actions) return
    const overlap = el.getBoundingClientRect().bottom - actions.getBoundingClientRect().top + 8
    if (overlap > 0) body.scrollTop += overlap
  }

  function onFieldFocus(e: React.FocusEvent<HTMLElement>) {
    scrollFocusedIntoView(e)
    const el = e.target as HTMLElement
    if (el.tagName !== 'INPUT' && el.tagName !== 'TEXTAREA') return
    clearTimeout(kbDropRef.current)
    clearTimeout(kbProbeRef.current)
    clearTimeout(kbConfirmRef.current)
    // Тільки для тач-пристроїв: на десктопі клавіатура фізична, ліфт лишив би
    // порожню діру під шитом.
    const touch = navigator.maxTouchPoints > 0 || window.matchMedia('(pointer: coarse)').matches
    if (!touch) { clearStickyActions(el); return }
    kbProbeRef.current = setTimeout(() => {
      // У режимі стиснення webview лейаут уже без клавіатури — власний ліфт
      // відняв би її вдруге і затиснув шит (див. layoutShrunkByKeyboard).
      const stillNoKeyboard = !layoutCompressed() && reportedKeyboardPx() < KB_TRUSTED_PX
      if (!stillNoKeyboard) { clearStickyActions(el); return }
      // Підтверджуємо ще раз замість вмикати фолбек одразу (див. KB_CONFIRM_MS).
      kbConfirmRef.current = setTimeout(() => {
        const lift = !layoutCompressed() && reportedKeyboardPx() < KB_TRUSTED_PX
        if (lift) setKbFallback(true)
        // Ліфт змінює геометрію і їде transition-ом (.25s) — міряємо ПІСЛЯ нього,
        // інакше скоригуємо на застарілих координатах.
        clearTimeout(kbFixRef.current)
        kbFixRef.current = setTimeout(() => clearStickyActions(el), lift ? 320 : 0)
      }, KB_CONFIRM_MS)
    }, KB_PROBE_MS)
  }

  function onFieldBlur() {
    clearTimeout(kbProbeRef.current)
    clearTimeout(kbConfirmRef.current)
    clearTimeout(kbFixRef.current)
    // Перехід між сусідніми полями — це blur+focus; пауза не дає шиту стрибати.
    clearTimeout(kbDropRef.current)
    kbDropRef.current = setTimeout(() => setKbFallback(false), 180)
  }

  // Якщо фолбек усе-таки увімкнувся хибно (KB_CONFIRM_MS не врятував — платформа
  // ще довше мовчала) і РЕАЛЬНА висота клавіатури приходить вже ПІСЛЯ цього, шит
  // без цього ефекту лишався б на фейкових 320px аж до блура поля, хоч платформа
  // вже знає точний розмір. Знімаємо локальний ліфт — CSS-змінна одразу впаде до
  // справжнього глобального `--keyboard-h`.
  useEffect(() => {
    if (!kbFallback) return
    const onViewportResize = () => {
      if (layoutCompressed() || reportedKeyboardPx() >= KB_TRUSTED_PX) {
        // Ліфт був ХИБНИЙ — знімаємо його без анімації, інакше вийде видимий
        // стрибок угору й сповзання назад (див. `.kb-snap` у globals.css).
        setKbSnap(true)
        setKbFallback(false)
      }
    }
    // window.resize — теж обовʼязково: коли Telegram СТИСКАЄ webview, змінюється
    // саме воно, і клієнт, що не оновлює visualViewport, інакше лишив би
    // хибний ліфт висіти до блура поля.
    window.visualViewport?.addEventListener('resize', onViewportResize)
    window.addEventListener('resize', onViewportResize)
    return () => {
      window.visualViewport?.removeEventListener('resize', onViewportResize)
      window.removeEventListener('resize', onViewportResize)
    }
  }, [kbFallback])

  // Знятий transition живе рівно один закомічений кадр: два rAF — щоб браузер
  // устиг НАМАЛЮВАТИ нульовий падінг без анімації, і лише тоді повертаємо
  // transition для наступних, уже легітимних змін висоти клавіатури.
  useEffect(() => {
    if (!kbSnap) return
    let inner = 0
    const outer = requestAnimationFrame(() => {
      inner = requestAnimationFrame(() => setKbSnap(false))
    })
    return () => { cancelAnimationFrame(outer); cancelAnimationFrame(inner) }
  }, [kbSnap])

  useEffect(() => () => {
    clearTimeout(kbProbeRef.current)
    clearTimeout(kbConfirmRef.current)
    clearTimeout(kbDropRef.current)
    clearTimeout(kbFixRef.current)
  }, [])

  const requestClose = () => {
    if (firedRef.current) return
    // Поки летить дія — не закриваємось. Гард мусить стояти САМЕ ТУТ, до старту
    // анімації, а не в `onClose` викликача.
    //
    // Три екрани (TeamScreen, ManageGuestsScreen, PaymentCalendarScreen) робили
    // `onClose={() => !creating && setShow(false)}` — і це було ГІРШЕ за
    // відсутність гарда. Закриття двофазне: `requestClose` вішає клас `closing`,
    // CSS зʼїжджає шит за екран і ставить оверлею `pointer-events:none`, і лише
    // потім `finishClose` виставляє `firedRef=true` і кличе `onClose`. Якщо той
    // відмовляється закривати, шит лишається змонтованим, але невидимим і
    // мертвим, а `firedRef` назавжди блокує будь-яке наступне закриття —
    // модалку неможливо ні закрити, ні відкрити знову до перемонтування екрана.
    // Досягалось звичайним тапом по бекдропу, поки на LTE летів запит.
    //
    // `busy` завжди скидається у `finally` (див. обробник дії нижче), тож
    // зависнути тут не можна.
    if (busyRef.current) return
    setClosing(true)
  }
  const finishClose = () => {
    if (firedRef.current) return
    firedRef.current = true
    onClose()
  }

  // ── Swipe-down-to-dismiss (from the header/grabber only, so it never fights
  // the scrollable body). Follows the finger, dims the backdrop, and on release
  // either flings the sheet away or snaps it back. ──────────────────────────────
  const DRAG_CLOSE_PX = 96
  // Швидкий флік закриває раніше за поріг відстані: на короткому шиті 96px — це
  // майже вся його висота, тож рішучий рух пальцем угору-вниз читався як «нічого
  // не сталось». Пороги — з жестів iOS: 0.5px/мс приблизно відповідає рухові, що
  // на 60fps проходить ~30px за кадр.
  const FLING_VELOCITY = 0.5
  const FLING_MIN_PX = 24
  // Мінімальний інтервал між замірами швидкості. Ділити на dt=1мс не можна: один
  // випадковий кадр, що прийшов упритул до попереднього, дає 25px/1мс = 50px/мс і
  // ПОВІЛЬНИЙ жест закривається як флік. Кадр швидше за 8мс — це вже понад 120Гц,
  // тобто шум замірів, а не рух пальця.
  const V_MIN_DT_MS = 8
  const drag = useRef({ startY: 0, dy: 0, active: false, lastY: 0, lastT: 0, v: 0 })
  // Таймери прибирання інлайнових стилів: без них `transition`, виставлений на
  // час snap-back, лишається на елементі, коли `transitionend` не приходить
  // взагалі — а він НЕ приходить у найчастішому випадку, тап по хедеру без руху
  // (transform уже '' → нічого не переходить). Далі цей мертвий transition
  // перебивав анімацію закриття.
  const dragCleanupRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => () => clearTimeout(dragCleanupRef.current), [])

  function onDragStart(e: React.TouchEvent) {
    // `closing` — обовʼязково: під час .24s виходу шит ще в DOM і його можна було
    // схопити, отримавши шит, що їде за екран і слухається пальця одночасно.
    if (firedRef.current || busyRef.current || closing) return
    const y = e.touches[0].clientY
    drag.current = { startY: y, dy: 0, active: true, lastY: y, lastT: Date.now(), v: 0 }
    const el = modalRef.current
    if (el) el.style.transition = 'none'
  }
  function onDragMove(e: React.TouchEvent) {
    if (!drag.current.active) return
    const y = e.touches[0].clientY
    const dy = y - drag.current.startY
    const now = Date.now()
    const dt = now - drag.current.lastT
    if (dt >= V_MIN_DT_MS) {
      drag.current.v = (y - drag.current.lastY) / dt
      drag.current.lastY = y
      drag.current.lastT = now
    }
    if (dy <= 0) { // dragged back up — reset
      drag.current.dy = 0
      const el = modalRef.current
      if (el) el.style.transform = ''
      return
    }
    drag.current.dy = dy
    const el = modalRef.current
    if (el) el.style.transform = `translateY(${dy}px)`
    const ov = overlayRef.current
    if (ov) ov.style.opacity = String(Math.max(0.35, 1 - dy / 480))
  }
  function onDragEnd() {
    if (!drag.current.active) return
    const { dy, v } = drag.current
    drag.current.active = false
    const el = modalRef.current
    const ov = overlayRef.current
    clearTimeout(dragCleanupRef.current)
    if (dy > DRAG_CLOSE_PX || (v > FLING_VELOCITY && dy > FLING_MIN_PX)) {
      // Fling away — continue from the current offset to fully off-screen.
      if (el) {
        el.style.transition = 'transform .2s cubic-bezier(.4,0,1,1)'
        el.style.transform = 'translateY(100%)'
        el.addEventListener('transitionend', (ev) => { if ((ev as TransitionEvent).propertyName === 'transform') finishClose() }, { once: true })
      }
      if (ov) { ov.style.transition = 'opacity .2s ease'; ov.style.opacity = '0' }
      setTimeout(finishClose, 260) // fallback if transitionend is missed
    } else {
      // Snap back to rest.
      if (el) {
        el.style.transition = 'transform .24s var(--ease-out)'
        el.style.transform = ''
        el.addEventListener('transitionend', () => { el.style.transition = '' }, { once: true })
      }
      if (ov) { ov.style.transition = 'opacity .24s ease'; ov.style.opacity = '' }
      // Безумовне прибирання — див. коментар до dragCleanupRef.
      dragCleanupRef.current = setTimeout(() => {
        if (el) el.style.transition = ''
        if (ov) ov.style.transition = ''
      }, 300)
    }
  }

  useEffect(() => {
    const id = idRef.current!
    modalStack.push(id)
    return () => {
      const i = modalStack.indexOf(id)
      if (i !== -1) modalStack.splice(i, 1)
    }
  }, [])

  // Desktop Telegram / web: Escape mirrors the backdrop tap — topmost only.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && modalStack[modalStack.length - 1] === idRef.current) requestClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Lock background scroll while open (nesting-safe: each restores the prior value).
  useEffect(() => {
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = prev }
  }, [])

  // Return focus to whatever opened the dialog when it closes (APG dialog).
  // Captured before the initial-focus effect below steals it.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    return () => { opener?.focus?.() }
  }, [])

  // Move focus into the dialog for a11y — unless an inner input already grabbed
  // it (e.g. an autoFocus rename field), which we must not steal.
  //
  // Залежність від `mounted` ОБОВʼЯЗКОВА, і це не мікрооптимізація: до неї ефект
  // мав `[]`, тобто біг на першому коміті — коли `mounted` ще false і компонент
  // повернув `null` (портал існує лише в браузері, див. гейт нижче). `modalRef`
  // у той момент порожній, ефект більше не повторювався, і фокус НЕ переходив у
  // діалог ніколи: він лишався на кнопці-опенері, тож читалка озвучувала екран
  // ПІД шитом. Спіймано `modal-a11y.spec.ts` — жоден із 202 тестів до нього Tab
  // не натискав і `activeElement` не читав.
  useEffect(() => {
    if (!mounted) return
    const el = modalRef.current
    if (el && !el.contains(document.activeElement)) el.focus()
  }, [mounted])

  // Focus trap: keep Tab / Shift+Tab cycling inside the topmost dialog so focus
  // never lands on the background behind the backdrop (aria-modal hides it from
  // AT, but doesn't stop keyboard Tab on its own).
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      if (modalStack[modalStack.length - 1] !== idRef.current) return
      const el = modalRef.current
      if (!el) return
      const nodes = el.querySelectorAll<HTMLElement>(
        'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])',
      )
      if (nodes.length === 0) { e.preventDefault(); el.focus(); return }
      const first = nodes[0]
      const last = nodes[nodes.length - 1]
      const active = document.activeElement
      if (e.shiftKey) {
        if (active === first || active === el || !el.contains(active)) { e.preventDefault(); last.focus() }
      } else if (active === last || !el.contains(active)) {
        e.preventDefault(); first.focus()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  // Safety net: if the exit animation never fires (reduced-motion edge cases,
  // interrupted paint), still unmount shortly after a close was requested.
  useEffect(() => {
    if (!closing) return
    const t = setTimeout(finishClose, 320)
    return () => clearTimeout(t)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [closing])

  if (!mounted) return null

  // Portal to <body>: .modal uses backdrop-filter, which makes it a containing
  // block for position:fixed descendants — a nested confirm rendered in-tree was
  // clipped to the parent sheet (floated mid-screen, backdrop covered only it).
  return createPortal(
    <div
      ref={overlayRef}
      className={`modal-overlay${closing ? ' closing' : ''}${kbSnap ? ' kb-snap' : ''}`}
      style={kbFallback ? ({ '--keyboard-h': `${KB_FALLBACK_PX}px` } as React.CSSProperties) : undefined}
      onClick={(e) => { if (e.target === e.currentTarget) requestClose() }}
    >
      <div
        ref={modalRef}
        className={`modal${closing ? ' closing' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={subtitle ? descId : undefined}
        tabIndex={-1}
        onAnimationEnd={(e) => { if (closing && e.target === modalRef.current) finishClose() }}
      >
        {/* Fixed header — never scrolls; also the swipe-to-dismiss grab area */}
        <div
          className="modal-head"
          onTouchStart={onDragStart}
          onTouchMove={onDragMove}
          onTouchEnd={onDragEnd}
          onTouchCancel={onDragEnd}
        >
          <div className="modal-h" id={titleId}>{title}</div>
          {subtitle && <div className="modal-s" id={descId}>{subtitle}</div>}
        </div>

        {/* Scrollable body — inputs scroll freely; action buttons are sticky at the bottom
            so they never overlap inputs when the keyboard is open */}
        {(children || actions) && (
          <div
            className="modal-body"
            onFocusCapture={onFieldFocus}
            onBlurCapture={onFieldBlur}
          >
            {children}
            {actions && (
              <div className={`modal-actions ${actions.length === 2 ? 'two' : ''}`}>
                {actions.map((a) => (
                  <button
                    key={a.label}
                    className={modalBtnClass(a.variant)}
                    onClick={async () => {
                      if (busyRef.current) return
                      busyRef.current = true
                      setBusy(true)
                      try { await a.onClick() } finally { busyRef.current = false; setBusy(false) }
                    }}
                    disabled={a.disabled || busy}
                  >
                    {a.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>,
    document.body,
  )
}
