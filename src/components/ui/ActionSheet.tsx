'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

/**
 * Легкий шит для дій БЕЗ жодного текстового поля: підтвердження, меню, QR/лінк,
 * вибір зі списку. Замінює `Modal.tsx` для сайтів, які НІКОЛИ не показують
 * клавіатуру — і саме тому не несе жодного рядка клавіатурної евристики.
 *
 * Modal.tsx зрісся з фіксом кожної платформної примхи клавіатури (проба →
 * підтвердження → фолбек → самоскасування, подвійний сигнал стиснення лейауту,
 * зняття блюру під час руху клавіатури) — 200+ рядків із 570, і кожен наступний
 * фікс ризикував розламати попередній (рівно це й сталось із анімацією
 * закриття в PR #110). Взаємодії БЕЗ поля вводу цей клас багів фізично не
 * можуть отримати, тож тут його просто немає — не «вимкнено», а не написано.
 *
 * Форми (навіть однопільні) сюди НЕ йдуть — вони повноекранні екрани
 * (`PropertyFormScreen`, `CreateDatabaseScreen` — наявний, дворічний, ніким не
 * патчений патерн: `Header` + скрольне тіло + `mbtn-flow`, клавіатура через
 * глобальний `--keyboard-h`, без жодної власної евристики).
 */

// Той самий стек, що був у Modal.tsx: Escape/фокус-пастка діють лише на
// верхньому шиті — вкладене підтвердження всередині цього ж шару не має
// зносити те, що під ним.
const sheetStack: symbol[] = []

const BTN_GLASS: Record<string, string> = {
  primary: 'btn-glass info',
  danger: 'btn-glass err',
}

/** Той самий хелпер, що був у Modal.tsx — заливку кнопки поза `actions` дає він. */
export function modalBtnClass(variant: 'primary' | 'danger' | 'secondary'): string {
  return `modal-btn ${variant} ${BTN_GLASS[variant] ?? ''}`.trim()
}

interface ActionSheetProps {
  /** Керує видимістю. НЕ гейтуй виклик компонента `{open && <ActionSheet…>}` —
   *  саме так робив кожен викликач Modal.tsx, і саме тому анімація закриття
   *  була неможлива без клону DOM: розмонтування випереджало вихідну анімацію.
   *  Рендерити компонент завжди, `open` вирішує решту. */
  open: boolean
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

export default function ActionSheet({ open, title, subtitle, onClose, children, actions }: ActionSheetProps) {
  const idRef = useRef<symbol | null>(null)
  if (idRef.current === null) idRef.current = Symbol('sheet')
  const titleId = useId()
  const descId = useId()
  const modalRef = useRef<HTMLDivElement>(null)
  const overlayRef = useRef<HTMLDivElement>(null)

  // Портал існує лише в браузері (статичний експорт пререндерить на Node).
  const [mounted, setMounted] = useState(false)
  useEffect(() => { setMounted(true) }, [])

  // `rendered` — чи є щось у DOM УЗАГАЛІ (true, поки `open`, і ще трохи довше,
  // поки дограє вихідна анімація); `closing` — чи саме зараз ця анімація йде.
  // Розділені навмисно: `rendered` керує монтуванням, `closing` — лише класом.
  const [rendered, setRendered] = useState(open)
  const [closing, setClosing] = useState(false)
  // Дзеркало `closing`: на швидкому переоткритті (перше підтвердження щойно
  // відповіли, ДРУГЕ вже летить) `animationend` попереднього, перерваного
  // виїзду інколи доїжджає до обробника ПІСЛЯ того, як React уже закомітив
  // реоткриття — race у порядку доставки нативної події проти рендеру, не
  // помилка React. Замкнута в closure `closing` тоді читається ЗАСТАРІЛОЮ
  // (`true`), і гілка `if (closing)` розмонтовує щойно відкритий шит
  // (`setRendered(false)`) відразу після появи. Той самий клас, що вже
  // лікували ref'ами для `busy`/`onClose` — обробник нативної події теж не
  // може покладатись на замкнення рендера.
  // Дзеркало `open`, актуальне на момент, коли РЕАЛЬНО спрацьовує подія:
  // на швидкому переоткритті (перше підтвердження щойно відповіли, ДРУГЕ вже
  // летить) природний `animationend` перерваного виїзду ІНОДІ встигає
  // спрацювати вже ПІСЛЯ того, як React синхронно обробив реоткриття —
  // `animationName` у нього коректний ('modalSlideDown'), тож фільтр за
  // назвою анімації тут безсилий: подія не «підроблена», вона просто про
  // цикл, який реоткриття вже скасувало. `open` — єдине джерело правди про
  // те, чи шит МАЄ БУТИ відкритий ЗАРАЗ, і `openRef` оновлюється синхронно
  // під час рендеру (до commit), тож завжди випереджає нативну подію, чия
  // доставка йде через чергу задач браузера.
  const openRef = useRef(open)
  openRef.current = open
  const wasOpenRef = useRef(open)
  useEffect(() => {
    if (open) {
      setRendered(true)
      setClosing(false)
      // Компонент тепер живе довше за один цикл відкриття/закриття (на
      // відміну від Modal.tsx, який монтувався заново щоразу) — `useState(open)`
      // нижче ловить лише ПЕРШИЙ показ. Без цього повторне відкриття вже
      // змонтованого шита лишало б `moving=false`, і блюр не знімався б на
      // час виїзду вдруге.
      setMoving(true)
    } else if (wasOpenRef.current) {
      setClosing(true)
    }
    wasOpenRef.current = open
  }, [open])

  // Re-entry guard: небезпечна дія зазвичай асинхронна, і шит лишається
  // видимим, поки вона летить — швидкий подвійний тап інакше стріляв би нею
  // двічі (напр. подвійний DELETE).
  const [busy, setBusy] = useState(false)
  // Синхронне дзеркало `busy`: ефект Escape має `[]`-залежності й захопив би
  // застарілий `false` з першого рендера — Escape тоді обходив би гард
  // закриття. Ref читається завжди свіжим.
  const busyRef = useRef(false)
  // Те саме про `onClose`: Escape/Tab-пастка теж читають `requestClose` із
  // ефектів на `[]`, тож застаріла версія викликала б застарілий `onClose`
  // першого рендера, якщо викликач передає новий інлайновий колбек щоразу.
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  /** Єдина точка, звідки шит МОЖЕ попросити себе закрити (бекдроп/Escape/свайп).
   *  Кнопки в `actions`/тілі викликають СВІЙ власний `onClick` — часто це той
   *  самий `onClose`, і це нормально: власник даних керує своїм станом сам. */
  const requestClose = () => {
    if (busyRef.current) return
    onCloseRef.current()
  }

  /**
   * Шит ЗАРАЗ їде (відкривається або закривається) → блюр на час руху знято.
   * Той самий вимір, що в Modal.tsx: перші ~60% шляху шит долає за ОДИН кадр
   * (замір з реального iPhone), бо відкриття створює два нові backdrop-шари
   * поверх екрана, де вже десятки скляних карток, і композитор не встигає.
   * У Chromium ефекту не видно (`_blur-cost`: p50 16.7мс з блюром і без) —
   * WebKit композитить скло інакше, доказ лежить у записі з пристрою.
   */
  const [moving, setMoving] = useState(open)

  // ── Свайп-закриття (тільки з хедера — не конфліктує зі скролом тіла) ───────
  const DRAG_CLOSE_PX = 96
  const FLING_VELOCITY = 0.5
  const FLING_MIN_PX = 24
  // Мінімальний інтервал між замірами швидкості: кадр швидше за 8мс — це вже
  // понад 120Гц, тобто шум, а не рух пальця (ділити на dt≈1мс дало б хибний
  // флік із повільного руху).
  const V_MIN_DT_MS = 8
  const drag = useRef({ startY: 0, dy: 0, active: false, lastY: 0, lastT: 0, v: 0 })
  const dragCleanupRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => () => clearTimeout(dragCleanupRef.current), [])

  function onDragStart(e: React.TouchEvent) {
    if (busyRef.current || closing) return
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
    if (dy <= 0) {
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
    if (busyRef.current) {
      // Летить дія — повертаємо на місце, як і звичайний недостатній свайп.
    }
    if (!busyRef.current && (dy > DRAG_CLOSE_PX || (v > FLING_VELOCITY && dy > FLING_MIN_PX))) {
      if (el) {
        el.style.transition = 'transform .2s cubic-bezier(.4,0,1,1)'
        el.style.transform = 'translateY(100%)'
      }
      if (ov) { ov.style.transition = 'opacity .2s ease'; ov.style.opacity = '0' }
      onClose()
      return
    }
    // Snap back to rest.
    if (el) {
      el.style.transition = 'transform .24s var(--ease-out)'
      el.style.transform = ''
      el.addEventListener('transitionend', () => { el.style.transition = '' }, { once: true })
    }
    if (ov) { ov.style.transition = 'opacity .24s ease'; ov.style.opacity = '' }
    // Безумовне прибирання: тап по хедеру без руху ніколи не шле `transitionend`
    // (transform не міняється), і без цього мертвий inline `transition` лишався б
    // назавжди, перебиваючи анімацію закриття.
    dragCleanupRef.current = setTimeout(() => {
      if (el) el.style.transition = ''
      if (ov) ov.style.transition = ''
    }, 300)
  }

  // Стек — лише поки `open`; топ стека природно кодує «чи я найверхніший».
  useEffect(() => {
    if (!open) return
    const id = idRef.current!
    sheetStack.push(id)
    return () => {
      const i = sheetStack.indexOf(id)
      if (i !== -1) sheetStack.splice(i, 1)
    }
  }, [open])

  // Desktop Telegram / web: Escape дзеркалить бекдроп-тап — лише верхній шит.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && sheetStack[sheetStack.length - 1] === idRef.current) requestClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Блокування скролу фону — лише поки відкрито, з відновленням попереднього
  // значення (вкладено-безпечно: два шити одночасно не заплутають один одного).
  useEffect(() => {
    if (!open) return
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = prev }
  }, [open])

  // Повернення фокуса на кнопку, що відкрила шит (APG dialog) — знімається
  // ЩОРАЗУ, коли `open` стає true, а не один раз при монтуванні: компонент
  // тепер живе довше за один цикл відкриття/закриття.
  useEffect(() => {
    if (!open) return
    const opener = document.activeElement as HTMLElement | null
    return () => { opener?.focus?.() }
  }, [open])

  // Фокус — усередину шита. Залежність від `mounted` ОБОВʼЯЗКОВА: до порталу
  // (Node-пререндер) `modalRef` порожній, і без цього фокус не заходив би в
  // діалог НІКОЛИ на першому в житті сторінки відкритті.
  useEffect(() => {
    if (!mounted || !open) return
    const el = modalRef.current
    if (el && !el.contains(document.activeElement)) el.focus()
  }, [mounted, open])

  // Фокус-пастка: Tab/Shift+Tab не виходять за межі верхнього шита.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      if (sheetStack[sheetStack.length - 1] !== idRef.current) return
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

  // Страховка: якщо `animationend` не прийде (reduced-motion, вкладка
  // сховалась посеред виходу), усе одно прибрати шит невдовзі.
  // `openRef`-гард той самий, що в `onAnimationEnd`, і з тієї ж причини:
  // цей таймер планується в момент, коли `closing` стає true, але до його
  // спрацювання шит може встигнути ПЕРЕВІДКРИТИСЬ (`open`→false→true) — а
  // `[closing]`-ефект технічно МАЄ скасувати таймер через cleanup, та це не
  // єдиний захист і не варто покладатись на нього самотужки.
  useEffect(() => {
    if (!closing) return
    const t = setTimeout(() => {
      if (openRef.current) return
      setClosing(false); setRendered(false)
    }, 320)
    return () => clearTimeout(t)
  }, [closing])

  if (!mounted || !rendered) return null

  // Портал у <body>: `.modal` сам є containing block для position:fixed
  // (через backdrop-filter) — вкладене підтвердження в дереві обрізалось б
  // рамкою батьківського шита.
  return createPortal(
    <div
      ref={overlayRef}
      className={`modal-overlay${closing ? ' closing' : ''}${moving ? ' moving' : ''}`}
      onClick={(e) => { if (e.target === e.currentTarget) requestClose() }}
    >
      <div
        ref={modalRef}
        className={`modal${closing ? ' closing' : ''}${moving ? ' moving' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={subtitle ? descId : undefined}
        tabIndex={-1}
        onAnimationEnd={(e) => {
          if (e.target !== modalRef.current) return
          // `open` (через `openRef`), а НЕ `closing`, вирішує, чи ця подія ще
          // чинна: реоткриття скасовує намір закритись раніше, ніж природний
          // `animationend` перерваного виїзду встигає прийти, тож застарілий
          // "кінець виїзду" (з ЦІЛКОМ коректним `animationName`) інакше
          // розмонтував би щойно відкритий шит.
          if (openRef.current) {
            if (e.animationName === 'modalSlideUp') setMoving(false)
            return
          }
          if (e.animationName !== 'modalSlideDown') return
          setClosing(false); setRendered(false)
        }}
      >
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

        {(children || actions) && (
          <div className="modal-body">
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
