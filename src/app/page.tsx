'use client'

import { useEffect } from 'react'
import dynamic from 'next/dynamic'
import { useAppStore } from '@/store/appStore'
import { hapticNotify, layoutShrunkByKeyboard, telegramSafeArea } from '@/lib/telegram'
import { useAuth } from '@/hooks/useAuth'
import { useDeepLink } from '@/hooks/useDeepLink'
import { useNotifications } from '@/hooks/useNotifications'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { IconWifiOff } from '@/components/Icons'
import SplashScreen from '@/screens/SplashScreen'

/** Мусить дорівнювати --bg у globals.css (нативний хром Telegram — не CSS). */
const TG_CHROME_BG = '#040408'

const screenFallback = (
  <div className="scr bg-purple" style={{ alignItems: 'center', justifyContent: 'center' }}>
    <div className="loader" />
  </div>
)

const WelcomeScreen = dynamic(() => import('@/screens/WelcomeScreen'), { loading: () => screenFallback })
const RoleSelectScreen = dynamic(() => import('@/screens/RoleSelectScreen'), { loading: () => screenFallback })
const ProfileSetupScreen = dynamic(() => import('@/screens/ProfileSetupScreen'), { loading: () => screenFallback })
const EmptyStateScreen = dynamic(() => import('@/screens/EmptyStateScreen'), { loading: () => screenFallback })
const DatabaseListScreen = dynamic(() => import('@/screens/DatabaseListScreen'), { loading: () => screenFallback })
const CreateDatabaseScreen = dynamic(() => import('@/screens/CreateDatabaseScreen'), { loading: () => screenFallback })
const DatabaseObjectsScreen = dynamic(() => import('@/screens/DatabaseObjectsScreen'), { loading: () => screenFallback })
const PropertyFormScreen = dynamic(() => import('@/screens/PropertyFormScreen'), { loading: () => screenFallback })
const PropertyDetailScreen = dynamic(() => import('@/screens/PropertyDetailScreen'), { loading: () => screenFallback })
const SharingAnalyticsScreen = dynamic(() => import('@/screens/SharingAnalyticsScreen'), { loading: () => screenFallback })
const ExportScreen = dynamic(() => import('@/screens/ExportScreen'), { loading: () => screenFallback })
const RealtorDashboardScreen = dynamic(() => import('@/screens/RealtorDashboardScreen'), { loading: () => screenFallback })
const RealtorDatabaseScreen = dynamic(() => import('@/screens/RealtorDatabaseScreen'), { loading: () => screenFallback })
const CollectionsScreen = dynamic(() => import('@/screens/CollectionsScreen'), { loading: () => screenFallback })
const ProfileScreen = dynamic(() => import('@/screens/ProfileScreen'), { loading: () => screenFallback })
const NotificationsScreen = dynamic(() => import('@/screens/NotificationsScreen'), { loading: () => screenFallback })
const ErrorScreen = dynamic(() => import('@/screens/ErrorScreen'), { loading: () => screenFallback })
const SuccessScreen = dynamic(() => import('@/screens/SuccessScreen'), { loading: () => screenFallback })
const PhotoUploadScreen = dynamic(() => import('@/screens/PhotoUploadScreen'), { loading: () => screenFallback })
const PhotoGalleryScreen = dynamic(() => import('@/screens/PhotoGalleryScreen'), { loading: () => screenFallback })
const QRScannerScreen = dynamic(() => import('@/screens/QRScannerScreen'), { loading: () => screenFallback })
const GuestDatabaseScreen = dynamic(() => import('@/screens/GuestDatabaseScreen'), { loading: () => screenFallback })
const GuestHomeScreen = dynamic(() => import('@/screens/GuestHomeScreen'), { loading: () => screenFallback })
const ManageGuestsScreen = dynamic(() => import('@/screens/ManageGuestsScreen'), { loading: () => screenFallback })
const TeamScreen = dynamic(() => import('@/screens/TeamScreen'), { loading: () => screenFallback })
const SharedCollectionScreen = dynamic(() => import('@/screens/SharedCollectionScreen'), { loading: () => screenFallback })
const PaymentCalendarScreen = dynamic(() => import('@/screens/PaymentCalendarScreen'), { loading: () => screenFallback })
const PaymentScheduleScreen = dynamic(() => import('@/screens/PaymentScheduleScreen'), { loading: () => screenFallback })
const PaymentConfirmScreen = dynamic(() => import('@/screens/PaymentConfirmScreen'), { loading: () => screenFallback })
const CreateInviteScreen = dynamic(() => import('@/screens/CreateInviteScreen'), { loading: () => screenFallback })
const FolderManageScreen = dynamic(() => import('@/screens/FolderManageScreen'), { loading: () => screenFallback })
const DbPickerScreen = dynamic(() => import('@/screens/DbPickerScreen'), { loading: () => screenFallback })
const FolderPickerScreen = dynamic(() => import('@/screens/FolderPickerScreen'), { loading: () => screenFallback })
const RentPropertyScreen = dynamic(() => import('@/screens/RentPropertyScreen'), { loading: () => screenFallback })
const DeleteAccountScreen = dynamic(() => import('@/screens/DeleteAccountScreen'), { loading: () => screenFallback })

export default function Page() {
  const screen = useAppStore((s) => s.screen)
  const navKey = useAppStore((s) => s.navKey)
  const navDirection = useAppStore((s) => s.navDirection)
  const historyLength = useAppStore((s) => s.history.length)
  const back = useAppStore((s) => s.back)
  const isOnline = useAppStore((s) => s.isOnline)
  const setOnline = useAppStore((s) => s.setOnline)
  const showToast = useAppStore((s) => s.showToast)
  const userId = useAppStore((s) => s.user?.id)
  const { setupAuthListener } = useAuth()
  const { loadNotifications } = useNotifications()
  useDeepLink()

  // TG SDK setup — runs once on mount
  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    tg.ready()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tgAny = tg as any
    try {
      // Telegram API приймає лише hex — var(--bg) тут не працює, тож тримаємо
      // одну константу поряд із токеном (значення мусять збігатись).
      tgAny.setHeaderColor?.(TG_CHROME_BG)
      tgAny.setBackgroundColor?.(TG_CHROME_BG)
      tgAny.disableVerticalSwipes?.()
    } catch { /* older TMA versions may not support these APIs */ }
    // Застосунок ТЕМНИЙ незалежно від теми Telegram (світла давала білі смуги
    // під нативним хромом). Атрибут лишається як діагностичний слід — «яку тему
    // повідомив клієнт»; жоден CSS його НЕ читає і не має читати: скоупнутий
    // світлий блок уже колись перефарбовував текст у чорний.
    if (tg.colorScheme) {
      document.documentElement.dataset.tgTheme = tg.colorScheme
    }

    // Врізи від Telegram: у його iOS-webview env(safe-area-inset-*) не
    // наповнюється, тож весь наш хром (таббар, CTA, панель обраних) сідав би під
    // home-індикатор. CSS бере max(env, --tg-safe-*), тобто це підсилення, а не
    // заміна: де env працює, нічого не змінюється.
    function applySafeArea() {
      const { top, bottom } = telegramSafeArea()
      const root = document.documentElement.style
      root.setProperty('--tg-safe-top', `${top}px`)
      root.setProperty('--tg-safe-bottom', `${bottom}px`)
    }
    applySafeArea()
    tgAny.onEvent?.('safeAreaChanged', applySafeArea)
    tgAny.onEvent?.('contentSafeAreaChanged', applySafeArea)
    // Fullscreen міняє саме contentSafeArea — старі клієнти події не надсилають,
    // тож перечитуємо ще й на зміні вʼюпорта.
    tgAny.onEvent?.('fullscreenChanged', applySafeArea)

    // Keyboard height comes from two independent signals and we take the max:
    // - Telegram viewportChanged (works on Android where the webview resizes)
    // - visualViewport (works on iOS where the keyboard overlays the webview and
    //   Telegram's stable/current heights move together, reading as 0)
    let tgKbH = 0
    let vvKbH = 0
    // Стан передбачливого підйому (див. блок «ПІДЙОМ НА ФОКУС» нижче). Оголошено
    // ТУТ, поряд з рештою стану клавіатури: `applyKeyboardFromVV` читає ці
    // змінні, тож нижче за нього вони лишались би в TDZ для раннього виклику.
    const KB_CACHE_KEY = 'kb_h_v1'
    let predicted = 0
    let confirmTimer = 0
    let blurTimer = 0
    function applyKeyboardHeight() {
      document.documentElement.style.setProperty('--keyboard-h', `${Math.max(tgKbH, vvKbH)}px`)
    }
    function applyViewportHeight() {
      const stable = tgAny.viewportStableHeight ?? tgAny.viewportHeight ?? 0
      const current = tgAny.viewportHeight ?? stable
      const reported = Math.max(0, Math.round(stable - current))
      // Клавіатура «зʼїдає» екран двома різними способами, і плутати їх не можна:
      //  • ПЕРЕКРИВАЄ (iOS): лейаут лишається на всю висоту, і відступ знизу
      //    мусимо додати ми;
      //  • СТИСКАЄ webview (Android, новий Telegram iOS): лейаут УЖЕ без
      //    клавіатури — додатковий відступ віднімає її вдруге. Саме так модалку
      //    затискало до ~180px, її тіло починало прокручуватись, і sticky-кнопки
      //    накривали поле, у яке користувач друкував.
      const innerH = window.innerHeight || stable
      const layoutShrunk = layoutShrunkByKeyboard()
      // Висота, доступна лейауту ЗАРАЗ: у режимі стиснення це вже урізана.
      //
      // Поки клавіатури НЕМА, авторитет — `viewportStableHeight`, а не
      // `innerHeight`. Telegram надсилає viewportChanged ще до того, як webview
      // домалює повернення висоти, тож `innerHeight` у цю мить лишається
      // урізаним — і `min()` фіксував ту урізану висоту НАЗАВЖДИ (події більше
      // не буде). Саме так під екраном оселялась чорна смуга після закриття
      // клавіатури у формі обʼєкта.
      const vh = reported > 0 ? Math.min(stable, innerH) : (stable > 0 ? stable : innerH)
      if (vh > 0) document.documentElement.style.setProperty('--tg-vh', `${vh}px`)
      tgKbH = layoutShrunk ? 0 : reported
      applyKeyboardHeight()
    }
    function onActivated() {
      tg!.expand()
      applyViewportHeight()
    }
    function onViewportChanged() {
      applyViewportHeight()
      applySafeArea()
    }
    applyViewportHeight()
    tgAny.onEvent?.('viewportChanged', onViewportChanged)
    tgAny.onEvent?.('activated', onActivated)

    // Keyboard height must react only to the keyboard opening/closing (resize),
    // NOT to scrolling. vv.offsetTop changes on every scroll frame while the
    // keyboard stays put; subtracting it here recomputed a fluctuating height on
    // every scroll event, which made --keyboard-h jitter — bouncing the save
    // button and glitching the caret mid-typing. Drop offsetTop, drop 'scroll'.
    function applyKeyboardFromVV() {
      const vv = window.visualViewport
      if (!vv) return
      vvKbH = Math.max(0, Math.round(window.innerHeight - vv.height))
      // Правда з платформи ПЕРЕТИРАЄ передбачене значення (а не додається до
      // нього) і поповнює кеш для наступних відкриттів. Поріг 100px відсікає
      // дрібні ресайзи, які WebKit шле з інших причин — рядок підказок,
      // автодоповнення: закешувати їх означало б підіймати шит на 40px.
      if (vvKbH > 100) { predicted = 0; clearTimeout(confirmTimer); writeKbCache(vvKbH) }
      applyKeyboardHeight()
      // Висоту оболонки перечитуємо ТУТ ТАКОЖ: resize вʼюпорта приходить уже
      // після того, як лейаут осів, тобто це єдиний сигнал, який виправляє
      // значення, зняте зарано на viewportChanged.
      applyViewportHeight()
    }
    /**
     * ПІДЙОМ НА ФОКУС, ЗВІРКА НА `resize`.
     *
     * Заміряно на записі з iPhone: клавіатура рушає на 3543 мс, а шит — лише на
     * 3691 мс, тобто **лаг 148 мс**, і ще ~220 мс їде. Увесь цей час поле, по
     * якому щойно тапнули, перекрите клавіатурою.
     *
     * Причина не в тривалості переходу, а в ДЖЕРЕЛІ: `visualViewport.resize` на
     * WebKit приходить ОДИН раз — наприкінці анімації клавіатури. Слідкувати за
     * нею покадрово неможливо в принципі: WebKit свідомо не перебудовує лейаут
     * щокадру, а потік подій під час руху дає лише `geometrychange` з
     * VirtualKeyboard API, і той є тільки в Chromium. Telegram власного API для
     * клавіатури не має взагалі (відкриті Telegram-iOS #1296/#1410/#1637).
     *
     * Тому не «стежити», а СТАРТУВАТИ ОДНОЧАСНО: клавіатура iOS їде ~0.25s, наш
     * `transition` теж 0.25s — якщо запустити їх в один момент, рухи збігаються
     * без жодного стеження. Висоту беремо з КЕШУ попереднього відкриття, а
     * `resize` потім лише звіряє.
     *
     * ЧОМУ ЦЕ НЕ ДАЄ ПОДВІЙНОГО ЛІФТА (той дефект уже коштував окремого раунду):
     * кеш наповнюється ЛИШЕ зі `applyKeyboardFromVV`, тобто лише коли
     * `innerHeight − vv.height > 0`. Таке можливе тільки там, де клавіатура
     * НАКРИВАЄ лейаут. Клієнт, що стискає webview (типовий Android), у кеш не
     * потрапляє ніколи — і передбачливий підйом там просто не вмикається.
     */
    // Ключ на геометрію: у ландшафті й на іншому екрані клавіатура інша.
    const kbCacheKey = () => `${window.innerWidth}x${window.innerHeight}`
    function readKbCache(): number {
      try {
        const raw = localStorage.getItem(KB_CACHE_KEY)
        if (!raw) return 0
        return (JSON.parse(raw) as Record<string, number>)[kbCacheKey()] ?? 0
      } catch { return 0 }
    }
    function writeKbCache(px: number) {
      try {
        const raw = localStorage.getItem(KB_CACHE_KEY)
        const map = raw ? (JSON.parse(raw) as Record<string, number>) : {}
        map[kbCacheKey()] = px
        localStorage.setItem(KB_CACHE_KEY, JSON.stringify(map))
      } catch { /* приватний режим — просто без кешу */ }
    }

    /**
     * Поле, яке підіймає САМЕ КЛАВІАТУРУ.
     *
     * `date`/`time` свідомо ВИКЛЮЧЕНІ: вони відкривають барабан, а не
     * клавіатуру, і його висота інша — підйом на кешовану висоту клавіатури
     * був би просто хибним.
     */
    function opensKeyboard(el: Element | null): boolean {
      if (!(el instanceof HTMLElement)) return false
      if (el.isContentEditable) return true
      if (el.tagName === 'TEXTAREA') return true
      if (el.tagName !== 'INPUT') return false
      const t = (el as HTMLInputElement).type
      return !['button', 'submit', 'reset', 'checkbox', 'radio', 'file', 'range',
        'color', 'image', 'date', 'time', 'datetime-local', 'month', 'week'].includes(t)
    }

    function onFocusIn(e: Event) {
      clearTimeout(blurTimer)
      if (!opensKeyboard(e.target as Element | null)) return
      const cached = readKbCache()
      // Кеш порожній (перший фокус на цьому пристрої) або клієнт стискає лейаут
      // — поведінка лишається сьогоднішньою.
      if (cached <= 0 || layoutShrunkByKeyboard()) return
      if (vvKbH > 0) return                      // клавіатура вже відкрита
      predicted = cached
      vvKbH = cached
      applyKeyboardHeight()
      // Не підтвердили — знімаємо. Так буває з апаратною клавіатурою на
      // планшеті: фокус є, OSK немає, і без цього шит завис би піднятим.
      clearTimeout(confirmTimer)
      confirmTimer = window.setTimeout(() => {
        if (predicted <= 0) return
        predicted = 0
        vvKbH = 0
        applyKeyboardHeight()
      }, 600)
    }

    function onFocusOut() {
      clearTimeout(confirmTimer)
      // Через тік: перехід фокуса між двома полями того самого шита дає
      // focusout+focusin поспіль, і клавіатура при цьому НЕ ховається —
      // миттєве обнулення блимнуло б шитом униз і назад.
      clearTimeout(blurTimer)
      blurTimer = window.setTimeout(() => {
        predicted = 0
        vvKbH = 0
        applyKeyboardHeight()
        // Клавіатура могла лишитись (клієнт не сховав її, фокус пішов у
        // нефокусований контрол) — перечитуємо ЖИВИЙ вʼюпорт і вертаємо правду.
        setTimeout(applyKeyboardFromVV, 300)
      }, 0)
    }

    document.addEventListener('focusin', onFocusIn)
    document.addEventListener('focusout', onFocusOut)
    window.visualViewport?.addEventListener('resize', applyKeyboardFromVV)
    // Telegram не надсилає viewportChanged на кожну зміну лейаута (поворот,
    // згортання клавіатури «своїм» шляхом), а `#app-root` живе на --tg-vh —
    // без цього слухача будь-яка пропущена подія лишає порожню смугу.
    window.addEventListener('resize', applyViewportHeight)

    return () => {
      tgAny.offEvent?.('viewportChanged', onViewportChanged)
      tgAny.offEvent?.('activated', onActivated)
      tgAny.offEvent?.('safeAreaChanged', applySafeArea)
      tgAny.offEvent?.('contentSafeAreaChanged', applySafeArea)
      tgAny.offEvent?.('fullscreenChanged', applySafeArea)
      document.removeEventListener('focusin', onFocusIn)
      document.removeEventListener('focusout', onFocusOut)
      clearTimeout(confirmTimer)
      clearTimeout(blurTimer)
      window.visualViewport?.removeEventListener('resize', applyKeyboardFromVV)
      window.removeEventListener('resize', applyViewportHeight)
    }
  }, [])

  // BackButton: register handler once (back is a stable Zustand function)
  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    tg.BackButton.onClick(back)
    return () => tg.BackButton.offClick(back)
  }, [back])

  /**
   * Нижня смуга і фон Telegram беруть колір НИЗУ градієнта поточного екрана.
   *
   * Було `#06050e` на все — і це видно на записі з пристрою: коли клавіатура
   * стискає webview, навколо її панелі (в iOS 26 вона з заокругленими кутами)
   * лишається ЧОРНА рамка. Заміряно по кадру: `#070610` ліворуч і праворуч від
   * клавіатури — тобто рівно наш колір хрому, а не «баг Telegram».
   *
   * Верх (`setHeaderColor`) НЕ чіпаємо: там градієнт справді майже чорний, і
   * саме тому константа колись і зʼявилась. Помилкою було поширити її на НИЗ,
   * де кожен градієнт світлий (`.bg-blue` закінчується на #5480dc).
   *
   * Значення читається з DOM (`--bg-end` живе поряд із самим градієнтом у
   * globals.css), щоб не заводити другу копію палітри в JS. Екрани ліниві, тож
   * на момент першого коміту в дереві ще може стояти fallback — звідси кілька
   * спроб на rAF, а не одна.
   */
  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    let tries = 0
    let raf = 0
    const apply = () => {
      const el = document.querySelector('#app-root .scr[class*="bg-"]') as HTMLElement | null
      const end = el ? getComputedStyle(el).getPropertyValue('--bg-end').trim() : ''
      if (!end) {
        if (++tries < 12) raf = requestAnimationFrame(apply)
        return
      }
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const tgAny = tg as any
        tgAny.setBackgroundColor?.(end)
        tgAny.setBottomBarColor?.(end)
      } catch { /* старий клієнт — лишається типовий колір */ }
    }
    raf = requestAnimationFrame(apply)
    return () => cancelAnimationFrame(raf)
  }, [screen, navKey])

  // BackButton: show/hide independently of handler registration
  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    if (historyLength > 0) tg.BackButton.show()
    else tg.BackButton.hide()
  }, [historyLength])

  // Wire JWT auto-refresh and SIGNED_OUT redirect
  useEffect(() => {
    const subscription = setupAuthListener()
    return () => subscription.unsubscribe()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Лічильник непрочитаних — щоб бейдж у таббарі не лишався нулем до того, як
  // користувач сам відкриє екран сповіщень.
  //
  // Але НЕ на критичному шляху: цей запит спрацьовував одразу на встановлення
  // user, тобто вилітав РАНІШЕ за запит даних екрана і конкурував з ним за
  // зʼєднання. Малює він при цьому лише бейдж. Тож чекаємо, поки головний потік
  // звільниться — контент має виграти гонку.
  useEffect(() => {
    if (!userId) return
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ric = (window as any).requestIdleCallback as
      | ((cb: () => void, o?: { timeout: number }) => number)
      | undefined
    const id = ric ? ric(() => loadNotifications(), { timeout: 2000 }) : window.setTimeout(loadNotifications, 500)
    return () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const cancel = (window as any).cancelIdleCallback as ((h: number) => void) | undefined
      if (ric && cancel) cancel(id)
      else clearTimeout(id)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId])

  // Лічильник непрочитаних інакше читався РІВНО ОДИН РАЗ за сесію (ефект вище),
  // а realtime-канал живе лише поки відкритий екран сповіщень. Тобто застосунок,
  // який пролежав у фоні добу, показував учорашній бейдж. Webview Telegram
  // ховається щоразу, коли користувач перемикає чат, тож повернення на видимість
  // — найчастіша і найдешевша точка оновлення.
  useEffect(() => {
    if (!userId) return
    function onVisible() {
      if (document.visibilityState === 'visible') void loadNotifications()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId])

  // Network status monitoring
  useEffect(() => {
    const handleOffline = () => {
      setOnline(false)
      hapticNotify('warning')
    }
    const handleOnline = () => {
      setOnline(true)
      showToast({ type: 'success', title: 'Зʼєднання відновлено' })
    }
    window.addEventListener('offline', handleOffline)
    window.addEventListener('online', handleOnline)
    return () => {
      window.removeEventListener('offline', handleOffline)
      window.removeEventListener('online', handleOnline)
    }
  }, [setOnline, showToast])

  function renderScreen() {
    switch (screen) {
      case 'splash': return <SplashScreen />
      case 'welcome': return <WelcomeScreen />
      case 'role-select': return <RoleSelectScreen />
      case 'profile-setup': return <ProfileSetupScreen />
      case 'empty-state': return <EmptyStateScreen />
      case 'db-list': return <DatabaseListScreen />
      case 'create-db': return <CreateDatabaseScreen />
      case 'edit-db': return <CreateDatabaseScreen />
      case 'db-objects': return <DatabaseObjectsScreen />
      case 'property-form': return <PropertyFormScreen />
      case 'property-detail': return <PropertyDetailScreen />
      case 'sharing-analytics': return <SharingAnalyticsScreen />
      case 'export': return <ExportScreen />
      case 'realtor-dashboard': return <RealtorDashboardScreen />
      case 'realtor-database': return <RealtorDatabaseScreen />
      case 'collections': return <CollectionsScreen />
      case 'profile': return <ProfileScreen />
      case 'notifications': return <NotificationsScreen />
      case 'error': return <ErrorScreen />
      case 'success': return <SuccessScreen />
      case 'photo-upload': return <PhotoUploadScreen />
      case 'photo-gallery': return <PhotoGalleryScreen />
      case 'qr-scanner': return <QRScannerScreen />
      case 'guest-database': return <GuestDatabaseScreen />
      case 'guest-home': return <GuestHomeScreen />
      case 'manage-guests': return <ManageGuestsScreen />
      case 'team': return <TeamScreen />
      case 'shared-collection': return <SharedCollectionScreen />
      case 'payment-calendar': return <PaymentCalendarScreen />
      case 'payment-schedule': return <PaymentScheduleScreen />
      case 'payment-confirm': return <PaymentConfirmScreen />
      case 'create-invite': return <CreateInviteScreen />
      case 'folder-manage': return <FolderManageScreen />
      case 'db-picker': return <DbPickerScreen />
      case 'folder-picker': return <FolderPickerScreen />
      case 'rent-property': return <RentPropertyScreen />
      case 'delete-account': return <DeleteAccountScreen />
      default: return <SplashScreen />
    }
  }

  return (
    <ErrorBoundary>
      {!isOnline && (
        <div className="offline-banner">
          <IconWifiOff size={14} />
          Немає інтернету — дані можуть бути застарілими
        </div>
      )}
      <div key={navKey} className={`nav-wrap nav-${navDirection}`}>
        {renderScreen()}
      </div>
    </ErrorBoundary>
  )
}
