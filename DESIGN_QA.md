# DESIGN QA — план перевірки фронтенду та елементів дизайну

Чек-лист візуальної/UX перевірки **всіх** екранів, компонентів і елементів
дизайн-системи PropSpace. Доповнює `QA.md` (там — логіка/безпека/флоу; тут —
**вигляд, верстка, стани, анімації, адаптивність**).

> Як користуватись: прогнати на **iPhone SE (320–375px)**, **великому телефоні**
> (414px), у **темній і світлій** темі Telegram, на **iOS і Android**. Скріншоти
> онбордингу автоматично збирає E2E (`tests/e2e/*`, артефакт `playwright-report`).

Позначки: ☐ не перевірено · ✅ ок · ⚠️ є зауваження.

---

## 0. Як перевіряти

| Інструмент | Команда / дія | Що дає |
|---|---|---|
| Автоматичні скріншоти | CI → артефакт `playwright-report/` | онбординг-екрани на iPhone SE |
| Guard видимості кнопок | `tests/e2e/layout-buttons.spec.ts` | головні кнопки не обрізані |
| Локальний перегляд | `npm run dev` + Telegram Web / BotFather | ручний обхід |
| Адаптив | DevTools device toolbar: 320×568, 375×667, 414×896 | брейкпоінти |
| Теми | Telegram → налаштування теми (dark/light) | `data-tgTheme` |

---

## 1. Дизайн-токени (`globals.css :root`)

- [ ] **Кольори тексту** `--t1..--t4`: ієрархія читабельна, `--t4` не зливається з фоном.
- [ ] **Скло** `--glass-0..--glass-4`, `--bd/--bd-s/--bd-strong`: панелі мають видиму, але делікатну межу.
- [ ] **Семантика** `--ok/--err/--info/--warn` (+ `-bg/-fg/-bd`): бейджі/тости коректного кольору.
- [ ] **Типографіка** `--fs-t1..--fs-foot`, `--fw-reg..--fw-heavy`, `--lh-*`: заголовки/підписи консистентні, без «стрибків».
- [ ] **Відступи** `--g1..--g6`, `--pad-card`: однакові поля між екранами.
- [ ] **Радіуси** `--r-xs..--r-xl`, `--r-pill`, `--r-icon`, `--r-phone`: картки/кнопки/інпути однаковий стиль.
- [ ] **Тіні** `--shadow-btn-blue/-success/-danger/-hover`, `--shadow-fab`: глибина без «брудних» країв.
- [ ] **Висоти** `--btn-h`, `--input-h`, `--row-h`: кнопки/інпути/рядки однакові скрізь.
- [ ] **Safe-area** `--safe-top/--safe-bottom`: контент не під «чубчиком»/home-indicator.
- [ ] **Рух** `--dur-xs..--dur-xl`, `--ease/-out/-spr`: анімації плавні, не різкі/не повільні.

---

## 2. Дизайн-система — примітиви

- [ ] **Фони** (`.bg-purple/pink/green/blue/cyan/orange/teal/violet/welcome/empty/error/success`): градієнт зверху→вниз чорний→колір, радіальні акценти без бендингу.
- [ ] **Скло-картки** `.glass / .glass-s / .glass-d`: blur, межа, фон — однакові на всіх екранах.
- [ ] **Головна кнопка** `.mbtn` (+ `.success/.danger/.disabled/.is-loading`): завжди `position:absolute` внизу, видима на малому екрані, спінер у `is-loading` центрований.
- [ ] **FAB**: над таб-баром, у safe-area, `fabPop` при появі.
- [ ] **Бейджі** `.bdg-ok/busy/sale/info/fav`: колір=статус, текст не обрізається.
- [ ] **Форми** `.fg/.fr/.fr-i/.fr-l`: вирівнювання іконка→лейбл→інпут, фокус-рінг (`inputRing`).
- [ ] **Toggle** (`Toggle.tsx`): анімація ручки, увімк/вимк кольори, haptic.
- [ ] **Segment** `.seg/.seg-b` (+ `segPop`): активний таб підсвічений.
- [ ] **Modal** (`Modal.tsx`, `modalSlideUp`): bottom-sheet, overlay, drag-нічка, danger-варіант.
- [ ] **Toast** (`Toast.tsx`, `toastSlideIn`): success/error/info, автоховання ~3.5с, не перекриває кнопку.
- [ ] **Skeleton** (`SkeletonLoader.tsx`, `shimmer`): форма ≈ контенту, плавний шиммер.
- [ ] **Mascot Prox** (`ProxMascot.tsx`): mood happy/neutral/sad, `antBlink`/`bounce`, розміри 110–140.
- [ ] **Icons** (`Icons.tsx`): однакова товщина ліній, колір успадковується, Glass-іконки з градієнтом.
- [ ] **Confetti** (`Confetti.tsx`): на SuccessScreen, без лагів.

---

## 3. Компоненти (`src/components`)

| Компонент | Перевірити | ☐ |
|---|---|---|
| `Header` | назад-кнопка, заголовок+підзаголовок не обрізані, дії праворуч | ☐ |
| `TabBar` | 4 таби, активний стан, іконки-анімації (`tabHomeHop/tabBookPop/tabBellRing/tabUserNod`), бейдж непрочитаних | ☐ |
| `SearchBar` | плейсхолдер, очищення, фокус, не стрибає при вводі | ☐ |
| `Badge` | усі варіанти кольорів/розмірів | ☐ |
| `Modal` | open/close-анімація, overlay-клік, контент-скрол | ☐ |
| `Toast` | стек/заміна, типи, таймер | ☐ |
| `Toggle` | стан, дизейбл, haptic | ☐ |
| `SkeletonLoader` | усі варіанти (картка/рядок/список) | ☐ |
| `CoachMark` | підказка-онбординг, позиціонування, dismiss | ☐ |
| `DatabaseStatsPanel` | числа вирівняні, нема overflow при великих сумах | ☐ |
| `FilesList` / `FilePreviewModal` | список файлів, прев'ю, видалення | ☐ |
| `ErrorBoundary` | фолбек-екран при краші, не білий екран | ☐ |

---

## 4. Екрани (25) — верстка, стани, кнопки, анімації

Для **кожного**: safe-area зверху/знизу · головна кнопка видима й не перекрита ·
скрол не ховає контент під кнопкою · перехід `navRight/navLeft/navFade` · довгий
текст/числа не ламають верстку.

### Auth / онбординг
- [ ] **Splash** — лого-градієнт, прогрес-бар 0→100%, версія внизу; без застрягання.
- [ ] **Welcome** — idle: маскот+фічі+кнопка в `.body`; loading: кроковий лоадер, крапки, retry після 25с; кнопка **не сплюснута** (guard E2E).
- [ ] **RoleSelect** — 2 картки, активний стан/обведення, текст ролі з ellipsis, «Крок 1 з 2».
- [ ] **ProfileSetup** — locked Telegram-дані, інпути email/phone, кнопки «Почати»/«Пропустити» обидві видимі, валідація email.
- [ ] **EmptyState** — owner: 3 поради + «Створити першу базу»; realtor: маскот + «Сканувати QR»; контент у `.body`, кнопка внизу.

### Owner
- [ ] **DatabaseList** — stats-grid, список баз, пошук, FAB; skeleton при завантаженні; empty-state.
- [ ] **CreateDatabase** — name/address, type-grid (6), color-picker; валідація; edit-режим.
- [ ] **DatabaseObjects** — таби (Всі/Вільно/Зайнято), пошук, сорт, картки об'єктів, batch-bar у safe-area; FAB.
- [ ] **PropertyForm** — секції (площа/оренда/комуналка/паркінг/фото/файли), скрол з клавіатурою, кнопки Save/Delete.
- [ ] **PropertyDetail** — hero `min(140px,22vh)`, метрики-grid, статус-бейдж, галерея, контакти; кнопки share/edit.
- [ ] **SharingAnalytics** — графік переглядів (`drawLine`), список переглядачів, QR/копіювання.
- [ ] **Export** — формати (PDF/Excel/LUN/OLX), шаблони, тоглі; кнопка генерації.

### Realtor
- [ ] **RealtorDashboard** — stats, список підписок, пошук, таб-бар; empty/skeleton/retry.
- [ ] **RealtorDatabase** — owner-картка, read-only список, retry-стан, share.
- [ ] **Collections** — список підбірок, прев'ю, FAB, додавання/видалення об'єктів (modal).
- [ ] **SharedCollection** — read-only підбірка чужого ріелтора.

### Система
- [ ] **Profile** — avatar+ініціали, stats, pro-card («Скоро»), контакти (revert при помилці), мова/валюта, тоглі сповіщень, logout-modal.
- [ ] **Notifications** — таби (Всі/Перегляди/Чати/Система), групування за датою, swipe/delete вирівняний, mark-all-read.
- [ ] **Error** — sad-маскот, повідомлення, «Спробувати ще раз»; скрол-safe (margin:auto).
- [ ] **Success** — happy-маскот, конфеті, авто-навігація 3с, крапки-прогрес; скрол-safe.

### Медіа / допоміжні
- [ ] **PhotoUpload** — кругл. прогрес, черга, авто-back по завершенню.
- [ ] **PhotoGallery** — fullscreen, свайп, thumbnail-стрічка, share; `galleryFadeIn`.
- [ ] **QRScanner** — превʼю камери, рамка, `scanLine`, ліхтарик, ручний ввід токена.
- [ ] **GuestDatabase** — публічний перегляд, помилка «Посилання недійсне» (🔗), CTA-логін.
- [ ] **PaymentCalendar** — календар, due-day, mark-paid/archive, статуси pending/paid/overdue.

---

## 5. Наскрізні перевірки

### Адаптивність
- [ ] iPhone SE 320×568: жодна кнопка/контент не обрізані, нема горизонт. скролу.
- [ ] Великий екран 414×896: контент не «розтягнутий», макс-ширина розумна.
- [ ] Довгі назви/великі суми/`@username`: ellipsis або перенос, без ламання сітки.

### Safe-area та клавіатура
- [ ] Нижні кнопки/FAB/таб-бар над home-indicator (`--safe-bottom`).
- [ ] Хедери під «чубчиком» (`--safe-top`).
- [ ] iOS клавіатура: активний інпут скролиться у видиму зону (`scrollFocusedIntoView`), кнопка не перекрита (`--keyboard-h`).

### Тема й контраст
- [ ] Dark тема: усі фони/тексти коректні (`data-tgTheme=dark`).
- [ ] Light тема Telegram: текст читабельний, скло не зникає.
- [ ] Контраст `--t3/--t4` на градієнтах ≥ WCAG AA для основного тексту.

### Навігація та рух
- [ ] Переходи forward/back/root правильного напрямку (`navRight/navLeft/navFade`).
- [ ] Telegram BackButton: показ при `history>0`, повертає на коректний екран, не на auth.
- [ ] `cascadeIn` для списків, `statPop` для stat-карток, `fabPop` для FAB — без сіпання.

### Взаємодія / стани
- [ ] Кожна async-кнопка має `is-loading`/`disabled` (без подвійних натискань).
- [ ] Кожен список має 3 стани: skeleton → empty → populated; помилка → retry.
- [ ] Haptic на виборі ролі/типу/сабміті/помилці.
- [ ] Offline-банер з'являється/зникає, контент лишається доступним.

### Доступність (a11y)
- [ ] Tap-таргети ≥ 44×44px (кнопки, таби, toggle, delete).
- [ ] `aria-label` на іконкових кнопках (напр. «Написати власнику»).
- [ ] Фокус-стан інпутів видимий (`inputRing`).

---

## 6. Анімації (37 keyframes) — без лагів/сіпання

- [ ] Вхід екрана `screenEnter`; навігація `navRight/navLeft/navFade`.
- [ ] Кнопка `btnPress`/`btnPulse`/`btnSuccess`; спінер `spin`.
- [ ] Списки `cascadeIn`; stat `statPop`; seg `segPop`; tabbar `tabbarIn` + іконки.
- [ ] Скло/світло `shimmer/shimmerSpin/glowPulse/sparkleFloat`.
- [ ] Модал `modalSlideUp`; тост `toastSlideIn`; інпут `inputRing`.
- [ ] Спец: QR `scanLine/qrPop`, графік `drawLine`, чек `checkIn/cmarkIn/cmarkPulse`, галерея `galleryFadeIn`, маскот `antBlink/bounce`.
- [ ] `prefers-reduced-motion` (бажано): критичні переходи лишаються зрозумілими.

---

## Sign-off

| Блок | iOS | Android | Примітки |
|---|---|---|---|
| Токени/дизайн-система | ☐ | ☐ | |
| Компоненти | ☐ | ☐ | |
| Екрани (25) | ☐ | ☐ | |
| Адаптив/safe-area/клавіатура | ☐ | ☐ | |
| Теми/контраст | ☐ | ☐ | |
| Навігація/анімації | ☐ | ☐ | |
| Доступність | ☐ | ☐ | |
