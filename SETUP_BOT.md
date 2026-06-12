# Налаштування бота і прямих посилань на Mini App

Після виконання цих кроків:
- посилання «Відкрити в Telegram» з публічної сторінки відкриватиме Mini App **одразу з базою**, без проміжного чату;
- бот відповідатиме на `/start` кнопкою, що відкриває застосунок.

Кроки 1, 2 і 4 — тільки вручну (доступ до BotFather, GitHub і Vercel є лише у вас).
Крок 3 — повністю автоматичний (один клік у GitHub Actions).

---

## Крок 1 — Створити Mini App у BotFather (~2 хв)

1. Відкрийте чат з **@BotFather** у Telegram.
2. Надішліть команду `/newapp`.
3. Виберіть свого бота зі списку.
4. **Title:** введіть назву, наприклад `PropSpace`.
5. **Description:** короткий опис, наприклад `Керування нерухомістю`.
6. **Photo:** надішліть будь-яке квадратне фото 640×360 (можна скрін застосунку). Якщо просить demo GIF — надішліть `/empty`.
7. **Web App URL:** вставте адресу застосунку на Vercel, наприклад `https://your-app.vercel.app` (точну адресу видно у Vercel → проект → Domains).
8. **Short name:** введіть коротке ім'я латиницею, наприклад `app`.
   ⚠️ **Запишіть це значення** — воно потрібне у кроках 3 і 4.

BotFather відповість посиланням виду `t.me/<bot>/<short_name>` — це і є прямий лінк на Mini App.

---

## Крок 2 — Додати токен бота в GitHub Secrets (~1 хв)

> `SUPABASE_ACCESS_TOKEN` і `SUPABASE_PROJECT_REF` вже додані (їх використовує деплой Edge Functions). Потрібен лише токен бота.

1. Відкрийте https://github.com/korhovoyn-sketch/telegramprostir/settings/secrets/actions
2. Натисніть **New repository secret**.
3. **Name:** `TELEGRAM_BOT_TOKEN`
4. **Secret:** токен вашого бота (виглядає як `1234567890:AAE...`). Якщо загубили — у BotFather: `/mybots` → ваш бот → **API Token**.
5. **Add secret**.

---

## Крок 3 — Запустити автоматичне налаштування (1 клік)

Workflow сам: згенерує випадковий `TELEGRAM_WEBHOOK_SECRET`, запише всі змінні у Supabase Edge Functions Secrets і зареєструє webhook у Telegram. Нічого копіювати вручну не треба.

1. Відкрийте https://github.com/korhovoyn-sketch/telegramprostir/actions
2. Зліва виберіть **Setup Telegram Bot Webhook**.
3. Натисніть **Run workflow** (праворуч), заповніть:
   - **bot_username** — ім'я бота без `@` (наприклад `prostirapplbot`)
   - **app_name** — short name з кроку 1 (наприклад `app`)
4. Натисніть зелену кнопку **Run workflow**.
5. Дочекайтеся зеленої галочки (~30 сек). В кінці лога буде `✅ Webhook registered`.

Перевірка: надішліть боту `/start` — він має відповісти привітанням із кнопкою «🚀 Відкрити PropSpace».

---

## Крок 4 — Додати short name у Vercel (~2 хв)

Без цього кнопка «Відкрити в Telegram» на публічній сторінці продовжить вести у чат.

1. Відкрийте Vercel → ваш проект → **Settings → Environment Variables**.
2. Додайте змінну:
   - **Key:** `NEXT_PUBLIC_TELEGRAM_APP_NAME`
   - **Value:** short name з кроку 1 (наприклад `app`)
   - **Environments:** Production (можна всі).
3. **Save**.
4. Перейдіть у **Deployments** → останній деплой → меню `⋯` → **Redeploy** (застосунок статичний, env запікається при білді).

---

## Фінальна перевірка

| Що | Як | Очікування |
|---|---|---|
| Бот відповідає | Надіслати `/start` боту | Привітання + кнопка «🚀 Відкрити PropSpace» |
| Deep link з параметром | Надіслати боту `/start db_<токен>` | Повідомлення + кнопка «🏠 Відкрити в PropSpace», тап відкриває базу |
| Публічна сторінка | Відкрити `https://<app>.vercel.app/v/?db=<токен>` у браузері телефону → «Відкрити в Telegram» | Mini App відкривається одразу з базою, без чату |

Якщо щось не працює — Supabase → Edge Functions → `telegram-bot` → **Logs** покаже помилки.
