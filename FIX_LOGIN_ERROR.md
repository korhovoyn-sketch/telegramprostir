# Виправлення помилки входу "The string did not match the expected pattern"

## 🔍 Діагностика

### Крок 1: Перевірити браузер консоль

1. Відкрити Telegram Mini App на тестуванні
2. Натиснути F12 (или open DevTools)
3. Перейти на вкладку **Console**
4. Натиснути кнопку "Вхід через Telegram"
5. **Записати точну помилку** з консолі

Виберіть свою помилку з переліку:

#### Помилка A: "No access_token in response"
**Причина**: Edge function повернув response без access_token
**Крок**: Перейти до Крок 2 (Перевірити Edge Function)

#### Помилка B: "Invalid token format: expected 3 parts"
**Причина**: Edge function повернув non-JWT токен (не має 3 частин)
**Крок**: Перейти до Крок 2 (Перевірити Edge Function)

#### Помилка C: "setSession failed: ..."
**Причина**: Supabase auth.setSession() кинув exception
**Крок**: Перейти до Крок 3 (Перевірити Supabase SDK)

#### Помилка D: "The string did not match the expected pattern" (оригінальна)
**Причина**: iOS Safari atob() кинув exception (невалідний JWT)
**Крок**: Перейти до Крок 2 (Перевірити Edge Function)

#### Помилка E: "Supabase URL not configured"
**Причина**: `NEXT_PUBLIC_SUPABASE_URL` не встановлена на клієнті
**Крок**: Перейти до Крок 4 (Перевірити Vercel Env Vars)

---

### Крок 2: Перевірити Edge Function на Supabase

1. Перейти в **Supabase Dashboard**
2. Вибрати проект: `propspace` (ref: `cjsuuzynpuimgndudzka`)
3. Перейти **Edge Functions** → **telegram-auth**
4. Клікнути на вкладку **Logs**
5. Натиснути кнопку входу в app
6. **Перевірити логи** на наявність помилок

Виберіть свою помилку з логів:

#### Лог A: "[telegram-auth] Invalid initData"
```
Status: 401
Message: "Invalid initData"
```
**Причина**: HMAC валідація initData невдала
**Виправлення**: 
- ✅ Перевірити що TELEGRAM_BOT_TOKEN правильний (в Supabase → Settings → Secrets)
- ✅ Перевірити що initData відправляється коректно

#### Лог B: "[telegram-auth] Missing user id"
```
Status: 400
Message: "Missing user id"
```
**Причина**: Telegram user object не містить id
**Виправлення**: 
- ✅ Перевірити що клієнт повертає правильний Telegram user object

#### Лог C: "[telegram-auth] Failed to create session: ..."
```
Status: 500
Message: "Failed to create session: ..."
```
**Причина**: Supabase admin.createSession() кинув error
**Виправлення**:
- ✅ Перевірити що SUPABASE_SERVICE_ROLE_KEY правильна
- ✅ Перевірити що auth.users таблиця має місце на Supabase

#### Лог D: "[telegram-auth] Invalid JWT format from createSession"
```
Status: 500
Message: "Invalid JWT format from createSession: got 1 parts instead of 3"
```
**Причина**: Edge function SDK повернув невалідний токен
**Виправлення**:
- ⚠️ Це критична помилка у Supabase SDK
- ✅ Оновити `@supabase/supabase-js` до latest версії
- ✅ Контактувати Supabase support якщо проблема залишиться

---

### Крок 3: Перевірити Supabase SDK на клієнті

В браузері console:
```javascript
// Перевірити що Supabase client створений правильно
console.log(window.navigator)

// Перевірити версію Supabase JS SDK
const supabaseVersion = document.querySelector('script[src*="supabase"]')?.src
console.log('Supabase version:', supabaseVersion)
```

Очікуваний результат:
```
@supabase/supabase-js v2.45.0+
```

Якщо версія старша за 2.40.0:
```bash
npm update @supabase/supabase-js
npm run build
```

---

### Крок 4: Перевірити Vercel Environment Variables

1. Перейти в **Vercel Dashboard**
2. Вибрати проект: **propspace**
3. Перейти **Settings** → **Environment Variables**
4. Перевірити що ці змінні встановлені:

| Назва | Значення | Тип |
|-------|----------|-----|
| `NEXT_PUBLIC_SUPABASE_URL` | `https://cjsuuzynpuimgndudzka.supabase.co` | Public |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | `...` (анонімний ключ) | Public |

Якщо змінні не встановлені:
```bash
# На локальній машині встановити .env.local
cat > .env.local << EOF
NEXT_PUBLIC_SUPABASE_URL=https://cjsuuzynpuimgndudzka.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key-here
EOF

# Потім синхронізувати з Vercel
vercel env pull
```

---

### Крок 5: Перевірити Supabase Edge Function Secrets

1. Перейти в **Supabase Dashboard**
2. Вибрати проект: **propspace**
3. Перейти **Edge Functions** → **telegram-auth** → **Settings**
4. Перевірити що ці secrets встановлені:

| Назва | Очікування | Статус |
|-------|-----------|--------|
| `SUPABASE_URL` | `https://cjsuuzynpuimgndudzka.supabase.co` | ✅ Set |
| `SUPABASE_SERVICE_ROLE_KEY` | (secret key) | ✅ Set |
| `TELEGRAM_BOT_TOKEN` | (от BotFather) | ✅ Set |
| `ALLOWED_ORIGIN` | `https://propspace.vercel.app` OR `https://yourdomain.com` | ⚠️ Optional (defaults to `*`) |

Якщо `ALLOWED_ORIGIN` не встановлена:
```bash
# На локальній машині
supabase functions update telegram-auth --env ALLOWED_ORIGIN=https://propspace.vercel.app

# ИЛИ через Supabase Dashboard:
# Edge Functions → telegram-auth → Settings → Add secret ALLOWED_ORIGIN
```

---

## 🔧 Виправлення

### Варіант A: Edge Function деплоївся правильно, але код старий

Якщо на Supabase логах бачите посилання на `verifyOtp` замість `createSession`:

1. Видалити old edge function:
```bash
supabase functions delete telegram-auth
```

2. Переписати функцію:
```bash
cp supabase/functions/telegram-auth/index.ts /tmp/backup.ts
```

3. Найнижче версія:
```bash
git pull origin main
npm run build
supabase functions deploy telegram-auth
```

### Варіант B: Edge Function не деплоївся взагалі

Перевірити CI/CD:

1. Перейти в **GitHub** → **Actions**
2. Подивитись **deploy-edge-function.yml** на последнee run
3. Якщо FAILED:
   - ✅ Перевірити чи `SUPABASE_ACCESS_TOKEN` секрет встановлен у GitHub
   - ✅ Перевірити чи рабочий token не просів (терміін дії)
   - ✅ Переписати token:
     ```bash
     # На локальній машині:
     supabase projects api-show --project-id cjsuuzynpuimgndudzka
     # Отримати access token
     # Встановити у GitHub → Settings → Secrets → SUPABASE_ACCESS_TOKEN
     ```

---

## ✅ Перевіка після виправлення

1. **Локально**:
```bash
npm run dev
# Відкрити http://localhost:3000
# Перевірити в браузер console для помилок
```

2. **На Staging** (якщо є):
```bash
# Натиснути кнопку входу
# Перевірити редиректування на role-select або db-list
```

3. **На Production**:
```bash
# Відкрити Telegram Bot Mini App
# Натиснути "Вхід через Telegram"
# Перевірити що входу успішний (редиректування)
```

---

## 📞 Якщо нічого не допомогло

Скопіюйте эти інформацій і надішліть розробнику:

```
🐛 Login Error Report

Browser Console Error:
[copy exact error message from console]

Supabase Edge Function Logs:
[copy exact log message from Supabase]

HTTP Status Code:
[e.g., 401, 500, etc.]

Device/Browser:
[e.g., iPhone 13 Safari, Android Chrome, etc.]

Steps to Reproduce:
1. Open Mini App
2. Click "Вхід через Telegram"
3. See error

Expected:
[describe what should happen]

Actual:
[describe what actually happens]
```

---

## 🚀 Запобігання на майбутнє

1. **Enable Server Logs**: Виконувати `supabase functions logs telegram-auth --follow` під час тестування
2. **Use Staging**: Завжди тестувати на staging перед production deployment
3. **Monitor Errors**: Налаштувати Sentry або similar для捕捉 error signals
4. **Automated Tests**: Запустити `test-auth-flow.js` перед кожним deploymentом

```bash
# Before deploying:
node test-auth-flow.js
# Should see: 5 passing tests
```

---

## 📚 Useful Links

- Telegram Bot API: https://core.telegram.org/bots/webapps
- Supabase Edge Functions: https://supabase.com/docs/guides/functions
- Supabase Auth: https://supabase.com/docs/guides/auth
- HMAC-SHA256: https://en.wikipedia.org/wiki/HMAC
