import { defineConfig, devices } from '@playwright/test'
import { existsSync } from 'node:fs'

// Hermetic E2E: a dev server with dummy Supabase env (real network calls are
// intercepted per-test via page.route). No live Supabase/Telegram needed.

// Пісочниця Claude Code на вебі має предвстановлений Chromium поза стандартним
// кешем Playwright — там цей шлях існує і МУСИТЬ використовуватись (playwright
// install у пісочниці заборонений). На CI/локалі шляху немає — Playwright
// резолвить браузер зі свого кешу (npx playwright install --with-deps chromium).
const SANDBOX_CHROMIUM = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'
const launchOptions = existsSync(SANDBOX_CHROMIUM) ? { executablePath: SANDBOX_CHROMIUM } : {}
export default defineConfig({
  testDir: './tests/e2e',
  // Замірні спеки (`_*.spec.ts`) не входять у звичайний прогін: вони не гарди, а
  // інструмент — друкують хвилю запитів і кадри, свідомо ганяються з
  // `--workers=1`, і в паралельному прогоні їхні цифри однаково безглузді.
  // Запуск: npx playwright test _perf --workers=1
  testIgnore: process.env.PERF ? [] : ['**/_*.spec.ts'],
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['html', { open: 'never' }], ['list']] : 'list',
  use: {
    baseURL: 'http://localhost:3000',
    screenshot: 'only-on-failure',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'iphone-se',
      use: {
        browserName: 'chromium',
        viewport: { width: 375, height: 667 },
        deviceScaleFactor: 2,
        isMobile: true,
        hasTouch: true,
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
        launchOptions,
      },
    },
  ],
  webServer: {
    // CI ганяє тести проти ПРОДАКШН static export (як у Vercel): dev-сервер з
    // on-demand компіляцією на 2-ядерному раннері + паралельні Chromium давали
    // масові таймаути (62/74 падали, /v-статика проходила). Локально/пісочниця —
    // швидкий ітеративний dev.
    command: process.env.CI
      ? 'npm run build && npx serve@14 out -l 3000'
      : 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
    env: {
      NEXT_PUBLIC_SUPABASE_URL: 'http://localhost:9999',
      NEXT_PUBLIC_SUPABASE_ANON_KEY: 'test-anon-key',
    },
  },
})
