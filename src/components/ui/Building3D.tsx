'use client'

import { useEffect, useRef, useState } from 'react'

/**
 * Ілюстрація «немає фото» на картці обʼєкта.
 *
 * Була статичною SVG-картинкою, що ліниво пливла вгору-вниз. Власник попросив
 * зробити її живою за зразком зірки Telegram Premium: обʼєм, скло, реакція на
 * палець і зірочки, що спалахують від дотику.
 *
 * ЯК ЦЕ ЗРОБЛЕНО БЕЗ 3D-РУШІЯ. Справжнього рендера тут не треба: будинок уже
 * намальований в ізометрії (три грані — верх, фронт, бік), тож достатньо
 * нахиляти всю сцену в CSS-перспективі й РОЗНОСИТИ шари по `translateZ`. Тоді
 * при нахилі шари зміщуються по-різному — це паралакс, і око читає його як
 * глибину. Той самий прийом, що в іконок Apple TV/watchOS.
 *
 * ЩО ТУТ КРИТИЧНО ДЛЯ ПРОДУКТИВНОСТІ (правила проєкту):
 *  • рухаються ЛИШЕ `transform`/`opacity` — жодного лейауту щокадру;
 *  • `backdrop-filter` тут НЕ використовується: скло малюється градієнтами.
 *    Блюр на сцені, що обертається щокадру, — це рівно та патологія WebKit,
 *    через яку в шитах і акордеоні його вимикають на час руху;
 *  • `will-change` не тримається постійно — лише поки палець на сцені;
 *  • `prefers-reduced-motion` читається В JS: CSS-блок не спиняє ні rAF, ні
 *    інлайновий transform (та сама пастка, що вже описана в `Collapsible`).
 */

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

export default function Building3D() {
  const stageRef = useRef<HTMLDivElement>(null)
  const rafRef = useRef(0)
  const [burst, setBurst] = useState(0)
  const burstTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  useEffect(() => () => {
    cancelAnimationFrame(rafRef.current)
    clearTimeout(burstTimer.current)
  }, [])

  // Записуємо нахил у CSS-змінні, а не в style.transform: так сама формула
  // (скільки градусів, які шари, наскільки зміщується відблиск) лишається в
  // CSS поряд із рештою сцени, а JS віддає лише два числа −1..1.
  const setTilt = (nx: number, ny: number) => {
    cancelAnimationFrame(rafRef.current)
    rafRef.current = requestAnimationFrame(() => {
      const el = stageRef.current
      if (!el) return
      el.style.setProperty('--nx', nx.toFixed(3))
      el.style.setProperty('--ny', ny.toFixed(3))
    })
  }

  const onMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (prefersReducedMotion()) return
    const el = stageRef.current
    if (!el) return
    const r = el.getBoundingClientRect()
    // −1..1 від центру сцени. Не clamp-имо жорстко: палець може вийти за межі
    // під час свайпу, і плавний вихід за одиницю виглядає природніше за стоп.
    const nx = Math.max(-1.4, Math.min(1.4, ((e.clientX - r.left) / r.width - 0.5) * 2))
    const ny = Math.max(-1.4, Math.min(1.4, ((e.clientY - r.top) / r.height - 0.5) * 2))
    setTilt(nx, ny)
  }

  const release = () => {
    const el = stageRef.current
    if (el) el.classList.remove('b3d-live')
    setTilt(0, 0)
  }

  const onDown = (e: React.PointerEvent<HTMLDivElement>) => {
    const el = stageRef.current
    // `will-change` вмикається рівно на час взаємодії: постійний шар тут — це
    // назавжди виділена памʼять під сцену, яку майже весь час ніхто не чіпає.
    if (el) el.classList.add('b3d-live')
    onMove(e)
    if (prefersReducedMotion()) return
    // Спалах зірочок. Ключ у React-стані, щоб кожен тап перезапускав анімацію:
    // без зміни ключа браузер вважає, що вона вже програна.
    setBurst((n) => n + 1)
    clearTimeout(burstTimer.current)
    burstTimer.current = setTimeout(() => setBurst(0), 700)
  }

  return (
    <div
      ref={stageRef}
      className="b3d-stage"
      onPointerMove={onMove}
      onPointerDown={onDown}
      onPointerUp={release}
      onPointerCancel={release}
      onPointerLeave={release}
      aria-hidden="true"
    >
      <div className="b3d-tilt">
        {/* Задній ореол — найглибший шар, рухається проти будинку */}
        <span className="b3d-halo" />

        <svg viewBox="0 0 160 150" width="136" height="126" className="b3d-body" style={{ overflow: 'visible' }}>
          <defs>
            <linearGradient id="b3dFr" x1="0" y1="0" x2=".08" y2="1">
              <stop offset="0%" stopColor="#4E87E8"/><stop offset="100%" stopColor="#1C3F8E"/>
            </linearGradient>
            <linearGradient id="b3dSd" x1="0" y1="0" x2="1" y2=".15">
              <stop offset="0%" stopColor="#1C3F8E"/><stop offset="100%" stopColor="#0B2362"/>
            </linearGradient>
            <linearGradient id="b3dTp" x1="0" y1="1" x2="1" y2="0">
              <stop offset="0%" stopColor="#3A70D4"/><stop offset="100%" stopColor="#61A0F0"/>
            </linearGradient>
            {/* Полиск скла — тільки на гранях, тож обмежений їхньою формою */}
            <linearGradient id="b3dGl" x1="0" y1="0" x2=".7" y2="1">
              <stop offset="0%" stopColor="#fff" stopOpacity=".34"/>
              <stop offset="55%" stopColor="#fff" stopOpacity=".06"/>
              <stop offset="100%" stopColor="#fff" stopOpacity="0"/>
            </linearGradient>
            <linearGradient id="b3dGlF" x1=".15" y1="0" x2=".85" y2="1">
              <stop offset="0%" stopColor="#fff" stopOpacity="0"/>
              <stop offset="42%" stopColor="#fff" stopOpacity=".16"/>
              <stop offset="58%" stopColor="#fff" stopOpacity=".16"/>
              <stop offset="100%" stopColor="#fff" stopOpacity="0"/>
            </linearGradient>
          </defs>

          <g className="b3d-g">
            <polygon points="46,50 110,50 132,36 68,36" fill="url(#b3dTp)"/>
            <rect x="46" y="50" width="64" height="70" fill="url(#b3dFr)"/>
            <polygon points="110,50 132,36 132,106 110,120" fill="url(#b3dSd)"/>

            <rect x="83" y="28" width="3.5" height="10" fill="rgba(160,200,255,.65)" rx="1"/>
            <circle cx="84.75" cy="27" r="2.5" fill="rgba(180,220,255,.85)"/>

            <line x1="46" y1="50" x2="46" y2="120" stroke="rgba(255,255,255,.2)" strokeWidth="1.5"/>
            <line x1="46" y1="50" x2="110" y2="50" stroke="rgba(255,255,255,.24)" strokeWidth="1"/>

            <rect className="b3d-wa" x="53" y="59" width="13" height="13" rx="2" fill="rgba(165,215,255,.82)"/>
            <rect className="b3d-wb" x="72" y="59" width="13" height="13" rx="2" fill="rgba(165,215,255,.52)"/>
            <rect className="b3d-wc" x="91" y="59" width="13" height="13" rx="2" fill="rgba(165,215,255,.76)"/>

            <rect className="b3d-wd" x="53" y="77" width="13" height="13" rx="2" fill="rgba(165,215,255,.44)"/>
            <rect className="b3d-wa" x="72" y="77" width="13" height="13" rx="2" fill="rgba(165,215,255,.86)"/>
            <rect className="b3d-wb" x="91" y="77" width="13" height="13" rx="2" fill="rgba(165,215,255,.38)"/>

            <rect className="b3d-wc" x="53" y="95" width="13" height="13" rx="2" fill="rgba(165,215,255,.7)"/>
            <rect x="72"  y="95" width="13" height="13" rx="2" fill="rgba(165,215,255,.22)"/>
            <rect className="b3d-wd" x="91" y="95" width="13" height="13" rx="2" fill="rgba(165,215,255,.62)"/>

            <rect className="b3d-wb" x="115" y="55" width="9" height="12" rx="1.5" fill="rgba(120,175,240,.48)"/>
            <rect className="b3d-wc" x="115" y="73" width="9" height="12" rx="1.5" fill="rgba(120,175,240,.62)"/>
            <rect x="115" y="91" width="9" height="12" rx="1.5" fill="rgba(120,175,240,.28)"/>

            {/* Полиск лягає ПІСЛЯ вікон, але ДО цоколя: скло поверх фасаду */}
            <polygon points="46,50 110,50 132,36 68,36" fill="url(#b3dGl)"/>
            <rect x="46" y="50" width="64" height="70" fill="url(#b3dGlF)"/>
            <rect x="46" y="108" width="64" height="12" fill="rgba(12,28,72,.7)"/>
            <rect x="70" y="108" width="18" height="12" fill="rgba(18,36,90,.9)" rx="1"/>
            <line x1="46" y1="120" x2="110" y2="120" stroke="rgba(255,255,255,.07)" strokeWidth="1"/>
          </g>
        </svg>


        {/* Зірочки — найближчий до глядача шар, тож на нахилі вони йдуть
            найдалі. `key` перезапускає спалах на кожен новий тап. */}
        <span className={`b3d-sparks${burst ? ' b3d-burst' : ''}`} key={burst}>
          <i style={{ '--sx': '-46px', '--sy': '-34px', '--sd': '0ms' } as React.CSSProperties} />
          <i style={{ '--sx': '52px', '--sy': '-18px', '--sd': '60ms' } as React.CSSProperties} />
          <i style={{ '--sx': '-52px', '--sy': '26px', '--sd': '120ms' } as React.CSSProperties} />
          <i style={{ '--sx': '44px', '--sy': '38px', '--sd': '30ms' } as React.CSSProperties} />
          <i style={{ '--sx': '6px', '--sy': '-52px', '--sd': '90ms' } as React.CSSProperties} />
        </span>
      </div>
    </div>
  )
}
