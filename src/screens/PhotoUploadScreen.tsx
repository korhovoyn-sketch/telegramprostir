'use client'

import { useEffect, useState, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import { offlineGuard } from '@/lib/offline'
import { isImage, MAX_INPUT_MB } from '@/lib/fileType'
import { uploadPropertyPhoto } from '@/lib/photoUpload'
import Header from '@/components/ui/Header'
import { humanizeDbError } from '@/lib/utils'
import { IconCheck, IconX, IconAlertTriangle } from '@/components/Icons'
import { tr } from '@/lib/i18n'

/* eslint-disable @next/next/no-img-element */

interface UploadItem {
  file: File
  status: 'pending' | 'uploading' | 'done' | 'error'
  progress: number
  path?: string
  errorMsg?: string
}

export default function PhotoUploadScreen() {
  const { screenParams, back, showToast } = useAppStore()
  const propertyId = screenParams.propertyId as string
  // МЕЖА НА ОБʼЄКТ, не на партію. Доти 20 обмежувало рівно один захід, а
  // `existingCount` читався лише заради нумерації — тобто 20 + 20 + 20 клалось
  // без жодного слова. Документи цю дисципліну мали з самого початку
  // (`MAX_FILES` звіряється з лічильником у БД), фото — ні.
  const MAX_PHOTOS = 20
  const rawFiles = (screenParams.files as File[]) ?? []
  // Причини відсіву РОЗДІЛЬНІ: «не те» і «завелике» лікуються по-різному, тож
  // спільне «не підійшло» лишало б користувача без наступного кроку.
  // Межа ВХОДУ, а не фінальна: конвеєр навмисно стискає знімок перед
  // перевіркою 10 МБ (див. `lib/fileType`), тож фільтрувати вхід по 10 означало
  // б відкидати звичайне фото з сучасного телефона ДО стиснення — тобто
  // позбавляти сенсу сам конвеєр.
  const notImages = rawFiles.filter((f) => !isImage(f))
  const tooBig = rawFiles.filter((f) => isImage(f) && f.size > MAX_INPUT_MB * 1024 * 1024)
  const validFiles = rawFiles.filter((f) => isImage(f) && f.size <= MAX_INPUT_MB * 1024 * 1024)
  const files = validFiles.slice(0, MAX_PHOTOS)
  // Скільки партія втратила на ВЛАСНІЙ межі. Без цього рядка зріз був німий:
  // `files` уже обрізаний до 20, тож пізніша перевірка `files.length > room`
  // на порожньому обʼєкті рахує `20 > 20` — тобто хибу, і 25 обраних фото
  // мовчки ставали 20 без тоста й без напису.
  const batchOver = validFiles.length - files.length

  // Stable preview URLs — created once, revoked on unmount
  const [previews] = useState<string[]>(() => files.map((f) => URL.createObjectURL(f)))
  useEffect(() => () => previews.forEach((u) => URL.revokeObjectURL(u)), [previews])

  const [queue, setQueue] = useState<UploadItem[]>(
    files.map((f) => ({ file: f, status: 'pending', progress: 0 }))
  )
  // Зріз за лічильником НАЯВНИХ фото приїжджає асинхронно, тож він мусить мати
  // власний стан: тост про нього затирає підсумок завантаження (стор тримає
  // рівно ОДИН тост), а напис лишається на екрані.
  const [roomCut, setRoomCut] = useState(0)

  // Derive done from queue — no separate boolean that can get stuck
  const total = queue.length
  const doneCount = queue.filter((x) => x.status === 'done').length
  const errorCount = queue.filter((x) => x.status === 'error').length
  const done = total > 0 && (doneCount + errorCount) === total
  // Черга порожня, хоч файли ПРИНОСИЛИ — усе відсіяв фільтр. Окремий стан, бо
  // `done` вимагає `total > 0`: без нього екран показував «Завантаження… 0 з 0»
  // назавжди, без пояснення і без виходу, крім стрілки в хедері.
  const nothingToUpload = total === 0 && rawFiles.length > 0
  // Скільки з обраного не поїде і ЧОМУ. Причини роздільні: «не те», «завелике»
  // і «понад межу» лікуються по-різному, тож спільне «не підійшло» лишало б
  // користувача без наступного кроку.
  // ПЕРЕЛІК, А НЕ ТЕРНАРНИЙ ВИБІР ОДНІЄЇ: причини НЕ взаємовиключні, і
  // `skipped` рахував суму, тоді як підпис називав лише першу — один PDF плюс
  // два завеликих звітувались як «Не зображення: 1» при трьох відсіяних.
  const overLimit = batchOver + roomCut
  const skipped = notImages.length + tooBig.length + overLimit
  const skipReasons: string[] = []
  if (notImages.length > 0) skipReasons.push(tr('Не зображення: {0}', notImages.length))
  if (tooBig.length > 0) skipReasons.push(tr('Завеликі: {0} — максимум {1} МБ', tooBig.length, MAX_INPUT_MB))
  if (overLimit > 0) skipReasons.push(tr('Понад межу {0} фото: {1}', MAX_PHOTOS, overLimit))
  const skipReason = skipReasons.join(' · ')
  const overallPct = total > 0 ? Math.round((doneCount / total) * 100) : 0

  // Auto-navigate back 1.5s after all uploads finish
  const backedRef = useRef(false)
  // Підсумок показуємо РІВНО раз. Ефект тепер залежить від `skipped`/`skipReason`
  // (вони похідні від `roomCut`, тобто від СТАНУ, який приїжджає асинхронно) —
  // без цієї засувки повторний прогін ефекту дублював би тост і скидав таймер.
  const toastedRef = useRef(false)
  useEffect(() => {
    if (!done || backedRef.current) return
    if (doneCount > 0 && !toastedRef.current) {
      toastedRef.current = true
      // ПІДСУМОК КАЖЕ ВСЮ ПРАВДУ, і це не косметика: стор тримає рівно ОДИН
      // тост, тож окреме раннє попередження про відсіяні файли затирав саме
      // цей рядок — користувач читав «3 фото завантажено», обравши пʼять.
      showToast(skipped > 0
        ? { type: 'error', title: tr('{0} фото завантажено', doneCount), subtitle: skipReason }
        : { type: 'success', title: tr('{0} фото завантажено', doneCount) })
    }
    const timer = setTimeout(() => {
      backedRef.current = true
      back()
    }, 1500)
    return () => clearTimeout(timer)
  }, [done, doneCount, skipped, skipReason, showToast, back])

  // Гард від подвійного старту черги: StrictMode у dev проганяє mount-ефекти
  // двічі — без гарда КОЖНЕ фото вантажилось двома копіями (два файли в
  // storage + два рядки property_photos). Ref переживає double-invoke.
  const startedRef = useRef(false)
  // Скільки з цієї партії дозволено. Ref, бо читає замикання черги, яке
  // створюється до того, як лічильник із БД приїхав.
  const limitRef = useRef(Infinity)
  useEffect(() => {
    if (startedRef.current) return
    startedRef.current = true
    if (files.length === 0) {
      // ВСІ файли відсіяв фільтр — і доти це давало вічний спінер: `done`
      // вимагає `total > 0`, тобто «Готово» не зʼявлялось НІКОЛИ, а причини
      // не було видно ніде (тост існував лише для «>20 фото»). Найчастіший
      // випадок — знімок понад 10 МБ: інпут має `accept="image/*"` і розміру
      // не перевіряє, drop-зона теж.
      if (rawFiles.length > 0) {
        showToast({
          type: 'error', title: tr('Не підійшов жоден файл'),
          subtitle: tr('Потрібні JPG, PNG або WebP до {0} МБ', MAX_INPUT_MB),
        })
      }
      return
    }
    if (offlineGuard(tr('Завантаження фото недоступне офлайн'))) { back(); return }
    let idx = 0
    // Скільки фото в обʼєкта ВЖЕ є — щоб продовжити нумерацію, а не почати
    // спочатку. Читаємо один раз перед чергою; помилка тут не критична —
    // фолбек 0 повертає стару (гіршу, але робочу) поведінку.
    let existingCount = 0

    async function uploadNext() {
      if (idx >= Math.min(files.length, limitRef.current)) return

      const currentIdx = idx
      setQueue((q) => q.map((x, i) => i === currentIdx ? { ...x, status: 'uploading', progress: 10 } : x))

      // Shared pipeline (lib/photoUpload) handles compress → path → upload →
      // insert → orphan cleanup; the queue index becomes the row's sort_order.
      try {
        // `sort_order` продовжує НАЯВНІ фото, а не стартує з нуля: інакше друга
        // партія давала другий знімок із `sort_order = 0`, тобто нічию з чинною
        // обкладинкою. І галерея, і `get_public_property_preview` сортують саме
        // по ньому, тож обкладинка на /v могла мовчки помінятись.
        const path = await uploadPropertyPhoto(propertyId, files[currentIdx], existingCount + currentIdx)
        setQueue((q) => q.map((x, i) => i === currentIdx
          ? { ...x, status: 'done', progress: 100, path } : x))
      } catch (e) {
        const msg = humanizeDbError(e, tr('Невідома помилка'))
        setQueue((q) => q.map((x, i) => i === currentIdx
          ? { ...x, status: 'error', progress: 0, errorMsg: msg } : x))
        showToast({ type: 'error', title: tr('Помилка завантаження'), subtitle: msg })
      }

      idx++
      uploadNext()
    }

    // Підрахунок наявних фото — РІВНО ОДИН раз і ПЕРЕД чергою.
    // Попередня версія цього блоку опинилась усередині `uploadNext`, після
    // `idx++`, і давала рівно те, що мала прибрати: перше фото партії йшло з
    // `existingCount = 0`, тобто в нічию з чинною обкладинкою. Плюс запит на
    // КОЖНЕ фото і — найгірше — рекурсія лишалась досяжною тільки з того IIFE
    // без try, тож мережевий збій посеред партії вішав екран назавжди
    // (`done` не наставав, спінер крутився без помилки).
    void (async () => {
      try {
        const { count } = await supabase
          .from('property_photos')
          .select('id', { count: 'exact', head: true })
          .eq('property_id', propertyId)
        existingCount = count ?? 0
      } catch {
        // Фолбек 0 — стара (гірша, але робоча) нумерація. Черга мусить
        // стартувати в будь-якому разі.
      }
      // Той самий лічильник тепер тримає і МЕЖУ. Обрізаємо чергу, а не
      // відмовляємо цілком: із пʼяти обраних три можуть законно влізти.
      const room = Math.max(0, MAX_PHOTOS - existingCount)
      if (files.length > room) {
        setQueue((q) => q.slice(0, room))
        setRoomCut(files.length - room)
        limitRef.current = room
        // ТОСТ ЛИШЕ ДЛЯ `room === 0`, і це не економія. При `room > 0` екран
        // лишається відкритим, і зріз уже названий персистентним рядком
        // `.fr-note` («Понад межу N фото: M») — а тост, по-перше, казав
        // «Завантажено лише N» у МИНУЛОМУ часі ДО початку завантаження, тобто
        // стверджував те, чого ще не сталось, а по-друге його однаково затирав
        // підсумковий тост (стор тримає рівно один). При `room === 0` ми
        // НАВІГУЄМО ГЕТЬ, тож рядка на екрані вже ніхто не побачить — там тост
        // єдиний носій пояснення, і він лишається.
        if (room === 0) {
          showToast({
            type: 'error',
            title: tr('Максимум {0} фото на обʼєкт', MAX_PHOTOS),
            subtitle: tr('Видаліть зайві, щоб додати нові'),
          })
          back()
          return
        }
      }
      uploadNext()
    })()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const radius = 44
  const circ = 2 * Math.PI * radius
  const offset = circ * (1 - overallPct / 100)

  return (
    <div className="scr bg-violet">
      <Header title={tr('Завантаження фото')} backLabel={tr('Назад')} />

      <div className="body" style={{ alignItems: 'center', justifyContent: 'center', display: 'flex', flexDirection: 'column', gap: 24 }}>
        {/* Circular progress */}
        <div style={{ position: 'relative', width: 112, height: 112 }}>
          <svg width="112" height="112" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="56" cy="56" r={radius} fill="none" stroke="rgba(255,255,255,.1)" strokeWidth="8" />
            <circle
              cx="56" cy="56" r={radius}
              fill="none"
              stroke={done && errorCount === 0 ? 'var(--ok-bright)' : done && doneCount === 0 ? 'var(--err-fg)' : 'var(--violet)'}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circ}
              strokeDashoffset={done ? 0 : offset}
              style={{ transition: 'stroke-dashoffset 0.4s ease, stroke 0.3s ease' }}
            />
          </svg>
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          }}>
            {done ? (
              <span className="icon-check-pop">
                <IconCheck size={26} color="var(--ok-bright)" />
              </span>
            ) : (
              <>
                <div style={{ fontSize: 'var(--fs-t3)', fontWeight: 'var(--fw-bold)', color: 'var(--t1)' }}>{overallPct}%</div>
                <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)' }}>{doneCount}/{total}</div>
              </>
            )}
          </div>
        </div>

        <div style={{ textAlign: 'center' }}>
          <div style={{ color: 'var(--t1)', fontWeight: 'var(--fw-semi)', fontSize: 'var(--fs-call)' }}>
            {nothingToUpload
              ? tr('Не підійшов жоден файл')
              : done ? (errorCount > 0 && doneCount === 0 ? tr('Помилка завантаження') : tr('Завантажено!')) : tr('Завантаження...')}
          </div>
          <div style={{ color: 'var(--t3)', fontSize: 'var(--fs-foot)', marginTop: 4 }}>
            {nothingToUpload
              ? tr('Потрібні JPG, PNG або WebP до {0} МБ', MAX_INPUT_MB)
              : done
              ? (errorCount > 0 ? tr('{0} успішно, {1} з помилкою', doneCount, errorCount) : tr('{0} фото збережено', doneCount))
              : tr('{0} з {1} фото', doneCount, total)
            }
          </div>
        </div>

        {/* ВІДСІЯНЕ ВИДНО ВЕСЬ ЧАС, поки екран відкритий. Тостом це показати не
            можна: стор тримає рівно один, і підсумок завантаження його затирає
            — тобто попередження зникало саме тоді, коли ставало актуальним. */}
        {skipped > 0 && (
          <div className="fr-note" role="status" style={{ justifyContent: 'center', padding: 0 }}>
            <IconAlertTriangle size={14} color="var(--warn-fg)" />
            {skipReason}
          </div>
        )}

        {/* Queue list */}
        {/* Ширина — КЛАСОМ `.photo-queue`, а не інлайном: причина в CSS. */}
        <div className="glass-s photo-queue" style={{ borderRadius: 'var(--r-md)', overflow: 'hidden' }}>
          {queue.map((item, i) => (
            <div
              key={i}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '10px 14px',
                borderBottom: i < queue.length - 1 ? '1px solid rgba(255,255,255,.06)' : 'none',
              }}
            >
              {/* Thumbnail preview */}
              <div style={{
                width: 44, height: 44, borderRadius: 8,
                background: 'var(--glass-2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0, overflow: 'hidden',
                border: item.status === 'error'
                  ? '1.5px solid var(--err-fg)'
                  : item.status === 'done'
                  ? '1.5px solid var(--ok-bright)'
                  : '1.5px solid rgba(255,255,255,.1)',
                transition: 'border-color .3s ease',
              }}>
                {previews[i] ? (
                  <img
                    src={previews[i]}
                    alt=""
                    style={{ width: '100%', height: '100%', objectFit: 'cover',
                      opacity: item.status === 'pending' ? 0.5 : 1,
                      transition: 'opacity .3s ease' }}
                  />
                ) : null}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 'var(--fs-foot)', color: 'var(--t2)', fontWeight: 'var(--fw-med)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {item.file.name}
                </div>
                {/* Та сама геометрія, що `.dash-bar`: волосинка 3px під пігулкою.
                    Число 2 було третьою копією рецепта з власним значенням — на
                    3px пігулка й 2px візуально однакові, але зі шкали бере лише
                    перша. */}
                {item.status === 'uploading' && (
                  <div style={{ marginTop: 4, height: 3, background: 'var(--glass-2)', borderRadius: 'var(--r-pill)', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: '100%', background: 'var(--info)', transformOrigin: 'left', transform: `scaleX(${item.progress / 100})`, transition: 'transform .3s var(--ease)' }} />
                  </div>
                )}
                {item.status === 'error' && item.errorMsg && (
                  <div style={{ marginTop: 2, fontSize: 'var(--fs-cap1)', color: 'var(--err-fg)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.errorMsg}
                  </div>
                )}
                {item.status === 'pending' && (
                  <div style={{ marginTop: 2, fontSize: 'var(--fs-cap1)', color: 'var(--t3)' }}>
                    {(item.file.size / 1024 / 1024).toFixed(1)} MB
                  </div>
                )}
                {item.status === 'done' && (
                  <div style={{ marginTop: 2, fontSize: 'var(--fs-cap1)', color: 'var(--ok-bright)' }}>{tr('Збережено')}</div>
                )}
              </div>
              <div style={{ flexShrink: 0 }}>
                {item.status === 'done' && <IconCheck size={16} color="var(--ok-bright)" />}
                {item.status === 'error' && <IconX size={16} color="var(--err-fg)" />}
                {/* Та сама геометрія, що `.dash-bar`: волосинка 3px під пігулкою.
                    Число 2 було третьою копією рецепта з власним значенням — на
                    3px пігулка й 2px візуально однакові, але зі шкали бере лише
                    перша. */}
                {item.status === 'uploading' && (
                  <div className="loader" style={{ width: 14, height: 14 }} />
                )}
              </div>
            </div>
          ))}
        </div>

        {(done || nothingToUpload) && (
          <button
            className="mbtn mbtn-flow"
            onClick={back}
          >
            {nothingToUpload ? tr('Назад') : tr('Готово')}
          </button>
        )}
      </div>
    </div>
  )
}
