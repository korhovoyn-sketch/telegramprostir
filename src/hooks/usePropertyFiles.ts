'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { assertAffected } from '@/lib/dbWrite'
import { humanizeDbError } from '@/lib/utils'
import type { PropertyFile } from '@/types'
import { tr } from '@/lib/i18n'
import { resolveDocMime } from '@/lib/fileType'

const MAX_FILES = 10
const MAX_SIZE  = 20 * 1024 * 1024
const BUCKET    = 'property-files'

export function usePropertyFiles(propertyId: string | undefined) {
  const [files, setFiles]       = useState<PropertyFile[]>([])
  const [loading, setLoading]   = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState<{ done: number; total: number } | null>(null)
  const [currentUploadFile, setCurrentUploadFile] = useState<string | null>(null)
  // Збій ЗАВАНТАЖЕННЯ списку мусить відрізнятись від «файлів немає»: без цього
  // помилка запиту малювала «Файли ще не додані», і власник міг залити договір,
  // який уже там лежить. Причому мовчки — навіть тоста не було.
  const [loadError, setLoadError] = useState(false)

  const fetchFiles = useCallback(async () => {
    if (!propertyId) return
    setLoading(true)
    setLoadError(false)
    try {
      const { data, error } = await supabase
        .from('property_files')
        .select('id,property_id,owner_id,storage_path,file_name,file_size,mime_type,sort_order,created_at')
        .eq('property_id', propertyId)
        .order('sort_order', { ascending: true })
        .order('created_at',  { ascending: true })
      if (error) { setLoadError(true); return }
      setFiles((data ?? []) as PropertyFile[])
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [propertyId])

  /**
   * Повертає ПІДСУМОК, а не void, і це не косметика: викликач малював
   * «Файл(и) завантажено» беззастережно після `await`, а стор тримає РІВНО
   * ОДИН тост (`toast: Toast | null`) — тобто повідомлення про помилку, щойно
   * надіслане через `onError`, ЗАТИРАЛОСЬ успіхом. Користувач, який приніс
   * .txt, бачив «завантажено».
   */
  const uploadFiles = useCallback(async (
    picked: File[],
    onError: (msg: string) => void
  ): Promise<{ uploaded: number; failed: number }> => {
    if (!propertyId) return { uploaded: 0, failed: picked.length }

    // Guard: query DB for the real current count — avoids stale closure
    // when the user triggers a second upload batch before React re-renders.
    const { count: dbCount } = await supabase
      .from('property_files')
      .select('id', { count: 'exact', head: true })
      .eq('property_id', propertyId)
    let currentCount = dbCount ?? files.length

    // Filter out invalid files before showing progress so total is accurate.
    // Тип РОЗВʼЯЗУЄТЬСЯ, а не читається: `file.type` для .docx законно буває
    // порожнім (див. lib/fileType.ts). Далі по конвеєру йде саме розвʼязане
    // значення — і на сервер, і в колонку.
    // ОДИН НАКОПИЧУВАЧ НА ВЕСЬ ВИКЛИК, а не `onError` у кожній гілці.
    // Стор тримає рівно ОДИН тост — це властивість архітектури, тож поки
    // повідомлення розкидані по шляху виконання, ОСТАННЄ ЗА ЧАСОМ виграє
    // незалежно від важливості. Передперевірка це вже визнавала й агрегувала
    // причини відмови, а цикл завантаження її скасовував шістьма власними
    // викликами: партія `[bad.txt, good.pdf]`, де pdf упав на PUT, показувала
    // лише «Upload failed», і про відхилений формат користувач не дізнавався
    // НІКОЛИ. Правило: у межах однієї дії `onError` кличеться рівно раз, у кінці.
    const problems: string[] = []
    const fail = (msg: string) => { problems.push(msg) }
    const flush = () => {
      if (problems.length === 0) return
      const head = problems.slice(0, 3).join(' · ')
      onError(problems.length > 3
        ? `${head} · ${tr('…і ще {0}', problems.length - 3)}`
        : head)
    }

    const valid: { file: File; mime: string }[] = []
    let overLimit = 0
    for (const file of picked) {
      // ФОРМАТ І РОЗМІР ПЕРЕВІРЯЮТЬСЯ ПЕРШИМИ, і це не стиль: на МЕЖІ порядок
      // визначає ДІАГНОЗ. Поки перевірка місткості стояла попереду, .txt,
      // обраний на повному обʼєкті, чув «Максимум 10 файлів на обʼєкт» —
      // підказку, яка веде НЕ ТУДИ (видалити зайве замість узяти інший файл),
      // і при цьому лишає користувача в упевненості, що формат прийнятний.
      const mime = resolveDocMime(file)
      if (!mime)                { fail(tr('«{0}» — формат не підтримується (тільки PDF, DOC, DOCX)', file.name)); continue }
      if (file.size > MAX_SIZE) { fail(tr('«{0}» перевищує 20 МБ', file.name)); continue }
      if (currentCount + valid.length >= MAX_FILES) { overLimit++; continue }
      valid.push({ file, mime })
    }
    // Межу мовчки не проковтуємо: без цього вибір файлів на вже повному обʼєкті
    // не давав ані завантаження, ані пояснення.
    if (overLimit > 0) fail(tr('Максимум {0} файлів на обʼєкт', MAX_FILES))

    if (!valid.length) { flush(); return { uploaded: 0, failed: picked.length } }

    // Verify ownership before touching storage — prevents orphaned files when RLS
    // blocks the DB insert but the storage upload already succeeded.
    const { data: propRow, error: propErr } = await supabase
      .from('properties')
      .select('owner_id')
      .eq('id', propertyId)
      .single()

    if (propErr || !propRow?.owner_id) {
      fail(tr('Не вдалося підтвердити право власності на обʼєкт'))
      flush()
      return { uploaded: 0, failed: picked.length }
    }

    let uploaded = 0
    setUploading(true)
    setUploadProgress({ done: 0, total: valid.length })
    try {
      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
      const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
      if (!supabaseUrl || !supabaseKey) throw new Error('Supabase config missing')

      // Pass user's JWT so the Edge Function can verify ownership via RLS.
      // БЕЗ СЕСІЇ НЕ ПРОБУЄМО. Раніше тут стояв фолбек на anon-ключ у ролі
      // Bearer: edge-функція користувача не впізнавала й відмовляла, а людина
      // читала «Upload validation failed» — діагноз вів НЕ ТУДИ (шукати
      // проблему в файлі чи мережі замість «ви вийшли з акаунта»). Той самий
      // клас, що й порядок перевірок формату на межі.
      const { data: { session } } = await supabase.auth.getSession()
      if (!session?.access_token) {
        fail(tr('Сесія завершилась — увійдіть знову, щоб завантажити файли'))
        return { uploaded: 0, failed: picked.length }
      }
      const userToken = session.access_token

      for (let i = 0; i < valid.length; i++) {
        const { file, mime } = valid[i]
        if (currentCount >= MAX_FILES) {
          fail(tr('Максимум {0} файлів на обʼєкт', MAX_FILES))
          break
        }

        setCurrentUploadFile(file.name)
        setUploadProgress({ done: i, total: valid.length })

        // ОДИН БЮДЖЕТ ЧАСУ НА ВЕСЬ ФАЙЛ — і валідацію, і сам PUT.
        // Доти 10с стерегли ЛИШЕ виклик, що віддає JSON, а завантаження
        // 20-мегабайтного файлу лишалось без сигналу взагалі: на мертвому
        // зʼєднанні `fetch` висів безкінечно, `uploading` лишався true, і екран
        // замерзав без помилки й без виходу. Фіксовані 10с сюди не годяться —
        // 20 МБ на LTE законно довші; бюджет росте з розміру (≈50 КБ/с — це
        // свідомо ПОВІЛЬНА межа, а не очікувана швидкість), тож вбиває лише
        // справді мертве зʼєднання.
        const budgetMs = 15_000 + Math.ceil(file.size / (50 * 1024)) * 1000
        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), budgetMs)

        try {
          let validateRes
          try {
            validateRes = await fetch(`${supabaseUrl}/functions/v1/validate-upload`, {
              method: 'POST',
              signal: controller.signal,
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${userToken}`,
                'apikey': supabaseKey,
              },
              body: JSON.stringify({
                propertyId,
                fileName: file.name,
                mimeType: mime,
                fileSize: file.size,
              }),
            })
          } catch (err) {
            // Текст — той самий, що бачить користувач, тож через `tr()`.
            // Раніше тут (і в трьох сусідніх гілках) стояла сира англійська:
            // український користувач діставав технічну фразу, а рядок 2 ще й
            // транслював `err.message` — внутрішню деталь у тост.
            fail(err instanceof Error && err.name === 'AbortError'
              ? tr('«{0}» — перевищено час очікування, перевірте зʼєднання', file.name)
              : tr('«{0}» — не вдалося перевірити файл', file.name))
            continue
          }

          if (!validateRes.ok) {
            fail(tr('«{0}» — сервер відхилив файл', file.name))
            continue
          }

          const { uploadUrl, storagePath } = await validateRes.json() as { uploadUrl: string; storagePath: string }
          if (!uploadUrl || !storagePath) {
            fail(tr('«{0}» — некоректна відповідь сервера', file.name))
            continue
          }

          let uploadResult
          try {
            uploadResult = await fetch(uploadUrl, {
              method: 'PUT',
              signal: controller.signal,
              headers: { 'Content-Type': mime, 'x-upsert': 'false' },
              body: file,
            })
          } catch (err) {
            fail(err instanceof Error && err.name === 'AbortError'
              ? tr('«{0}» — перевищено час очікування, перевірте зʼєднання', file.name)
              : tr('«{0}» — не вдалося завантажити', file.name))
            continue
          }

          if (!uploadResult.ok) {
            fail(tr('«{0}» — не вдалося завантажити', file.name))
            continue
          }

          // Record in database
          const { data: row, error: dbErr } = await supabase
            .from('property_files')
            .insert({
              property_id:  propertyId,
              owner_id:     propRow.owner_id,
              storage_path: storagePath,
              file_name:    file.name,
              file_size:    file.size,
              mime_type:    mime,
              sort_order:   currentCount,
            })
            .select('id,property_id,owner_id,storage_path,file_name,file_size,mime_type,sort_order,created_at')
            .single()

          if (dbErr) {
            // ПОРЯДОК ТОЙ САМИЙ, ЩО В `photoUpload.ts`: рядок не зʼявився, отже
            // файл у сховищі нічим не адресований і не стане адресованим ніколи.
            // Прибираємо ОДРАЗУ — «почистимо потім» тут не існує, бо шлях
            // відомий лише в цій ітерації. Доти передперевірка власності
            // обіцяла в коментарі, що осиротілих не буде, але це був лише
            // ПЕРЕДчек: усе, що падає ПІСЛЯ аплоуду, лишало файл назавжди.
            //
            // Перевіряється ДОВЖИНА, а не `error`: `storage.remove()` на
            // схований політикою обʼєкт віддає порожній масив і `error: null`
            // (той самий урок, що в `deletePhoto`/`deleteFile` нижче).
            const { data: removed } = await supabase.storage.from(BUCKET).remove([storagePath])
            if ((removed?.length ?? 0) !== 1) {
              console.warn('[usePropertyFiles] orphan left in storage:', storagePath)
            }
            // `humanizeDbError`, а не сира `message`: та несе назви колонок,
            // констрейнтів і текст RLS-політик просто в тост (правило 1
            // Security rules) — рівно як уже зроблено в `deleteFile` нижче.
            fail(humanizeDbError(dbErr, tr('«{0}» — не збережено', file.name)))
            continue
          }

          setFiles(prev => [...prev, row as PropertyFile])
          setUploadProgress({ done: i + 1, total: valid.length })
          currentCount++
          uploaded++
        } finally {
          clearTimeout(timeout)
        }
      }
    } finally {
      setUploading(false)
      setCurrentUploadFile(null)
      setUploadProgress(null)
      // ОДИН тост на всю партію — і на прийомі, і на завантаженні.
      flush()
    }
    return { uploaded, failed: picked.length - uploaded }
  }, [propertyId, files.length])

  const deleteFile = useCallback(async (
    fileId: string,
    storagePath: string,
    onError: (msg: string) => void
  ) => {
    // Спершу РЯДОК і доказ, що його справді видалено, і лише потім файл.
    // Під RLS заблокований DELETE віддає порожній набір і NULL у `error`, тож
    // без `assertAffected` ми стирали б договір зі сховища, лишаючи рядок
    // живим: власник бачить файл у списку, тапає — і отримує мертве посилання.
    try {
      const { data, error } = await supabase
        .from('property_files').delete().eq('id', fileId).select('id')
      if (error) throw error
      assertAffected(data, 1, tr('видалення файлу'))
    } catch (e) {
      // `humanizeDbError`, а не сира `error.message`: та несе назви колонок,
      // констрейнтів і текст політик просто в тост (правило 1 Security rules).
      onError(humanizeDbError(e))
      return false
    }
    setFiles(prev => prev.filter(f => f.id !== fileId))

    // Той самий контракт, що в `useProperties.deletePhoto`: перевіряємо
    // ДОВЖИНУ, бо схований політикою обʼєкт приходить порожнім масивом без
    // помилки. Раніше тут стояв `.catch(() => {})` — два сусідні шляхи з
    // однаковою семантикою поводились протилежно, і жоден не доводив, що файл
    // зник. Бакет `property-files` ПРИВАТНИЙ, тож осиротілий файл не читається
    // ззовні — звідси мʼякший тон, ніж у фото, але мовчати однаково не можна.
    const { data: removed, error: rmErr } = await supabase.storage
      .from(BUCKET).remove([storagePath])
    if (rmErr || (removed?.length ?? 0) !== 1) {
      onError(tr('Документ прибрано зі списку, але файл лишився у сховищі'))
      // Рядок таки видалено — це часткова невдача, і викликач НЕ має малювати
      // поверх неї «Файл видалено» (єдиний тост у сторі затер би пояснення).
      return false
    }
    return true
  }, [])

  const getSignedUrl = useCallback(async (storagePath: string): Promise<string | null> => {
    const { data, error } = await supabase.storage
      .from(BUCKET)
      .createSignedUrl(storagePath, 3600)
    return error ? null : data.signedUrl
  }, [])

  return {
    files,
    loading,
    loadError,
    uploading,
    uploadProgress,
    currentUploadFile,
    fetchFiles,
    uploadFiles,
    deleteFile,
    getSignedUrl,
    maxFiles: MAX_FILES,
  }
}
