'use client'

import { useState, useEffect, useRef, useMemo } from 'react'
import { useAppStore } from '@/store/appStore'
import { hapticSelection, hapticNotify } from '@/lib/telegram'
import { offlineGuard } from '@/lib/offline'
import { confirmAction } from '@/lib/confirm'
import { useProperties } from '@/hooks/useProperties'
import { useLandlords } from '@/hooks/useLandlords'
import { useFolders } from '@/hooks/useFolders'
import Header from '@/components/ui/Header'
import Toggle from '@/components/ui/Toggle'
import { IconRuler, IconLayers, IconLayoutGrid, IconActivity, IconBuilding, IconCurrencyDollar, IconBolt, IconCarGarage, IconFile, IconUser, IconKey, IconMapPin, IconEdit, IconFolder, IconChevronRight, IconTrash, IconCheck, IconPlus } from '@/components/Icons'
import { UTILITY_META } from '@/lib/utilityMeta'
import FilesList from '@/components/ui/FilesList'
import { currencySymbol, sanitizeDecimal, sanitizeInt, formatPrice, calcRent, calcUtilities, basisArea, rentUnitLabel, nextCopyName, bulkCreateNames, objectsWord, scrollFocusedIntoView } from '@/lib/utils'
import type { PropertyStatus, RentType, ParkingType, AreaBasis } from '@/types'

const PARKING_TYPES: { v: ParkingType; l: string }[] = [
  { v: 'underground', l: 'Підземний' },
  { v: 'covered', l: 'Критий' },
  { v: 'open', l: 'Просто неба' },
]

export default function PropertyFormScreen() {
  const { screenParams, backThenReplace, back, showToast, user, isOnline, databases } = useAppStore()
  const { properties, loadProperties, createProperty, createProperties, updateProperty, deleteProperty, loading } = useProperties(screenParams.dbId)
  const { folders, unavailable: foldersUnavailable, loadFolders, createFolder } = useFolders(screenParams.dbId)

  const editId = screenParams.propertyId
  const isEdit = !!editId
  const existing = properties.find(p => p.id === editId)

  // Duplicate mode: prefill from a source object but stay in create mode.
  const duplicateId = screenParams.duplicateId as string | undefined
  const dupSource = properties.find(p => p.id === duplicateId)
  const dupFilledRef = useRef(false)
  const dupFilledStaleRef = useRef(false)
  // id обʼєкта, яким уже заповнено форму (щоб не префілити повторно)
  const prefilledRef = useRef<string | null>(null)
  // Префіл зроблено з кеш-рядка (`_stale`) — його треба переграти РІВНО ОДИН
  // раз, коли мережа підтвердить свіжий рядок.
  const prefilledStaleRef = useRef(false)
  // Користувач уже щось увів. Тоді переграння префілу СКАСОВУЄТЬСЯ: свіжий рядок
  // не має права затерти введене (саме так виглядає «зміни не зберігаються»).
  const touchedRef = useRef(false)

  // Parking DBs get a spot-oriented field set (number/area/level/type/EV, flat
  // utilities, monthly-or-daily rate) instead of the office/apartment layout.
  const isParking = databases.find(d => d.id === screenParams.dbId)?.type === 'parking'
  // Дефолт бази — для плейсхолдера: порожнє поле має читатись як «успадковано»,
  // а не як «нікого». Пропозиції збираються з уже введених значень власника.
  const dbLandlord = databases.find(d => d.id === screenParams.dbId)?.landlord_name ?? ''
  const { landlords: landlordSuggestions } = useLandlords()

  const [name, setName] = useState('')
  const [floor, setFloor] = useState('')
  const [status, setStatus] = useState<PropertyStatus>('free')
  const [areaUseful, setAreaUseful] = useState('')
  const [areaTotal, setAreaTotal] = useState('')
  // Which area the per-m² rate multiplies by; default розрахункова (total).
  const [areaBasis, setAreaBasis] = useState<AreaBasis>('total')
  const [rentType, setRentType] = useState<RentType>('per_m2')
  const [rentRate, setRentRate] = useState('')
  const [utilitiesRate, setUtilitiesRate] = useState('')
  const [hasParking, setHasParking] = useState(false)
  const [parkingSpaces, setParkingSpaces] = useState('1')
  const [parkingType, setParkingType] = useState<ParkingType | ''>('')
  const [evCharger, setEvCharger] = useState(false)
  const [description, setDescription] = useState('')
  const [salePrice, setSalePrice] = useState('')
  const [tenantName, setTenantName] = useState('')
  const [landlordName, setLandlordName] = useState('')
  const [leaseStartDate, setLeaseStartDate] = useState('')
  const [leaseEndDate, setLeaseEndDate] = useState('')
  const [address, setAddress] = useState('')
  const [utilities, setUtilities] = useState<string[]>([])
  // Папка призначення. Create-режим може успадкувати з контексту (FAB усередині
  // папки передає screenParams.folderId).
  const [folderId, setFolderId] = useState<string | null>((screenParams.folderId as string | undefined) ?? null)
  const [folderOpen, setFolderOpen] = useState(false)
  const [newFolderName, setNewFolderName] = useState('')
  const [addingFolder, setAddingFolder] = useState(false)

  // Створення ЗАВЕРШУЄ вибір: нова папка одразу стає обраною — так само, як
  // це робив пікер до переходу на інлайновий список.
  async function addFolder() {
    const name = newFolderName.trim()
    if (!name || addingFolder) return
    setAddingFolder(true)
    try {
      const created = await createFolder(name)
      if (created) { setFolderId(created.id); setNewFolderName(''); setFolderOpen(false) }
    } finally {
      setAddingFolder(false)
    }
  }
  // Bulk creation: how many objects to create from this one form (create mode
  // only). Names are auto-numbered from the entered name.
  const [count, setCount] = useState(1)
  // Per-row overrides for bulk mode: name '' means «use the auto-numbered
  // name», empty areas fall back to the shared «Площа» fields. Offices on the
  // same floor rarely share a footprint — this lets each row differ without
  // N separate form visits.
  const [bulkRows, setBulkRows] = useState<{ name: string; areaUseful: string; areaTotal: string }[]>([])

  useEffect(() => {
    setBulkRows(prev => {
      if (count <= 1) return []
      const next = prev.slice(0, count)
      while (next.length < count) next.push({ name: '', areaUseful: '', areaTotal: '' })
      return next
    })
  }, [count])

  useEffect(() => {
    if (screenParams.dbId) loadFolders(screenParams.dbId)
  }, [screenParams.dbId, loadFolders])

  useEffect(() => {
    const tg = window.Telegram?.WebApp
    tg?.enableClosingConfirmation()
    return () => { tg?.disableClosingConfirmation() }
  }, [])

  // ── Draft autosave (new object only) ────────────────────────────────────────
  // Closing confirmation guards against an accidental swipe-down, but a crash
  // or webview kill still loses typed input — the draft in localStorage
  // survives that. Restored automatically; «Очистити» in the toast discards.
  const isNewBlank = !isEdit && !duplicateId
  const draftKey = user && screenParams.dbId ? `draft_v1:${user.id}:prop-new:${screenParams.dbId}` : null
  const draftReadyRef = useRef(false)

  useEffect(() => {
    if (!isNewBlank || !draftKey || draftReadyRef.current) return
    draftReadyRef.current = true
    try {
      const raw = localStorage.getItem(draftKey)
      if (!raw) return
      const d = JSON.parse(raw) as Record<string, unknown>
      if (!d || typeof d !== 'object' || !(d.name || d.description || d.rentRate)) return
      setName(String(d.name ?? ''))
      setFloor(String(d.floor ?? ''))
      setStatus((d.status as PropertyStatus) ?? 'free')
      setAreaUseful(String(d.areaUseful ?? ''))
      setAreaTotal(String(d.areaTotal ?? ''))
      setAreaBasis((d.areaBasis as AreaBasis) ?? 'total')
      setRentType((d.rentType as RentType) ?? 'per_m2')
      setRentRate(String(d.rentRate ?? ''))
      setUtilitiesRate(String(d.utilitiesRate ?? ''))
      setHasParking(Boolean(d.hasParking))
      setParkingSpaces(String(d.parkingSpaces ?? '1'))
      setParkingType((d.parkingType as ParkingType | '') ?? '')
      setEvCharger(Boolean(d.evCharger))
      setDescription(String(d.description ?? ''))
      setSalePrice(String(d.salePrice ?? ''))
      setTenantName(String(d.tenantName ?? ''))
      setLeaseStartDate(String(d.leaseStartDate ?? ''))
      setLeaseEndDate(String(d.leaseEndDate ?? ''))
      setAddress(String(d.address ?? ''))
      setUtilities(Array.isArray(d.utilities) ? (d.utilities as string[]) : [])
      setFolderId((d.folderId as string | null) ?? null)
      showToast({
        type: 'info',
        title: 'Чернетку відновлено',
        subtitle: 'Незбережений обʼєкт з минулого разу',
        actionLabel: 'Очистити',
        onAction: () => {
          localStorage.removeItem(draftKey)
          setName(''); setFloor(''); setStatus('free'); setAreaUseful(''); setAreaTotal(''); setAreaBasis('total')
          setRentType('per_m2'); setRentRate(''); setUtilitiesRate(''); setHasParking(false)
          setParkingSpaces('1'); setParkingType(''); setEvCharger(false); setDescription('')
          setSalePrice(''); setTenantName(''); setLeaseStartDate(''); setLeaseEndDate('')
          setAddress(''); setUtilities([]); setFolderId(null)
        },
      })
    } catch { /* corrupted draft — ignore */ }
  }, [isNewBlank, draftKey, showToast])

  useEffect(() => {
    if (!isNewBlank || !draftKey || !draftReadyRef.current) return
    const t = setTimeout(() => {
      try {
        if (name.trim() || description.trim() || rentRate) {
          localStorage.setItem(draftKey, JSON.stringify({
            name, floor, status, areaUseful, areaTotal, areaBasis, rentType, rentRate,
            utilitiesRate, hasParking, parkingSpaces, parkingType, evCharger,
            description, salePrice, tenantName, leaseStartDate, leaseEndDate,
            address, utilities, folderId,
          }))
        } else {
          localStorage.removeItem(draftKey)
        }
      } catch { /* quota — best-effort */ }
    }, 600)
    return () => clearTimeout(t)
  }, [isNewBlank, draftKey, name, floor, status, areaUseful, areaTotal, areaBasis, rentType,
      rentRate, utilitiesRate, hasParking, parkingSpaces, parkingType, evCharger,
      description, salePrice, tenantName, leaseStartDate, leaseEndDate, address, utilities, folderId])

  useEffect(() => {
    // Префіл РІВНО ОДИН раз на обʼєкт. Ефект залежить від `existing`, а це
    // обʼєкт зі списку properties — будь-яке фонове оновлення списку давало
    // нову ідентичність, ефект перезапускався і ЗАТИРАВ уже введений текст
    // значеннями з БД (користувач бачив «зміни не зберігаються»).
    //
    // Виняток — рівно одне переграння: перший кадр списку може прийти з SWR-кешу
    // (`_stale`), і префіл з нього показав би СТАРУ ставку. Коли мережа
    // підтверджує рядок, заповнюємо ще раз — далі знову жодного разу. Але якщо
    // користувач уже почав правити, переграння скасовується: краще показати
    // введене ним, ніж «випадково» відкотити на серверне.
    const upgradeFromStale = prefilledStaleRef.current && !existing?._stale && !touchedRef.current
    if (isEdit && existing && (prefilledRef.current !== existing.id || upgradeFromStale)) {
      prefilledRef.current = existing.id
      prefilledStaleRef.current = !!existing._stale
      setName(existing.name)
      setFloor(existing.floor ?? '')
      setStatus(existing.status)
      setAreaUseful(String(existing.area_useful ?? ''))
      setAreaTotal(String(existing.area_total ?? ''))
      setAreaBasis(existing.area_basis ?? 'total')
      setRentType(existing.rent_type)
      setRentRate(String(existing.rent_rate ?? ''))
      setUtilitiesRate(String(existing.utilities_rate ?? ''))
      setHasParking(existing.has_parking)
      setParkingSpaces(String(existing.parking_spaces))
      setParkingType(existing.parking_type ?? '')
      setEvCharger(existing.ev_charger ?? false)
      setDescription(existing.description ?? '')
      setAddress(existing.address ?? '')
      setUtilities(existing.utilities ?? [])
      setSalePrice(String(existing.sale_price ?? ''))
      setTenantName(existing.tenant_name ?? '')
      setLandlordName(existing.landlord_name ?? '')
      setLeaseStartDate(existing.lease_start_date ?? '')
      setLeaseEndDate(existing.lease_end_date ?? '')
      setFolderId(existing.folder_id ?? null)
    } else if (isEdit) {
      loadProperties(screenParams.dbId)
    }
  }, [isEdit, existing, screenParams.dbId, loadProperties])

  // Create mode also needs the existing list: bulk naming skips taken names
  // and batch sort_order continues from the current maximum — both are wrong
  // against an empty list. SWR cache makes this paint-cheap.
  useEffect(() => {
    if (!isEdit && !duplicateId && screenParams.dbId) loadProperties(screenParams.dbId)
  }, [isEdit, duplicateId, screenParams.dbId, loadProperties])

  // Duplicate prefill — everything except tenant/lease/photos/files: a copy
  // starts free. Runs once (ref-guarded) so typing is never overwritten.
  useEffect(() => {
    if (isEdit || !duplicateId) return
    // Те саме одне переграння, що і в edit-режимі: копія, знята з кеш-рядка,
    // мусить оновитись, коли приїде свіже джерело.
    if (dupFilledRef.current && !(dupFilledStaleRef.current && !dupSource?._stale)) return
    if (!dupSource) { loadProperties(screenParams.dbId); return }
    dupFilledRef.current = true
    dupFilledStaleRef.current = !!dupSource._stale
    setName(nextCopyName(dupSource.name, properties.map(p => p.name)))
    setFloor(dupSource.floor ?? '')
    setStatus('free')
    setAreaUseful(String(dupSource.area_useful ?? ''))
    setAreaTotal(String(dupSource.area_total ?? ''))
    setAreaBasis(dupSource.area_basis ?? 'total')
    setRentType(dupSource.rent_type)
    setRentRate(String(dupSource.rent_rate ?? ''))
    setUtilitiesRate(String(dupSource.utilities_rate ?? ''))
    setHasParking(dupSource.has_parking)
    setParkingSpaces(String(dupSource.parking_spaces))
    setParkingType(dupSource.parking_type ?? '')
    setEvCharger(dupSource.ev_charger ?? false)
    setDescription(dupSource.description ?? '')
    setAddress(dupSource.address ?? '')
    setUtilities(dupSource.utilities ?? [])
    setSalePrice(String(dupSource.sale_price ?? ''))
    setFolderId(dupSource.folder_id ?? null)
  }, [isEdit, duplicateId, dupSource, properties, screenParams.dbId, loadProperties])

  // Parking rate is monthly-per-spot or daily — never $/m². Default a new
  // parking spot to a fixed monthly rate so the per_m2 office default never
  // leaks into a parking form (where that segment isn't even shown).
  useEffect(() => {
    if (isParking && !isEdit && rentType === 'per_m2') setRentType('fixed')
  }, [isParking, isEdit, rentType])

  // Only per_m2 needs a useful area to multiply; fixed (monthly) and per_day
  // (daily) are the rate itself, so don't gate them on area.
  const previewArea = basisArea(parseFloat(areaUseful) || undefined, parseFloat(areaTotal) || undefined, areaBasis)
  const rentCalc = parseFloat(rentRate) && (rentType !== 'per_m2' || previewArea)
    ? calcRent(previewArea, parseFloat(rentRate), rentType)
    : 0
  // Превʼю гейтилось на `areaTotal` — тобто на площі, якої обʼєкт із базою
  // «корисна» може не мати взагалі, і тоді форма показувала 0, картка $3, а
  // правильна відповідь була $125. ТРИ різні числа за той самий рядок.
  // Тепер обидві поверхні рахують ОДНИМ виразом: пласко для паркінга,
  // ставка × базова площа для решти.
  const utilsRateNum = parseFloat(utilitiesRate) || 0
  const utilsCalc = isParking
    ? utilsRateNum
    : (previewArea && utilsRateNum ? calcUtilities(previewArea, utilsRateNum) : 0)
  // A daily rate and a monthly utilities charge aren't the same unit — only sum
  // them into a monthly total when the rent itself is monthly.
  const total = rentType === 'per_day' ? 0 : rentCalc + utilsCalc

  function toggleUtility(id: string) {
    hapticSelection()
    setUtilities(prev =>
      prev.includes(id) ? prev.filter(u => u !== id) : [...prev, id]
    )
  }

  const canSave = name.trim().length > 0

  const BULK_MAX = 50
  const bulkNames = useMemo(
    () => (!isEdit && count > 1 && name.trim()
      ? bulkCreateNames(name, count, properties.map(p => p.name))
      : null),
    [isEdit, count, name, properties],
  )
  const saveLabel = isEdit
    ? 'Зберегти зміни'
    : count > 1 ? `Додати ${count} ${objectsWord(count)}` : 'Додати обʼєкт'

  // Returns the numeric value, or undefined if string is empty/invalid.
  // Avoids the `parseFloat('0') || undefined` pitfall where 0 is silently dropped.
  function numOrUndef(s: string): number | undefined {
    if (s.trim() === '') return undefined
    const n = parseFloat(s)
    return isNaN(n) ? undefined : n
  }

  async function handleDeleteProperty() {
    if (!editId) return
    const ok = await confirmAction({
      title: 'Видалити обʼєкт?',
      message: `Обʼєкт "${name}" буде видалено. Це незворотно.`,
      confirmLabel: 'Видалити',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    await deleteProperty(editId, screenParams.dbId!)
  }

  async function handleSave() {
    if (!canSave || !screenParams.dbId) return
    if (!isOnline) hapticNotify('error')
    if (offlineGuard()) return

    // Reject non-numeric values the browser's number input allows on some Android keyboards
    if (areaUseful && numOrUndef(areaUseful) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Корисна площа — лише число' }); return
    }
    if (areaTotal && numOrUndef(areaTotal) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Розрахункова площа — лише число' }); return
    }
    if (rentRate && numOrUndef(rentRate) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Орендна ставка — лише число' }); return
    }
    if (utilitiesRate && numOrUndef(utilitiesRate) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Ставка експлуатаційних — лише число' }); return
    }

    if (status === 'for_sale' && salePrice && numOrUndef(salePrice) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Ціна продажу — лише число' }); return
    }

    const au = numOrUndef(areaUseful) ?? 0
    const at = numOrUndef(areaTotal) ?? 0
    const rr = numOrUndef(rentRate) ?? 0
    const ur = numOrUndef(utilitiesRate) ?? 0
    const sp = numOrUndef(salePrice) ?? 0
    if (au < 0 || at < 0 || rr < 0 || ur < 0 || sp < 0) {
      showToast({ type: 'error', title: 'Значення не може бути відʼємним' })
      return
    }
    if (au > 0 && at > 0 && au > at) {
      showToast({ type: 'error', title: 'Корисна площа більша за розрахункову' })
      return
    }
    if (status === 'occupied' && leaseStartDate && leaseEndDate && leaseEndDate < leaseStartDate) {
      showToast({ type: 'error', title: 'Дата закінчення оренди раніше початку' })
      return
    }
    hapticNotify('success')
    // ПОРОЖНЄ ПОЛЕ В РЕЖИМІ РЕДАГУВАННЯ — ЦЕ `null`, А НЕ `undefined`.
    // `JSON.stringify` викидає ключі зі значенням `undefined`, тобто такий ключ
    // просто НЕ ПОТРАПЛЯЄ в тіло PATCH, і колонка лишається старою. Форма при
    // цьому рапортує «Збережено», а після повторного відкриття значення
    // повертається — очистити поверх раз заповнене поле було неможливо взагалі.
    // У create-режимі `undefined` навпаки правильний: він віддає колонку її
    // DEFAULT-у.
    const blank = <T,>(v: T | undefined): T | null | undefined => (isEdit ? (v ?? null) : v)
    const payload = {
      db_id: screenParams.dbId!,
      name: name.trim(),
      floor: blank(floor.trim() || undefined),
      address: blank(address.trim() || undefined),
      status,
      // Пропускаємо, коли папки недоступні на бекенді (043 не застосовано) —
      // useProperties однаково зріже folder_id, але не варто слати зайве.
      folder_id: foldersUnavailable ? undefined : folderId,
      area_useful: blank(numOrUndef(areaUseful)),
      // A parking spot has a single area; the office useful/total split doesn't apply.
      area_total: isParking ? blank(undefined) : blank(numOrUndef(areaTotal)),
      // A parking spot has one area, so its basis is always that area (useful).
      area_basis: isParking ? 'useful' : areaBasis,
      rent_type: rentType,
      rent_rate: blank(numOrUndef(rentRate)),
      utilities_rate: blank(numOrUndef(utilitiesRate)),
      // A parking spot never "has parking" of its own and carries no utility tags.
      has_parking: isParking ? false : hasParking,
      // Clearing the field leaves parkingSpaces '' → parseInt is NaN; floor to 1.
      parking_spaces: !isParking && hasParking ? Math.max(1, parseInt(parkingSpaces, 10) || 1) : 0,
      parking_type: isParking ? (parkingType || null) : null,
      ev_charger: isParking ? evCharger : false,
      utilities: !isParking && utilities.length > 0 ? utilities : null,
      description: blank(description.trim() || undefined),
      sale_price: status === 'for_sale' ? blank(numOrUndef(salePrice)) : null,
      tenant_name: status === 'occupied' ? blank(tenantName.trim() || undefined) : null,
      // БЕЗ статусного гейта і БЕЗ нулювання: орендодавець переживає і зміну
      // орендаря, і звільнення обʼєкта. Порожнє поле = «як у базі» (успадкування),
      // тож пишемо undefined→null через `blank`, а не порожній рядок.
      landlord_name: blank(landlordName.trim() || undefined),
      lease_start_date: status === 'occupied' ? blank(leaseStartDate || undefined) : null,
      lease_end_date: status === 'occupied' ? blank(leaseEndDate || undefined) : null,
    }

    if (isEdit && editId) {
      await updateProperty(editId, payload)
      // Повертаємось РІВНО туди, звідки відкрили форму.
      // • з екрана обʼєкта → backThenReplace: знімає попередній (той самий)
      //   екран деталей і ставить свіжий, щоб у history не було дубля;
      // • зі списку обʼєктів (кнопка «Редагувати» на картці) → просто back:
      //   раніше тут теж стояв backThenReplace('property-detail') і він ЗʼЇДАВ
      //   зі стека сам список — Back з деталей стрибав аж у список баз.
      if (useAppStore.getState().history.at(-1)?.screen === 'property-detail') {
        backThenReplace('property-detail', { propertyId: editId, dbId: screenParams.dbId })
      } else {
        back()
      }
    } else if (count > 1 && bulkNames) {
      // Bulk: shared fields + per-row overrides (name, areas). Empty row
      // fields fall back to the shared values from the form.
      const finalNames = bulkNames.map((auto, i) => (bulkRows[i]?.name.trim() || auto))
      const existingNames = new Set(properties.map(p => p.name))
      const seen = new Set<string>()
      for (const n of finalNames) {
        if (seen.has(n) || existingNames.has(n)) {
          showToast({ type: 'error', title: 'Імʼя повторюється', subtitle: `«${n}» вже існує або вжито двічі` })
          return
        }
        seen.add(n)
      }

      const rows: { au?: number; at?: number }[] = []
      for (let i = 0; i < count; i++) {
        const rawAu = bulkRows[i]?.areaUseful ?? ''
        const rawAt = bulkRows[i]?.areaTotal ?? ''
        if (rawAu && numOrUndef(rawAu) === undefined) {
          showToast({ type: 'error', title: 'Некоректне значення', subtitle: `${finalNames[i]}: площа — лише число` }); return
        }
        if (rawAt && numOrUndef(rawAt) === undefined) {
          showToast({ type: 'error', title: 'Некоректне значення', subtitle: `${finalNames[i]}: площа — лише число` }); return
        }
        const rowAu = numOrUndef(rawAu) ?? numOrUndef(areaUseful)
        const rowAt = isParking ? undefined : (numOrUndef(rawAt) ?? numOrUndef(areaTotal))
        if ((rowAu ?? 0) < 0 || (rowAt ?? 0) < 0) {
          showToast({ type: 'error', title: 'Значення не може бути відʼємним', subtitle: finalNames[i] }); return
        }
        if (rowAu && rowAt && rowAu > rowAt) {
          showToast({ type: 'error', title: 'Корисна площа більша за розрахункову', subtitle: finalNames[i] }); return
        }
        rows.push({ au: rowAu, at: rowAt })
      }

      // The whole batch shares one created_at (single INSERT), so give rows
      // explicit sort_order — otherwise their list order is arbitrary.
      const sortBase = Math.max(0, ...properties.map(p => p.sort_order ?? 0))
      const ok = await createProperties(finalNames.map((n, i) => ({
        ...payload,
        name: n,
        area_useful: rows[i].au,
        area_total: rows[i].at,
        sort_order: sortBase + (i + 1) * 100,
      })))
      if (ok && draftKey) localStorage.removeItem(draftKey)
    } else {
      const ok = await createProperty(payload)
      if (ok && draftKey) localStorage.removeItem(draftKey)
    }
  }

  return (
    <div className="scr bg-blue">
      <Header
        title={isEdit ? 'Редагування' : 'Новий обʼєкт'}
        backLabel={isEdit ? 'Назад' : 'База'}
        right={
          isEdit ? (
            <button
              className="hdr-a"
              aria-label="Видалити обʼєкт"
              onClick={handleDeleteProperty}
              style={{ background: 'none', border: 'var(--bd)', color: 'var(--err)' }}
            >
              <IconTrash size={16} />
            </button>
          ) : <div className="hdr-sp" />
        }
      />

      <div
        className="body has-flow-cta"
        onFocusCapture={scrollFocusedIntoView}
        onInputCapture={() => { touchedRef.current = true }}
      >
        {/* Basic */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBuilding size={14} color="var(--info)" />Основне</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconEdit size={14} color="var(--t3)" />{isParking ? 'Номер місця' : 'Назва'}</span>
            <input aria-label={isParking ? 'Номер місця' : 'Назва обʼєкта'} className="fr-i" placeholder={isParking ? '№ 42, A-15' : 'Офіс 101'} maxLength={100} value={name} onChange={e => setName(e.target.value)} autoFocus={!isEdit} />
          </div>
          {!isEdit && (
            <div className="fr">
              <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <IconLayoutGrid size={14} color="var(--t3)" />Кількість
              </span>
              {/* marginLeft:auto — контрол праворуч, як інпути/сегменти сусідніх рядків */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginLeft: 'auto' }}>
                <button
                  aria-label="Менше обʼєктів"
                  onClick={() => { hapticSelection(); setCount(c => Math.max(1, c - 1)) }}
                  disabled={count <= 1}
                  style={{
                    width: 32, height: 32, borderRadius: 'var(--r-xs)',
                    background: 'var(--glass-2)', border: '.5px solid var(--glass-bd)',
                    color: count <= 1 ? 'var(--t4)' : 'var(--t1)',
                    fontSize: 'var(--fs-lead)', lineHeight: 1, cursor: 'pointer',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}
                >−</button>
                <span className="num" style={{ minWidth: 28, textAlign: 'center', fontSize: 'var(--fs-call)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)' }}>{count}</span>
                <button
                  aria-label="Більше обʼєктів"
                  onClick={() => { hapticSelection(); setCount(c => Math.min(BULK_MAX, c + 1)) }}
                  disabled={count >= BULK_MAX}
                  style={{
                    width: 32, height: 32, borderRadius: 'var(--r-xs)',
                    background: 'var(--glass-2)', border: '.5px solid var(--glass-bd)',
                    color: count >= BULK_MAX ? 'var(--t4)' : 'var(--t1)',
                    fontSize: 'var(--fs-lead)', lineHeight: 1, cursor: 'pointer',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}
                >+</button>
              </div>
            </div>
          )}
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconLayers size={14} color="var(--t3)" />{isParking ? 'Рівень / поверх' : 'Поверх'}</span>
            <input aria-label={isParking ? 'Рівень' : 'Поверх'} className="fr-i" type="text" inputMode="text" placeholder={isParking ? '-1, 2, підвал' : '1, 2, B-1, МП'} maxLength={20} value={floor} onChange={e => setFloor(e.target.value)} />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconMapPin size={14} color="var(--t3)" />Адреса</span>
            <input aria-label="Адреса" className="fr-i" type="text" placeholder="вул. Хрещатик, 1" maxLength={200} value={address} onChange={e => setAddress(e.target.value)} />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconActivity size={14} color="var(--t3)" />Статус</span>
            <div className="fr-seg" style={{ maxWidth: 200 }}>
              {([
                { v: 'free', l: 'Вільно' },
                { v: 'occupied', l: 'Зайнято' },
                { v: 'for_sale', l: 'Продаж' },
              ] as const).map(({ v, l }) => (
                <button type="button" key={v} className={`fr-seg-b ${status === v ? 'on' : ''}`} onClick={() => { hapticSelection(); setStatus(v) }}>{l}</button>
              ))}
            </div>
          </div>
          {/* Вибір папки — ІНЛАЙНОВИЙ, а не шит і не окремий екран. Причина
              структурна: значення потрібне НЕЗБЕРЕЖЕНІЙ формі, а перехід на
              інший маршрут розмонтував би її разом з усіма правками (чернетка
              є лише в режимі створення). Оверлея тут теж не треба — це
              звичайне поле форми, і клавіатура для «нової папки» працює як у
              будь-якого іншого поля екрана. */}
          {!foldersUnavailable && (
            <>
              <button
                type="button"
                className="fr fr-tap"
                aria-expanded={folderOpen}
                onClick={() => { hapticSelection(); setFolderOpen(o => !o) }}
              >
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconFolder size={14} color="var(--t3)" />Папка</span>
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4, color: folderId ? 'var(--t1)' : 'var(--t3)', fontSize: 'var(--fs-call)' }}>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>
                    {folders.find(f => f.id === folderId)?.name ?? 'Без папки'}
                  </span>
                  <span style={{ display: 'flex', transform: folderOpen ? 'rotate(90deg)' : 'none', transition: 'transform var(--dur-sm) var(--ease-out)' }}>
                    <IconChevronRight size={16} color="var(--t4)" />
                  </span>
                </div>
              </button>
              {folderOpen && (
                <>
                  <button
                    type="button"
                    className="fr fr-tap fr-sub"
                    onClick={() => { hapticSelection(); setFolderId(null); setFolderOpen(false) }}
                  >
                    <span className="fr-l">Без папки</span>
                    {folderId === null && <span style={{ marginLeft: 'auto', display: 'flex' }}><IconCheck size={16} color="var(--ok)" /></span>}
                  </button>
                  {folders.map(f => (
                    <button
                      key={f.id}
                      type="button"
                      className="fr fr-tap fr-sub"
                      onClick={() => { hapticSelection(); setFolderId(f.id); setFolderOpen(false) }}
                    >
                      <span className="fr-l">{f.name}</span>
                      {folderId === f.id && <span style={{ marginLeft: 'auto', display: 'flex' }}><IconCheck size={16} color="var(--ok)" /></span>}
                    </button>
                  ))}
                  <div className="fr fr-sub">
                    <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconPlus size={14} color="var(--t3)" />Нова</span>
                    <input
                      className="fr-i"
                      aria-label="Назва нової папки"
                      placeholder="Назва папки…"
                      value={newFolderName}
                      maxLength={40}
                      onChange={(e) => setNewFolderName(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void addFolder() } }}
                    />
                    <button
                      type="button"
                      className="fr-add"
                      aria-label="Додати папку"
                      disabled={!newFolderName.trim() || addingFolder}
                      onClick={() => void addFolder()}
                    >
                      <IconCheck size={16} />
                    </button>
                  </div>
                </>
              )}
            </>
          )}
          {/* ОРЕНДОДАВЕЦЬ — той, хто ЗДАЄ. Свідомо ПОЗА гілкою
              `status === 'occupied'`: це властивість самого простору, а не
              орендних відносин, тож він лишається й на вільному обʼєкті, і на
              виставленому на продаж. З тієї ж причини його НЕ нулює збереження
              поза статусом «Зайнято» (на відміну від орендаря нижче).

              Порожнє поле означає «як у базі» — плейсхолдер показує успадковане
              значення, тож стан читається без окремого підпису.

              Підпис саме «Орендодавець», а не «Найменування»: рядок орендаря
              нижче вже так називається, і два ВІЗУАЛЬНО ІДЕНТИЧНІ підписи в
              одній формі розрізнялись би лише оверлайном секції. Заодно рядок
              живе тут, а не власною секцією: та зсувала весь блок площі нижче в
              градієнті, який світлішає донизу, — і «м²» падало під WCAG AA.

              А ОСТАННІМ рядком секції він стоїть з тієї ж причини, заміряної
              вдруге: поставлений вище (одразу після Адреси) він зсував пікер
              папок на 48px, і «Без папки» падало на 4.22:1. Тобто місце рядка
              у формі — це не смак, а бюджет контрасту для всього, що НИЖЧЕ. */}
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconUser size={14} color="var(--t3)" />Орендодавець</span>
            <input
              aria-label="Орендодавець"
              className="fr-i"
              placeholder={dbLandlord || 'ТОВ «Назва» або ФОП'}
              maxLength={200}
              value={landlordName}
              onChange={e => setLandlordName(e.target.value)}
              list={landlordSuggestions.length > 0 ? 'landlord-options' : undefined}
            />
            {landlordSuggestions.length > 0 && (
              <datalist id="landlord-options">
                {landlordSuggestions.map((l) => <option key={l} value={l} />)}
              </datalist>
            )}
          </div>
        </div>

        {/* Bulk rows: per-object name + areas; everything else is shared.
            Empty fields inherit the auto name / shared «Площа» values shown
            as placeholders. */}
        {bulkNames && (
          <>
            <div className="over">
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <IconLayoutGrid size={14} color="var(--info)" />Буде створено
              </span>
              <span className="over-a">{count} {objectsWord(count)}</span>
            </div>
            <div
              className="fg glass-s"
              style={{
                margin: '0 12px 16px', padding: '4px 0',
                maxHeight: 332, overflowY: 'auto',
                overscrollBehavior: 'contain', WebkitOverflowScrolling: 'touch',
              }}
            >
              {bulkNames.map((auto, i) => {
                const row = bulkRows[i] ?? { name: '', areaUseful: '', areaTotal: '' }
                const setRow = (patch: Partial<typeof row>) =>
                  setBulkRows(prev => prev.map((r, j) => (j === i ? { ...r, ...patch } : r)))
                const inputStyle: React.CSSProperties = {
                  width: 62, padding: '7px 8px', textAlign: 'right',
                  fontSize: 'var(--fs-call)', color: 'var(--t1)',
                  background: 'var(--glass-2)', border: '.5px solid var(--glass-bd)',
                  borderRadius: 'var(--r-xs)',
                }
                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 12px' }}>
                    <input
                      aria-label={`Назва обʼєкта ${i + 1}`}
                      style={{ ...inputStyle, flex: 1, width: 'auto', minWidth: 0, textAlign: 'left' }}
                      placeholder={auto}
                      maxLength={100}
                      value={row.name}
                      onChange={e => setRow({ name: e.target.value })}
                    />
                    <input
                      aria-label={`Корисна площа обʼєкта ${i + 1}`}
                      className="num"
                      style={inputStyle}
                      type="text" inputMode="decimal"
                      placeholder={areaUseful || '—'}
                      value={row.areaUseful}
                      onChange={e => setRow({ areaUseful: sanitizeDecimal(e.target.value) })}
                    />
                    {!isParking && (
                      <>
                        <span style={{ color: 'var(--t4)', fontSize: 'var(--fs-cap1)' }}>/</span>
                        <input
                          aria-label={`Розрахункова площа обʼєкта ${i + 1}`}
                          className="num"
                          style={inputStyle}
                          type="text" inputMode="decimal"
                          placeholder={areaTotal || '—'}
                          value={row.areaTotal}
                          onChange={e => setRow({ areaTotal: sanitizeDecimal(e.target.value) })}
                        />
                      </>
                    )}
                    <span style={{ color: 'var(--t3)', fontSize: 'var(--fs-cap1)', flexShrink: 0 }}>м²</span>
                  </div>
                )
              })}
            </div>
          </>
        )}

        {/* Sale price — shown only when for_sale */}
        {status === 'for_sale' && (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCurrencyDollar size={14} color="var(--ok-fg)" />Продаж</span></div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconCurrencyDollar size={14} color="var(--t3)" />Ціна продажу</span>
                <input aria-label="Ціна продажу" className="fr-i" type="text" inputMode="decimal" maxLength={12} placeholder="150000" value={salePrice} onChange={e => setSalePrice(sanitizeDecimal(e.target.value))} />
                <span className="fr-u">{currencySymbol(user?.currency)}</span>
              </div>
            </div>
          </>
        )}

        {/* Tenant info — shown only when occupied */}
        {status === 'occupied' && (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconUser size={14} color="var(--violet)" />Орендар</span></div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconUser size={14} color="var(--t3)" />Найменування</span>
                <input aria-label="Орендар" className="fr-i" placeholder="ТОВ «Назва» або ФОП Іванов" maxLength={200} value={tenantName} onChange={e => setTenantName(e.target.value)} />
              </div>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconKey size={14} color="var(--t3)" />Договір з</span>
                <input aria-label="Договір від" className="fr-i" type="date" lang="uk-UA" value={leaseStartDate} onChange={e => setLeaseStartDate(e.target.value)}
                  style={{ colorScheme: 'dark' }} />
              </div>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconKey size={14} color="var(--t3)" />Договір до</span>
                <input aria-label="Договір до" className="fr-i" type="date" lang="uk-UA" value={leaseEndDate} onChange={e => setLeaseEndDate(e.target.value)}
                  style={{ colorScheme: 'dark' }} />
              </div>
            </div>
          </>
        )}

        {/* Area */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconRuler size={14} color="var(--info)" />Площа</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconRuler size={14} color="var(--t3)" />{isParking ? 'Площа місця' : 'Корисна'}</span>
            <input aria-label="Корисна площа, м²" className="fr-i" type="text" inputMode="decimal" placeholder={isParking ? '13.5' : '47'} value={areaUseful} onChange={e => setAreaUseful(sanitizeDecimal(e.target.value))} />
            <span className="fr-u">м²</span>
          </div>
          {!isParking && (
            <div className="fr">
              <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconRuler size={14} color="var(--t3)" />Розрахункова</span>
              <input aria-label="Розрахункова площа, м²" className="fr-i" type="text" inputMode="decimal" placeholder="52" value={areaTotal} onChange={e => setAreaTotal(sanitizeDecimal(e.target.value))} />
              <span className="fr-u">м²</span>
            </div>
          )}
          {/* Which area the per-m² rate (rent AND expenses) multiplies by.
              `fr-stack` — підпис НАД сегментом, не поруч. Заміряно: у рядку
              349px підпис зʼїдає 120, сегменту лишається 191, тобто 84px на
              підпис, який потребує 93 — і ellipsis різав саме те слово, яким
              обирають базу розрахунку («Розрахунково…»). `maxWidth` тут не
              допомагає в принципі: він обмежує згори, а не додає ширини. */}
          {!isParking && (
            <div className="fr fr-stack">
              <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 0 }}><IconRuler size={14} color="var(--t3)" />Рахувати від</span>
              <div className="fr-seg">
                <button type="button" className={`fr-seg-b ${areaBasis === 'useful' ? 'on' : ''}`} onClick={() => { hapticSelection(); setAreaBasis('useful') }}>Корисної</button>
                <button type="button" className={`fr-seg-b ${areaBasis === 'total' ? 'on' : ''}`} onClick={() => { hapticSelection(); setAreaBasis('total') }}>Розрахункової</button>
              </div>
            </div>
          )}
        </div>

        {/* Rent */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCurrencyDollar size={14} color="var(--ok-fg)" />Орендна ставка</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Тип</span>
            <div className="fr-seg" style={{ maxWidth: 180 }}>
              {isParking ? (
                <>
                  <button type="button" className={`fr-seg-b ${rentType === 'fixed' ? 'on' : ''}`} onClick={() => { hapticSelection(); setRentType('fixed') }}>За місяць</button>
                  <button type="button" className={`fr-seg-b ${rentType === 'per_day' ? 'on' : ''}`} onClick={() => { hapticSelection(); setRentType('per_day') }}>Подобово</button>
                </>
              ) : (
                <>
                  <button type="button" className={`fr-seg-b ${rentType === 'per_m2' ? 'on' : ''}`} onClick={() => { hapticSelection(); setRentType('per_m2') }}>{currencySymbol(user?.currency)} за м²</button>
                  <button type="button" className={`fr-seg-b ${rentType === 'fixed' ? 'on' : ''}`} onClick={() => { hapticSelection(); setRentType('fixed') }}>Фікс. сума</button>
                </>
              )}
            </div>
          </div>
          <div className="fr hi-row">
            <span className="fr-l">{rentType === 'per_m2' ? 'Ставка' : 'Сума'}</span>
            <input aria-label={rentType === 'per_m2' ? 'Орендна ставка за м²' : 'Сума оренди'} className="fr-i" type="text" inputMode="decimal" placeholder={rentType === 'per_day' ? '150' : '18'} value={rentRate} onChange={e => setRentRate(sanitizeDecimal(e.target.value))} />
            <span className="fr-u">{currencySymbol(user?.currency)}{rentUnitLabel(rentType)}</span>
          </div>
          {rentCalc > 0 && (
            <div className="fr" style={{ background: 'rgba(34,158,217,.08)' }}>
              <span className="fr-l" style={{ color: 'var(--t3)', fontSize: 'var(--fs-cap1)' }}>{rentType === 'per_m2' ? 'Розрахунок' : 'Ставка'}</span>
              <span style={{ flex: 1, textAlign: 'right', fontWeight: 'var(--fw-bold)', fontSize: 'var(--fs-sub)', color: 'var(--info-fg)' }}>
                {formatPrice(rentCalc, user?.currency)}{rentUnitLabel(rentType === 'per_m2' ? 'fixed' : rentType)}
              </span>
            </div>
          )}
        </div>

        {/* Utilities */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBolt size={14} color="#fbbf24" />Експлуатаційні</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">{isParking ? 'Сума' : 'Ставка'}</span>
            <input aria-label={isParking ? 'Сума експлуатаційних' : 'Ставка експлуатаційних за м²'} className="fr-i" type="text" inputMode="decimal" placeholder={isParking ? '30' : '2.5'} value={utilitiesRate} onChange={e => setUtilitiesRate(sanitizeDecimal(e.target.value))} />
            <span className="fr-u">{currencySymbol(user?.currency)}{isParking ? '/міс' : '/м²'}</span>
          </div>
          {!isParking && utilsCalc > 0 && (
            <div className="fr" style={{ background: 'rgba(34,158,217,.08)' }}>
              <span className="fr-l" style={{ color: 'var(--t3)', fontSize: 'var(--fs-cap1)' }}>Розрахунок</span>
              <span style={{ flex: 1, textAlign: 'right', fontWeight: 'var(--fw-bold)', fontSize: 'var(--fs-sub)', color: 'var(--info-fg)' }}>
                {formatPrice(utilsCalc, user?.currency)}/міс
              </span>
            </div>
          )}
        </div>

        {/* Parking spot attributes — parking DBs only */}
        {isParking && (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCarGarage size={14} color="#fb923c" />Місце</span></div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
              <div className="fr">
                <span className="fr-l">Тип</span>
                <div className="fr-seg" style={{ maxWidth: 230 }}>
                  {PARKING_TYPES.map(({ v, l }) => (
                    <button type="button" key={v} className={`fr-seg-b ${parkingType === v ? 'on' : ''}`} onClick={() => { hapticSelection(); setParkingType(parkingType === v ? '' : v) }}>{l}</button>
                  ))}
                </div>
              </div>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconBolt size={14} color="var(--t3)" />Зарядка для електромобіля</span>
                <Toggle value={evCharger} onChange={setEvCharger} />
              </div>
            </div>
          </>
        )}

        {/* Parking (office/apartment DBs) */}
        {!isParking && (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCarGarage size={14} color="#fb923c" />Паркінг</span></div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
              <div className="fr">
                <span className="fr-l">Є паркінг</span>
                <Toggle value={hasParking} onChange={setHasParking} />
              </div>
              {hasParking && (
                <div className="fr">
                  <span className="fr-l">Місць</span>
                  <input aria-label="Кількість місць" className="fr-i" type="text" inputMode="numeric" maxLength={3} value={parkingSpaces} onChange={e => setParkingSpaces(sanitizeInt(e.target.value))} />
                </div>
              )}
            </div>

            {/* Utility services */}
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBolt size={14} color="#fbbf24" />Експлуатаційні послуги</span></div>
            <div className="glass-s" style={{ margin: '0 12px 16px', borderRadius: 'var(--r-md)' }}>
              <div className="util-tags">
                {UTILITY_META.map(({ id, label, Icon, color }) => {
                  const on = utilities.includes(id)
                  return (
                    <button
                      key={id}
                      className={`util-tag${on ? ' on' : ''}`}
                      onClick={() => toggleUtility(id)}
                      style={on ? { color } : undefined}
                    >
                      <Icon size={14} />
                      {label}
                    </button>
                  )
                })}
              </div>
            </div>
          </>
        )}

        {/* Description */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconFile size={14} color="var(--violet)" />Опис</span></div>
        <div className="glass-s" style={{ margin: '0 12px 16px', borderRadius: 'var(--r-md)', padding: '10px 14px' }}>
          <textarea
            aria-label="Опис обʼєкта"
            className="fr-textarea"
            placeholder="Додатковий опис обʼєкту..."
            value={description}
            onChange={e => setDescription(e.target.value)}
            rows={4}
            maxLength={2000}
            style={{ resize: 'none' }}
          />
        </div>

        {/* Files — only in edit mode (property exists in DB) */}
        {isEdit && editId && (
          <FilesList propertyId={editId} isOwner={true} />
        )}

        {/* Sum */}
        {total > 0 && (
          <div className="sum-bar glass-s" style={{ margin: '0 12px 16px' }}>
            {rentCalc > 0 && (
              <div className="sum-r">
                <span>Оренда</span>
                <span>{formatPrice(rentCalc, user?.currency)}/міс</span>
              </div>
            )}
            {utilsCalc > 0 && (
              <div className="sum-r">
                <span>Експлуатаційні</span>
                <span>{formatPrice(utilsCalc, user?.currency)}/міс</span>
              </div>
            )}
            <div className="sum-tot">
              <span className="sum-tot-l">Разом на місяць</span>
              <span className="sum-tot-v">{formatPrice(total, user?.currency)}</span>
            </div>
          </div>
        )}

        {/* CTA — ВСЕРЕДИНІ тіла, що прокручується, а не окремим блоком під ним.
            Знизу від `.body` вона лежала в СМУЗІ голого градієнта: щойно
            клавіатура піднімалась, тіло стискалось і над кнопкою проявлявся шов —
            видима «широка лінія» на межі панелі форми, а сама кнопка виглядала
            наклеєною на чужу смугу. У потоці тіла вона просто йде за останнім
            полем, на тому самому фоні. Ховається під шитом вибору папки — його
            власна кнопка мусить лишатись єдиною первинною дією на екрані. */}
        {(
          <button
            className={`mbtn success mbtn-flow ${!canSave || loading ? 'disabled' : ''} ${loading ? 'is-loading' : ''}`}
            onClick={handleSave}
            disabled={!canSave || loading}
            aria-busy={loading}
          >
            {saveLabel}
          </button>
        )}

      </div>


    </div>
  )
}
