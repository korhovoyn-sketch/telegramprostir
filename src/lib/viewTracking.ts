import { supabase } from '@/lib/supabase'
import type { User } from '@/types'

/**
 * Слід перегляду: хто з ІМЕНОВАНИХ користувачів відкривав базу чи картку.
 *
 * Рядки лягають у `property_views` і живлять блок «Хто переглядав» у
 * сповіщеннях. Анонімні відкриття публічної `/v` пише окремо
 * `record_public_view` (SECURITY DEFINER, anon) — сюди вони не потрапляють.
 *
 * ДЕДУП ЖИВЕ ТУТ, І ЦЕ НЕ ДРІБНИЦЯ. Попередній (і єдиний) запис — на екрані
 * обʼєкта — мав лише `useRef` на монтаж, тобто десять відкриттів тієї самої
 * картки давали десять рядків. Публічний шлях має вікно в хвилину, цей не мав
 * нічого: один рієлтор, що гортає базу, засипав би стрічку власника. Вікно
 * ширше за хвилину свідомо: тут не захист від подвійного кліку, а питання
 * «чи заходив він сьогодні», і повторний слід через 20 хвилин нічого не додає.
 */
const WINDOW_MS = 30 * 60_000

/** Ключ → час останнього запису. Модульний: переживає перемонтування екрана. */
const lastWrite = new Map<string, number>()

function throttled(key: string): boolean {
  const now = Date.now()
  const prev = lastWrite.get(key)
  if (prev !== undefined && now - prev < WINDOW_MS) return true
  lastWrite.set(key, now)
  return false
}

function viewerName(user: User): string {
  return `${user.first_name}${user.last_name ? ' ' + user.last_name : ''}`
}

/**
 * Слід перегляду БАЗИ (`property_id` NULL, `db_id` заповнений).
 *
 * ВЛАСНІ відкриття НЕ пишуться, і це не косметика: власник відкриває свою базу
 * щодня, тож його рядки були б переважною більшістю таблиці, а в стрічці все
 * одно відфільтровані. Для карток історична поведінка лишається як була —
 * там на кількості переглядів стоїть `_view_count`, і тиха зміна семантики
 * зрушила б цифру на всіх картках.
 *
 * До міграції 063 RLS цю вставку МОВЧКИ відхиляє (`property_id IS NULL` не
 * проходив предикат), тож фронт безпечно деплоїться раніше за неї: слідів
 * просто не буде, помилки теж.
 */
export function recordDbView(dbId: string | undefined, dbOwnerId: string | undefined, user: User | null) {
  if (!dbId || !user || !dbOwnerId || dbOwnerId === user.id) return
  if (throttled(`db:${dbId}:${user.id}`)) return
  supabase.from('property_views').insert({
    property_id: null,
    db_id: dbId,
    viewer_id: user.id,
    viewer_name: viewerName(user),
    action: 'view',
  }).then(() => {})
}

/** Слід перегляду КАРТКИ. Пише всіх, включно з власником (див. `_view_count`). */
export function recordPropertyView(propertyId: string, user: User | null) {
  if (throttled(`prop:${propertyId}:${user?.id ?? 'anon'}`)) return
  supabase.from('property_views').insert({
    property_id: propertyId,
    viewer_id: user?.id ?? null,
    viewer_name: user ? viewerName(user) : null,
    action: 'view',
  }).then(() => {})
}

/** Лише для тестів: скинути вікно дедупу між кейсами. */
export function __resetViewThrottle() { lastWrite.clear() }
