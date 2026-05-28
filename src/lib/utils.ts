export function formatPrice(amount: number, currency = 'USD'): string {
  if (currency === 'USD') return `$${amount.toLocaleString('uk-UA')}`
  if (currency === 'EUR') return `€${amount.toLocaleString('uk-UA')}`
  return `₴${amount.toLocaleString('uk-UA')}`
}

export function formatArea(m2: number): string {
  return `${m2} м²`
}

export function formatDate(iso: string): string {
  const d = new Date(iso)
  const now = new Date()
  const diff = now.getTime() - d.getTime()
  const mins = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days = Math.floor(diff / 86400000)

  if (mins < 1) return 'щойно'
  if (mins < 60) return `${mins} хв тому`
  if (hours < 24) return `${hours} год тому`
  if (days === 1) return 'вчора'
  if (days < 7) return `${days} дні тому`

  return d.toLocaleDateString('uk-UA', { day: 'numeric', month: 'short' })
}

export function calcRent(areaUseful: number, rentRate: number, rentType: string): number {
  if (rentType === 'fixed') return rentRate
  return Math.round(areaUseful * rentRate)
}

export function calcUtilities(areaTotal: number, utilitiesRate: number): number {
  return Math.round(areaTotal * utilitiesRate)
}

export function calcTotal(
  areaUseful: number,
  areaTotal: number,
  rentRate: number,
  rentType: string,
  utilitiesRate: number
): number {
  const rent = calcRent(areaUseful, rentRate, rentType)
  const utils = calcUtilities(areaTotal, utilitiesRate)
  return rent + utils
}

export function getInitials(firstName: string, lastName?: string): string {
  const f = firstName.charAt(0).toUpperCase()
  const l = lastName ? lastName.charAt(0).toUpperCase() : ''
  return f + l
}

export function freshnessLabel(updatedAt: string): { label: string; cls: string } {
  const days = Math.floor((Date.now() - new Date(updatedAt).getTime()) / 86400000)
  if (days === 0) return { label: 'сьогодні', cls: 'fresh' }
  if (days <= 3) return { label: `${days}д тому`, cls: 'fresh' }
  if (days <= 7) return { label: `${days}д тому`, cls: 'stale' }
  return { label: `${days}д тому`, cls: 'old' }
}

export const DB_TYPE_LABELS: Record<string, string> = {
  business_center: 'Бізнес-центр',
  residential: 'ЖК',
  retail: 'Рітейл',
  warehouse: 'Склади',
  individual: 'Приватне',
  parking: 'Паркінг',
}

export const DB_TYPE_ICONS: Record<string, string> = {
  business_center: 'ti-building-skyscraper',
  residential: 'ti-building-community',
  retail: 'ti-building-store',
  warehouse: 'ti-building-warehouse',
  individual: 'ti-home',
  parking: 'ti-car-garage',
}

export const STATUS_LABELS: Record<string, string> = {
  free: 'Вільно',
  occupied: 'Зайнято',
  for_sale: 'Продаж',
}

export const STATUS_BADGE_CLS: Record<string, string> = {
  free: 'bdg-ok',
  occupied: 'bdg-busy',
  for_sale: 'bdg-sale',
}

export const DB_COLORS: Record<string, string> = {
  purple: 'linear-gradient(135deg,#7B30EB,#5B1FD4)',
  blue: 'linear-gradient(135deg,#2AABEE,#1070B8)',
  green: 'linear-gradient(135deg,#34C759,#1A8A38)',
  orange: 'linear-gradient(135deg,#FF9500,#D06000)',
  pink: 'linear-gradient(135deg,#FF7AB8,#C42378)',
  teal: 'linear-gradient(135deg,#5AC8FA,#2A8AB0)',
}
