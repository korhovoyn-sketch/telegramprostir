export type UserRole = 'owner' | 'realtor' | 'guest'
export type UserPlan = 'free' | 'pro'
export type DatabaseType = 'business_center' | 'residential' | 'retail' | 'warehouse' | 'individual' | 'parking'
export type PropertyStatus = 'free' | 'occupied' | 'for_sale'
export type RentType = 'per_m2' | 'fixed' | 'per_day'
// Which area a per-m² rate multiplies by: корисна (useful) or розрахункова (total).
export type AreaBasis = 'useful' | 'total'
export type ParkingType = 'underground' | 'covered' | 'open'
export type NotificationAction = 'view' | 'photo' | 'document' | 'share' | 'favorite'

export interface User {
  id: string
  tg_id: number
  tg_username?: string
  first_name: string
  last_name?: string
  email?: string
  phone?: string
  role: UserRole
  language_code: string
  currency: string
  plan: UserPlan
  public_phone?: boolean
  notification_push?: boolean
  notification_weekly?: boolean
  notification_views?: boolean
  created_at: string
  updated_at: string
}

export interface Database {
  id: string
  owner_id: string
  name: string
  /** Колонка в БД NULLABLE, тож тип мусить пускати `null` — інакше «очистити
   *  адресу» неможливо виразити, і поле тихо лишалось незмінним (той самий
   *  клас, що вже полагоджено для `Property`). */
  address?: string | null
  type: DatabaseType
  color: string
  /** Орендодавець за замовчуванням для всіх обʼєктів бази (064). Обʼєкт може
   *  перевизначити своїм `landlord_name`. */
  landlord_name?: string | null
  share_token: string
  share_expires_at?: string
  created_at: string
  updated_at: string
  _property_count?: number
  _free_count?: number
  // true коли база доступна користувачу як члену команди (не власнику)
  _member?: boolean
  _occupied_count?: number
  _monthly_income?: number
  /** Експлуатаційні за місяць по зайнятих обʼєктах бази (див. `useDatabases`). */
  _monthly_utils?: number
}

export interface Property {
  id: string
  db_id: string
  owner_id: string
  name: string
  // Опційні колонки — nullable В БАЗІ, тож `| null` тут не педантизм: без нього
  // тип забороняв ОЧИСТИТИ поле (`null` у PATCH), а `undefined` замість нього
  // просто випадає з JSON і колонка лишається старою — форма рапортувала
  // «Збережено», не змінивши нічого.
  floor?: string | null
  status: PropertyStatus
  area_useful?: number | null
  area_total?: number | null
  area_basis?: AreaBasis | null
  folder_id?: string | null
  rent_type: RentType
  rent_rate?: number | null
  utilities_rate?: number | null
  has_parking: boolean
  parking_spaces: number
  parking_type?: ParkingType | null
  ev_charger?: boolean
  description?: string | null
  address?: string | null
  utilities?: string[] | null
  sale_price?: number | null
  tenant_name?: string | null
  /** Орендодавець — ТОЙ, ХТО ЗДАЄ. NULL означає «як у базі», не «немає»
   *  (успадкування, міграція 064). Не плутати з `tenant_name` (орендар)
   *  і з `owner_id` (акаунт у застосунку). */
  landlord_name?: string | null
  lease_start_date?: string | null
  lease_end_date?: string | null
  sort_order?: number
  share_token?: string
  share_expires_at?: string | null
  created_at: string
  updated_at: string
  photos?: PropertyPhoto[]
  _view_count?: number
  /**
   * Рядок намальовано з SWR-кешу і він ще НЕ підтверджений мережею. Форма
   * редагування дивиться на цей прапорець: префіл із кешу треба переграти, коли
   * приїде свіжий рядок, інакше застаріле значення виглядає як «не збереглося».
   */
  _stale?: boolean
}

export interface PropertyPhoto {
  id: string
  property_id: string
  storage_path: string
  sort_order: number
  created_at: string
}

// A named group of objects inside one database (owner/editor organisation tool).
export interface PropertyFolder {
  id: string
  db_id: string
  owner_id: string
  name: string
  sort_order: number
  created_at: string
  updated_at: string
}

export interface PropertyFile {
  id: string
  property_id: string
  owner_id: string
  storage_path: string
  file_name: string
  file_size: number
  mime_type: string
  sort_order: number
  created_at: string
}

export interface RealtorSubscription {
  id: string
  realtor_id: string
  db_id: string
  created_at: string
  database?: Database
}

export interface DbMember {
  id: string
  db_id: string
  user_id: string | null
  role: 'editor'
  invite_token: string
  label: string | null
  member_name: string | null
  status: 'pending' | 'active' | 'revoked'
  claimed_at: string | null
  created_at: string
}

export interface GuestLink {
  id: string
  owner_id: string
  property_id: string | null
  db_id: string | null
  invite_token: string
  label: string | null
  guest_user_id: string | null
  /** Імʼя того, хто ПРИЙНЯВ лінк (міграція 048) — дзеркало `member_name` у
   *  `db_members`. Опційне: фронт деплоїться незалежно від міграції. */
  guest_name?: string | null
  status: 'pending' | 'active' | 'revoked'
  claimed_at: string | null
  created_at: string
  property?: Property
  database?: Database
}

export interface Collection {
  id: string
  realtor_id: string
  name: string
  is_draft: boolean
  share_token?: string
  share_expires_at?: string | null
  created_at: string
  updated_at: string
  properties?: Property[]
}

export interface PropertyView {
  id: string
  // Null for db/collection open events (migration 040) — exactly one of
  // property_id / db_id / collection_id is set per row.
  property_id: string | null
  db_id?: string | null
  collection_id?: string | null
  viewer_id?: string
  viewer_name?: string
  action: NotificationAction
  created_at: string
}

export interface Notification {
  id: string
  user_id: string
  type: string
  title: string
  body?: string
  is_read: boolean
  data?: Record<string, unknown>
  created_at: string
}

export type ToastType = 'success' | 'error' | 'info'

export interface Toast {
  type: ToastType
  title: string
  subtitle?: string
  // Optional action button (e.g. «Скасувати» for undo). The toast stays
  // visible longer when present so the user has time to react.
  actionLabel?: string
  onAction?: () => void
}

/**
 * Запит підтвердження для фолбек-модалки (коли нативного попапа Telegram нема).
 * `resolve` — той самий проміс, який чекає `confirmAction()`.
 */
export interface ConfirmRequest {
  title: string
  message: string
  confirmLabel: string
  destructive?: boolean
  resolve: (ok: boolean) => void
}

export type ScreenName =
  | 'splash'
  | 'welcome'
  | 'role-select'
  | 'profile-setup'
  | 'empty-state'
  | 'db-list'
  | 'create-db'
  | 'edit-db'
  | 'db-objects'
  | 'property-form'
  | 'property-detail'
  | 'sharing-analytics'
  | 'export'
  | 'import-objects'
  | 'realtor-dashboard'
  | 'realtor-database'
  | 'collections'
  | 'profile'
  | 'notifications'
  | 'photo-upload'
  | 'photo-gallery'
  | 'qr-scanner'
  | 'guest-database'
  | 'guest-home'
  | 'manage-guests'
  | 'team'
  | 'shared-collection'
  | 'payment-calendar'
  | 'payment-schedule'
  | 'payment-confirm'
  | 'create-invite'
  | 'folder-manage'
  | 'db-picker'
  | 'folder-picker'
  | 'rent-property'
  | 'delete-account'

export interface RentPayment {
  id: string
  property_id: string
  owner_id: string
  due_day: number
  notify_days_before: number
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface RentPaymentRecord {
  id: string
  property_id: string
  owner_id: string
  due_date: string
  paid_at?: string | null
  amount?: number | null
  status: 'pending' | 'paid' | 'overdue'
  notes?: string | null
  created_at: string
  updated_at: string
}

export interface ScreenParams {
  dbId?: string
  propertyId?: string
  dueDate?: string
  kind?: 'team' | 'guest'
  /** Обʼєкти, над якими діє пікер (пакетне переміщення в базу чи папку).
   *  Виділення живе в стані DatabaseObjectsScreen і зникає при навігації —
   *  тому переміщення виконує САМ пікер, а не викликач: повернення на
   *  перемонтований екран показує вже готовий результат (урок фази 2). */
  propertyIds?: string[]
  collectionId?: string
  /** Share-токен підбірки. Носити його ДАЛІ обовʼязково: read-only перегляд
   *  авторизується саме токеном, а не UUID підбірки (див. IDOR у 049). */
  colToken?: string
  photoIndex?: number
  initialIndex?: number
  editMode?: boolean
  message?: string
  title?: string
  nextScreen?: string
  nextParams?: Record<string, unknown>
  photos?: unknown[]
  files?: unknown[]
  [key: string]: unknown
}
