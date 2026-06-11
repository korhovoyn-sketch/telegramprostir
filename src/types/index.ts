export type UserRole = 'owner' | 'realtor'
export type UserPlan = 'free' | 'pro'
export type DatabaseType = 'business_center' | 'residential' | 'retail' | 'warehouse' | 'individual' | 'parking'
export type PropertyStatus = 'free' | 'occupied' | 'for_sale'
export type RentType = 'per_m2' | 'fixed'
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
  address?: string
  type: DatabaseType
  color: string
  share_token: string
  share_expires_at?: string
  created_at: string
  updated_at: string
  _property_count?: number
  _free_count?: number
  _occupied_count?: number
  _monthly_income?: number
}

export interface Property {
  id: string
  db_id: string
  owner_id: string
  name: string
  floor?: string
  status: PropertyStatus
  area_useful?: number
  area_total?: number
  rent_type: RentType
  rent_rate?: number
  utilities_rate?: number
  has_parking: boolean
  parking_spaces: number
  description?: string
  address?: string | null
  utilities?: string[] | null
  sale_price?: number | null
  tenant_name?: string | null
  lease_start_date?: string | null
  lease_end_date?: string | null
  sort_order?: number
  share_token?: string
  share_expires_at?: string | null
  created_at: string
  updated_at: string
  photos?: PropertyPhoto[]
  _view_count?: number
}

export interface PropertyPhoto {
  id: string
  property_id: string
  storage_path: string
  sort_order: number
  created_at: string
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
  property_id: string
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
  | 'realtor-dashboard'
  | 'realtor-database'
  | 'collections'
  | 'profile'
  | 'notifications'
  | 'photo-upload'
  | 'photo-gallery'
  | 'qr-scanner'
  | 'guest-database'
  | 'shared-collection'
  | 'success'
  | 'error'
  | 'payment-calendar'

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
  collectionId?: string
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
