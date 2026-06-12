import type { User, Database, Property } from '@/types'

const NOW = '2026-01-01T00:00:00.000Z'

export function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-uuid-1',
    tg_id: 111222333,
    tg_username: 'tester',
    first_name: 'Test',
    last_name: 'User',
    role: 'owner',
    language_code: 'uk',
    currency: 'USD',
    plan: 'free',
    notification_push: true,
    notification_weekly: true,
    notification_views: true,
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  }
}

export function makeDatabase(overrides: Partial<Database> = {}): Database {
  return {
    id: 'db-uuid-1',
    owner_id: 'user-uuid-1',
    name: 'БЦ Олімп',
    type: 'business_center',
    color: 'purple',
    share_token: 'abc123def456',
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  }
}

export function makeProperty(overrides: Partial<Property> = {}): Property {
  return {
    id: 'prop-uuid-1',
    db_id: 'db-uuid-1',
    owner_id: 'user-uuid-1',
    name: 'Офіс 101',
    status: 'free',
    rent_type: 'per_m2',
    has_parking: false,
    parking_spaces: 0,
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  }
}

// A structurally valid (unsigned) JWT — 3 dot-separated segments, which is what
// loginViaTelegram validates before calling setSession.
export const FAKE_JWT = 'aaa.bbb.ccc'

export function makeAuthResponse(overrides: Partial<{ user: User; is_new: boolean }> = {}) {
  return {
    access_token: FAKE_JWT,
    refresh_token: 'refresh-token-xyz',
    user: overrides.user ?? makeUser(),
    is_new: overrides.is_new ?? false,
  }
}
