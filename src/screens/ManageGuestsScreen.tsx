'use client'

import AccessList from '@/components/AccessList'

// Тонка обгортка над спільним `AccessList` — уся логіка й розмітка там.
// Окремий ScreenName лишається, щоб маршрут, лінивий чанк і тести не мінялись.
export default function ManageGuestsScreen() {
  return <AccessList kind="guest" />
}
