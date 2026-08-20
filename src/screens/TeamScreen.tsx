'use client'

import AccessList from '@/components/AccessList'

// Керування командою бази (owner-only — редактори цей екран не бачать).
// Тонка обгортка над спільним `AccessList`: раніше цей екран і
// `ManageGuestsScreen` були дзеркальними копіями, через що кожен дефект
// аудиту доступів існував у ДВОХ місцях одночасно.
export default function TeamScreen() {
  return <AccessList kind="team" />
}
