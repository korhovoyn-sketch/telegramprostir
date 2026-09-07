'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { offlineGuard } from '@/lib/offline'
import { supabase } from '@/lib/supabase'
import { humanizeDbError, scrollFocusedIntoView } from '@/lib/utils'
import Header from '@/components/ui/Header'
import { modalBtnClass } from '@/components/ui/ActionSheet'
import { buildDeepLink, openTelegramShare } from '@/lib/telegram'
import { copyLink } from '@/lib/share'
import { tr } from '@/lib/i18n'

interface KindCopy {
  formTitle: string
  formSubtitle: string
  fieldLabel: string
  placeholder: string
  successTitle: string
  successSubtitle: string
  bg: string
  shareText: string
}

const KIND_COPY: Record<'team' | 'guest', KindCopy> = {
  team: {
    formTitle: tr('Запросити в команду'),
    formSubtitle: tr('Людина отримає право редагувати обʼєкти цієї бази'),
    fieldLabel: tr('Підпис інвайта'),
    placeholder: tr('напр. Менеджер Оля'),
    successTitle: tr('Запрошення створено!'),
    successSubtitle: tr('Надішліть майбутньому члену команди'),
    bg: 'bg-teal',
    shareText: tr('Запрошення до команди бази нерухомості'),
  },
  guest: {
    formTitle: tr('Запросити гостя'),
    formSubtitle: tr('Згенеруємо запрошення-посилання'),
    fieldLabel: tr('Підпис гостьового лінка'),
    placeholder: tr('напр. Орендар, кв. 5'),
    successTitle: tr('Посилання створено!'),
    successSubtitle: tr('Надішліть гостю для отримання доступу'),
    bg: 'bg-blue',
    shareText: tr('Запрошення до перегляду'),
  },
}

/**
 * Повноекранна форма запрошення — заміна колишнього InviteSheet+CreatedLinkSheet
 * (фаза 3 переробки модалок, atomic-riding-clock.md). `back()` з нового екрана
 * ПОВНІСТЮ перемонтовує TeamScreen/ManageGuestsScreen (page.tsx's key={navKey}),
 * тож щойно створений лінк неможливо «передати» назад через навігацію — обидва
 * кроки (форма і показ лінка) лишаються на ОДНОМУ екрані, крок 'created' малює
 * те, що раніше малював дочірній CreatedLinkSheet.
 */
export default function CreateInviteScreen() {
  const { screenParams, user, showToast, back } = useAppStore()
  const kind = (screenParams.kind as 'team' | 'guest' | undefined) ?? 'guest'
  const dbId = screenParams.dbId as string | undefined
  const propertyId = screenParams.propertyId as string | undefined
  const isProperty = !!propertyId
  const targetId = propertyId ?? dbId

  const copy = KIND_COPY[kind]

  const [step, setStep] = useState<'form' | 'created'>('form')
  const [label, setLabel] = useState('')
  const [saving, setSaving] = useState(false)
  const [link, setLink] = useState('')

  const usable = /^https?:\/\//.test(link)

  async function handleCreate() {
    if (!user || !targetId) return
    if (offlineGuard()) return
    setSaving(true)
    try {
      let token: string
      if (kind === 'team') {
        const { data, error } = await supabase
          .from('db_members')
          .insert({ db_id: targetId, label: label.trim() || null })
          .select('invite_token')
          .single()
        if (error) throw error
        token = (data as { invite_token: string }).invite_token
        setLink(buildDeepLink(`team_${token}`))
      } else {
        const { data, error } = await supabase
          .from('guest_links')
          .insert({
            owner_id: user.id,
            property_id: isProperty ? targetId : null,
            db_id: isProperty ? null : targetId,
            label: label.trim() || null,
          })
          .select('invite_token')
          .single()
        if (error) throw error
        token = (data as { invite_token: string }).invite_token
        setLink(buildDeepLink(`guest_${token}`))
      }
      setStep('created')
    } catch (e) {
      showToast({ type: 'error', title: tr('Не вдалося створити'), subtitle: humanizeDbError(e) })
    } finally {
      setSaving(false)
    }
  }

  async function handleCopy() {
    const ok = await copyLink(link)
    if (ok) showToast({ type: 'success', title: tr('Посилання скопійовано') })
    else showToast({ type: 'error', title: tr('Не вдалося скопіювати') })
  }

  function handleShare() {
    openTelegramShare(link, copy.shareText)
  }

  return (
    <div className={`scr ${copy.bg}`}>
      <Header title={step === 'form' ? copy.formTitle : copy.successTitle} backLabel={tr('Назад')} onBack={back} />

      {step === 'form' ? (
        <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
          <div style={{ margin: '0 12px 16px', fontSize: 'var(--fs-cap1)', color: 'var(--t3)' }}>
            {copy.formSubtitle}
          </div>
          <div style={{ margin: '0 12px 16px' }}>
            <div className="fld">
              <div className="fld-l">{tr('Підпис (необовʼязково)')}</div>
              <input
                aria-label={copy.fieldLabel}
                type="text"
                placeholder={copy.placeholder}
                value={label}
                onChange={e => setLabel(e.target.value)}
                maxLength={100}
              />
            </div>
          </div>

          {/* Підпис лишається в DOM і під час запиту: `.mbtn.is-loading` уже
              ховає його через `color:transparent`, тож знімати текстовий вузол
              нічого не давало візуально, зате забирало в кнопки ДОСТУПНУ
              НАЗВУ — читалка озвучувала безіменну кнопку, а пігулка ще й
              стискалась до ширини спінера. */}
          <button
            className={`mbtn success mbtn-flow ${saving ? 'disabled is-loading' : ''}`}
            onClick={handleCreate}
            disabled={saving}
            aria-busy={saving}
          >
            {tr('Створити')}
          </button>
        </div>
      ) : (
        <div className="body">
          <div style={{ margin: '0 12px 16px', fontSize: 'var(--fs-cap1)', color: 'var(--t3)' }}>
            {copy.successSubtitle}
          </div>
          {usable ? (
            <div className="link-mono" style={{ margin: '0 12px 16px' }}>{link}</div>
          ) : (
            <div className="link-mono" style={{ margin: '0 12px 16px' }}>
              {tr('Посилання не сформувалось: у застосунку не налаштований юзернейм бота. Запрошення вже створене — надішліть його після налаштування.')}
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, margin: '0 12px' }}>
            <button className={`${modalBtnClass('secondary')} sm`} disabled={!usable} onClick={handleCopy}>
              {tr('Скопіювати')}
            </button>
            <button className={`${modalBtnClass('primary')} sm`} disabled={!usable} onClick={handleShare}>
              {tr('У Telegram')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
