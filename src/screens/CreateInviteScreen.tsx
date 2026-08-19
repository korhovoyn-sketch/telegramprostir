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
    formTitle: 'Запросити в команду',
    formSubtitle: "Людина отримає право редагувати об'єкти цієї бази",
    fieldLabel: 'Підпис інвайта',
    placeholder: 'напр. Менеджер Оля',
    successTitle: 'Запрошення створено!',
    successSubtitle: 'Надішліть майбутньому члену команди',
    bg: 'bg-teal',
    shareText: 'Запрошення до команди бази нерухомості',
  },
  guest: {
    formTitle: 'Запросити гостя',
    formSubtitle: 'Згенеруємо запрошення-посилання',
    fieldLabel: 'Підпис гостьового лінка',
    placeholder: 'напр. Орендар, кв. 5',
    successTitle: 'Посилання створено!',
    successSubtitle: 'Надішліть гостю для отримання доступу',
    bg: 'bg-blue',
    shareText: 'Запрошення до перегляду',
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
      showToast({ type: 'error', title: 'Не вдалося створити', subtitle: humanizeDbError(e) })
    } finally {
      setSaving(false)
    }
  }

  async function handleCopy() {
    const ok = await copyLink(link)
    if (ok) showToast({ type: 'success', title: 'Посилання скопійовано' })
    else showToast({ type: 'error', title: 'Не вдалося скопіювати' })
  }

  function handleShare() {
    openTelegramShare(link, copy.shareText)
  }

  return (
    <div className={`scr ${copy.bg}`}>
      <Header title={step === 'form' ? copy.formTitle : copy.successTitle} backLabel="Назад" onBack={back} />

      {step === 'form' ? (
        <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
          <div style={{ margin: '0 12px 16px', fontSize: 'var(--fs-cap1)', color: 'var(--t3)' }}>
            {copy.formSubtitle}
          </div>
          <div style={{ margin: '0 12px 16px' }}>
            <div className="fld">
              <div className="fld-l">Підпис (необов&apos;язково)</div>
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

          <button
            className={`mbtn success mbtn-flow ${saving ? 'disabled is-loading' : ''}`}
            onClick={handleCreate}
            disabled={saving}
          >
            {!saving && 'Створити'}
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
              Посилання не сформувалось: у застосунку не налаштований юзернейм бота.
              Запрошення вже створене — надішліть його після налаштування.
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, margin: '0 12px' }}>
            <button className={`${modalBtnClass('secondary')} sm`} disabled={!usable} onClick={handleCopy}>
              Скопіювати
            </button>
            <button className={`${modalBtnClass('primary')} sm`} disabled={!usable} onClick={handleShare}>
              У Telegram
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
