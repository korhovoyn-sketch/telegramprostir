'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import Toggle from '@/components/ui/Toggle'
import { IconFileExport } from '@/components/Icons'
import type { Property } from '@/types'

const FORMATS = [
  { id: 'pdf', label: 'PDF Документ', desc: 'Красива презентація з фото для клієнта', emoji: '📄' },
  { id: 'excel', label: 'Excel таблиця', desc: 'Для аналітики, .xlsx формат', emoji: '📊' },
  { id: 'lun', label: 'Формат LUN.ua', desc: 'Готово для публікації на LUN', emoji: '🏠' },
  { id: 'olx', label: 'OLX / DOM.RIA', desc: 'Текст + структура для оголошень', emoji: '📋' },
]

const TEMPLATES = [
  { id: 'classic', label: 'Класик' },
  { id: 'modern', label: 'Модерн' },
  { id: 'minimal', label: 'Мінімал' },
]

const CSV_HEADERS = ['Назва', 'Поверх', 'Статус', 'Площа корисна (м²)', 'Площа загальна (м²)', 'Оренда ($/міс)', 'Комунальні ($/міс)', 'Паркінг']

function propertyToRow(p: Property): (string | number)[] {
  return [
    p.name,
    p.floor ?? '',
    p.status === 'free' ? 'Вільно' : p.status === 'occupied' ? 'Зайнято' : 'Продаж',
    p.area_useful ?? '',
    p.area_total ?? '',
    p.rent_rate
      ? (p.rent_type === 'per_m2' && p.area_useful ? Number((p.rent_rate * p.area_useful).toFixed(0)) : p.rent_rate)
      : '',
    p.utilities_rate && p.area_total ? Number((p.utilities_rate * p.area_total).toFixed(0)) : '',
    p.has_parking ? p.parking_spaces : 0,
  ]
}

export default function ExportScreen() {
  const { screenParams, showToast } = useAppStore()
  const { dbId } = screenParams
  const [format, setFormat] = useState('pdf')
  const [template, setTemplate] = useState('classic')
  const [includePhotos, setIncludePhotos] = useState(true)
  const [includeDocs, setIncludeDocs] = useState(true)
  const [onlyFree, setOnlyFree] = useState(false)
  const [qrCodes, setQrCodes] = useState(true)
  const [contacts, setContacts] = useState(true)
  const [loading, setLoading] = useState(false)

  async function handleExport() {
    setLoading(true)
    try {
      // Fetch properties
      const { data: propertiesRaw, error } = await supabase
        .from('properties')
        .select('*, photos:property_photos(*)')
        .eq('db_id', dbId ?? '')

      if (error) throw error

      const properties = (propertiesRaw ?? []) as Property[]
      const rows = onlyFree ? properties.filter((p) => p.status === 'free') : properties

      if (format === 'excel') {
        // CSV/Excel export
        const BOM = '﻿'
        const csvRows = rows.map((p) =>
          propertyToRow(p).map((v) => `"${v}"`).join(',')
        )
        const csv = [CSV_HEADERS.join(','), ...csvRows].join('\n')
        const blob = new Blob([BOM + csv], { type: 'text/csv;charset=utf-8;' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `properties_${Date.now()}.csv`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
        showToast({ type: 'success', title: 'Файл готовий', subtitle: 'Збережено у завантаження' })

      } else if (format === 'pdf') {
        // Fetch db name for heading
        const { data: dbRow } = await supabase.from('databases').select('name').eq('id', dbId ?? '').single()
        const dbName = dbRow?.name ?? 'Об\'єкти'

        const printDiv = document.createElement('div')
        printDiv.id = '__print_area'
        printDiv.innerHTML = `
          <style>@media print { body > *:not(#__print_area) { display: none !important; } #__print_area { display: block !important; } }</style>
          <h1 style="font-family: sans-serif">${dbName}</h1>
          <table style="border-collapse:collapse; width:100%; font-family:sans-serif; font-size:13px">
            <thead><tr style="background:#f5f5f5">${CSV_HEADERS.map((h) => `<th style="border:1px solid #ddd; padding:6px 10px; text-align:left">${h}</th>`).join('')}</tr></thead>
            <tbody>${rows.map((p) => `<tr>${propertyToRow(p).map((c) => `<td style="border:1px solid #ddd; padding:6px 10px">${c}</td>`).join('')}</tr>`).join('')}</tbody>
          </table>
        `
        document.body.appendChild(printDiv)
        window.print()
        setTimeout(() => document.body.removeChild(printDiv), 1000)
        showToast({ type: 'success', title: 'Відправлено на друк' })

      } else {
        // LUN / OLX — share as text via Telegram
        const text = rows.map((p) => {
          const rent = p.rent_rate
            ? (p.rent_type === 'per_m2' && p.area_useful
              ? (p.rent_rate * p.area_useful).toFixed(0)
              : p.rent_rate)
            : '?'
          return `🏢 ${p.name}\n📐 ${p.area_useful ?? '?'} м²\n💰 ${rent}/міс`
        }).join('\n\n')

        window.Telegram?.WebApp?.openTelegramLink(
          `https://t.me/share/url?url=${encodeURIComponent(text)}`
        )
        showToast({ type: 'success', title: 'Відкрито в Telegram' })
      }
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка експорту', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="scr bg-teal">
      <Header title="Експорт" backLabel="Назад" />

      <div className="body">
        {/* Format */}
        <div className="over">Формат файлу</div>
        <div className="format-list">
          {FORMATS.map((f) => (
            <div
              key={f.id}
              className={`format-card ${format === f.id ? 'sel' : ''}`}
              onClick={() => setFormat(f.id)}
            >
              <div className="format-ic glass-s">
                <span style={{ fontSize: 19 }}>{f.emoji}</span>
              </div>
              <div className="format-mn">
                <div className="format-n">{f.label}</div>
                <div className="format-s">{f.desc}</div>
              </div>
              {format === f.id && (
                <div className="format-r">✓</div>
              )}
            </div>
          ))}
        </div>

        {/* Template (PDF only) */}
        {format === 'pdf' && (
          <>
            <div className="over" style={{ marginTop: 8 }}>Шаблон PDF</div>
            <div className="tmpl-row">
              {TEMPLATES.map((t) => (
                <div key={t.id} className={`tmpl ${template === t.id ? 'sel' : ''}`} onClick={() => setTemplate(t.id)}>
                  <div className="tmpl-ph">
                    <div className="tmpl-bar" style={{ width: '60%', background: t.id === 'classic' ? '#3478F6' : t.id === 'modern' ? '#7B30EB' : '#666' }} />
                    <div className="tmpl-bar" style={{ width: '80%' }} />
                    <div className="tmpl-bar" style={{ width: '40%' }} />
                    <div style={{ flex: 1, background: '#f0f0f0', borderRadius: 4, marginTop: 4 }} />
                    <div className="tmpl-bar" style={{ width: '70%', marginTop: 4 }} />
                    <div className="tmpl-bar" style={{ width: '55%' }} />
                  </div>
                  <div className="tmpl-l">{t.label}</div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Options */}
        <div className="over" style={{ marginTop: 8 }}>Налаштування</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Включити фото</span>
            <Toggle value={includePhotos} onChange={setIncludePhotos} />
          </div>
          <div className="fr">
            <span className="fr-l">Включити документи</span>
            <Toggle value={includeDocs} onChange={setIncludeDocs} />
          </div>
          <div className="fr">
            <span className="fr-l">Тільки вільні</span>
            <Toggle value={onlyFree} onChange={setOnlyFree} />
          </div>
          <div className="fr">
            <span className="fr-l">QR-коди об&apos;єктів</span>
            <Toggle value={qrCodes} onChange={setQrCodes} />
          </div>
          <div className="fr">
            <span className="fr-l">Контакти власника</span>
            <Toggle value={contacts} onChange={setContacts} />
          </div>
        </div>

        <div style={{ height: 80 }} />
      </div>

      <button
        className={`mbtn ${loading ? 'is-loading' : ''}`}
        onClick={handleExport}
        disabled={loading}
      >
        {!loading && <IconFileExport size={18} />}
        {!loading && `Створити ${FORMATS.find((f) => f.id === format)?.label}`}
      </button>
    </div>
  )
}
