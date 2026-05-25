'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import Header from '@/components/ui/Header'
import Toggle from '@/components/ui/Toggle'
import { IconFileExport, IconFile } from '@/components/Icons'

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

export default function ExportScreen() {
  const { screenParams, showToast } = useAppStore()
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
    await new Promise(r => setTimeout(r, 1500))
    setLoading(false)
    showToast({ type: 'success', title: 'Файл готовий', subtitle: 'Збережено у завантаження' })
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
      >
        {!loading && <IconFileExport size={18} />}
        {!loading && `Створити ${FORMATS.find(f => f.id === format)?.label}`}
      </button>
    </div>
  )
}
