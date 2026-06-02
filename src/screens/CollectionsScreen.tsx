'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import TabBar from '@/components/ui/TabBar'
import { IconPlus, IconShare } from '@/components/Icons'
import { formatDate } from '@/lib/utils'
import type { Collection } from '@/types'

export default function CollectionsScreen() {
  const { user, showToast } = useAppStore()
  const [collections, setCollections] = useState<Collection[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      if (!user) return
      setLoading(true)
      try {
        const { data, error } = await supabase
          .from('collections')
          .select('*')
          .eq('realtor_id', user.id)
          .order('created_at', { ascending: false })
        if (error) throw error
        setCollections((data ?? []) as Collection[])
      } catch (e) {
        showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [user, showToast])

  async function createCollection() {
    if (!user) return
    const name = `Підбірка ${collections.length + 1}`
    try {
      const { data, error } = await supabase
        .from('collections')
        .insert({ realtor_id: user.id, name, is_draft: true })
        .select()
        .single()
      if (error) throw error
      setCollections([data as Collection, ...collections])
      showToast({ type: 'success', title: 'Підбірку створено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }

  return (
    <div className="scr bg-violet">
      <div className="hdr">
        <div className="hdr-sp" />
        <div className="hdr-t">Підбірки</div>
        <div className="hdr-sp" />
      </div>

      <div className="body has-fab">
        <div className="greet">Мої підбірки</div>
        <div className="display">Для клієнтів</div>

        {loading ? (
          <div className="loader-wrap"><div className="loader" /></div>
        ) : collections.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">📋</div>
            <div className="empty-h">Немає підбірок</div>
            <div className="empty-s">Створи першу підбірку об&apos;єктів для клієнта</div>
          </div>
        ) : (
          <div className="list">
            {collections.map((c) => (
              <div key={c.id} className="collection-c glass-s">
                <div className="collection-h">
                  <div>
                    <div className="collection-n">{c.name}</div>
                    <div className="collection-meta">
                      {c.is_draft && <span className="bdg bdg-info">Чернетка</span>}
                      <span>·</span>
                      <span>{formatDate(c.updated_at)}</span>
                    </div>
                  </div>
                  <button
                    className="owner-act"
                    onClick={() => {
                      const link = `https://t.me/propspacebot?start=col_${c.id?.slice(0, 8)}`
                      if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
                        window.Telegram.WebApp.openTelegramLink(`https://t.me/share/url?url=${encodeURIComponent(link)}`)
                      }
                    }}
                  >
                    <IconShare size={14} />
                  </button>
                </div>
                <div className="collection-thumbs">
                  <div className="collection-thumb" style={{ color: 'var(--t3)', fontSize: 20 }}>🏢</div>
                  <div className="collection-thumb" style={{ color: 'var(--t3)', fontSize: 20 }}>🏢</div>
                  <div className="collection-thumb more">+</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* FAB */}
      <button className="fab" onClick={createCollection}>
        <IconPlus size={20} />
      </button>

      <TabBar />
    </div>
  )
}
