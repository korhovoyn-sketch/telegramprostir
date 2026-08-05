// Спільна оболонка для юридичних сторінок (/privacy, /terms).
// Серверний компонент: сторінки статичні, без клієнтського JS.
import Link from 'next/link'

export function H({ children }: { children: React.ReactNode }) {
  return <h2 className="lg-h">{children}</h2>
}

export function P({ children }: { children: React.ReactNode }) {
  return <p className="lg-p">{children}</p>
}

export function UL({ items }: { items: string[] }) {
  return (
    <ul className="lg-ul">
      {items.map((t) => <li key={t}>{t}</li>)}
    </ul>
  )
}

export default function LegalPage({ title, updated, children }: {
  title: string
  updated: string
  children: React.ReactNode
}) {
  return (
    <div className="lg-wrap">
      <div className="lg-card">
        <Link className="lg-back" href="/">← prostir</Link>
        <h1 className="lg-t">{title}</h1>
        <div className="lg-upd">Оновлено: {updated}</div>
        {children}
      </div>
    </div>
  )
}
