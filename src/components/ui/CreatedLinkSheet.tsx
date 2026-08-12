'use client'

import Modal from '@/components/ui/Modal'

interface Props {
  title: string
  subtitle: string
  link: string
  onShare: () => void
  onCopy: () => void
  onClose: () => void
}

/**
 * Шит «посилання створено» — спільний для команди бази і гостьових лінків.
 * Обидва екрани мали ідентичну копію, включно з тим самим інлайновим обʼєктом
 * стилю моноспейс-блоку.
 */
export default function CreatedLinkSheet({ title, subtitle, link, onShare, onCopy, onClose }: Props) {
  return (
    <Modal
      title={title}
      subtitle={subtitle}
      onClose={onClose}
      actions={[
        { label: 'Поділитись в Telegram', variant: 'primary', onClick: onShare },
        { label: 'Скопіювати', variant: 'secondary', onClick: onCopy },
      ]}
    >
      <div className="link-mono">{link}</div>
    </Modal>
  )
}
