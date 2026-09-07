import { IconBolt, IconDroplet, IconThermometer, IconFlame, IconBatteryCharging } from '@/components/Icons'
import { tr } from '@/lib/i18n'

export interface UtilityMeta {
  id: string
  label: string
  Icon: (p: { className?: string; size?: number; color?: string }) => React.ReactNode
  color: string
}

export const UTILITY_META: UtilityMeta[] = [
  { id: 'electricity', label: tr('Електропостачання'), Icon: IconBolt, color: '#fbbf24' },
  { id: 'water', label: tr('Водопостачання'), Icon: IconDroplet, color: 'var(--info)' },
  { id: 'heating', label: tr('Теплопостачання'), Icon: IconThermometer, color: '#fb923c' },
  { id: 'gas', label: tr('Газопостачання'), Icon: IconFlame, color: '#4ade80' },
  { id: 'backup', label: tr('Резервне живлення'), Icon: IconBatteryCharging, color: 'var(--violet)' },
]
