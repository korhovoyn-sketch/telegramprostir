import { IconBolt, IconDroplet, IconThermometer, IconFlame, IconBatteryCharging } from '@/components/Icons'

export interface UtilityMeta {
  id: string
  label: string
  Icon: (p: { className?: string; size?: number; color?: string }) => React.ReactNode
  color: string
}

export const UTILITY_META: UtilityMeta[] = [
  { id: 'electricity', label: 'Електропостачання', Icon: IconBolt, color: '#fbbf24' },
  { id: 'water', label: 'Водопостачання', Icon: IconDroplet, color: '#7AB3FF' },
  { id: 'heating', label: 'Теплопостачання', Icon: IconThermometer, color: '#fb923c' },
  { id: 'gas', label: 'Газопостачання', Icon: IconFlame, color: '#4ade80' },
  { id: 'backup', label: 'Резервне живлення', Icon: IconBatteryCharging, color: '#a78bfa' },
]
