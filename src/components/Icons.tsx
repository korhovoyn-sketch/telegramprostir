'use client'

interface IconProps {
  className?: string
  size?: number
  color?: string
}

function Icon({ className = '', size = 24, color = 'currentColor', children, viewBox = '0 0 24 24' }: IconProps & { children?: React.ReactNode; viewBox?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox={viewBox}
      fill="none"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`ico ${className}`}
    >
      {children}
    </svg>
  )
}

export function IconChevronLeft(p: IconProps) {
  return <Icon {...p}><polyline points="15 6 9 12 15 18"/></Icon>
}
export function IconChevronRight(p: IconProps) {
  return <Icon {...p}><polyline points="9 6 15 12 9 18"/></Icon>
}
export function IconPlus(p: IconProps) {
  return <Icon {...p}><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></Icon>
}
export function IconX(p: IconProps) {
  return <Icon {...p}><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></Icon>
}
export function IconCheck(p: IconProps) {
  return <Icon {...p}><path d="M5 12l5 5l10 -10"/></Icon>
}
export function IconHome(p: IconProps) {
  return <Icon {...p}><polyline points="5 12 3 12 12 3 21 12 19 12"/><path d="M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-7"/><path d="M9 21v-6a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v6"/></Icon>
}
export function IconDatabase(p: IconProps) {
  return <Icon {...p}><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6a8 3 0 0 0 16 0v-6"/><path d="M4 12v6a8 3 0 0 0 16 0v-6"/></Icon>
}
export function IconBuilding(p: IconProps) {
  return <Icon {...p}><line x1="3" y1="21" x2="21" y2="21"/><path d="M9 21v-14a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v14"/><path d="M3 21l0 -7a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2"/><path d="M21 21l0 -4a2 2 0 0 0 -2 -2h-2a2 2 0 0 0 -2 2v4"/></Icon>
}
export function IconBuildingSkyscraper(p: IconProps) {
  return <Icon {...p}><line x1="3" y1="21" x2="21" y2="21"/><path d="M5 21v-14l8 -4v18"/><path d="M19 21v-10l-6 -4"/><line x1="9" y1="9" x2="9" y2="9.01"/><line x1="9" y1="12" x2="9" y2="12.01"/><line x1="9" y1="15" x2="9" y2="15.01"/><line x1="9" y1="18" x2="9" y2="18.01"/></Icon>
}
export function IconBuildingStore(p: IconProps) {
  return <Icon {...p}><path d="M3 21l18 0"/><path d="M3 7v1a3 3 0 0 0 6 0v-1m0 1a3 3 0 0 0 6 0v-1m0 1a3 3 0 0 0 6 0v-1h-18l2 -4h14l2 4"/><path d="M5 21l0 -10.15"/><path d="M19 21l0 -10.15"/><path d="M9 21v-4a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v4"/></Icon>
}
export function IconBuildingWarehouse(p: IconProps) {
  return <Icon {...p}><path d="M3 21v-13l9 -4l9 4v13"/><path d="M13 13h-2a1 1 0 0 0 -1 1v7h4v-7a1 1 0 0 0 -1 -1z"/><path d="M3 21h18"/><path d="M3 11h18"/></Icon>
}
export function IconBuildingCommunity(p: IconProps) {
  return <Icon {...p}><path d="M8 9l5 5v7h-5v-4l-5 4v-7l5 -5"/><line x1="3" y1="21" x2="21" y2="21"/><path d="M12.835 4.58a1 1 0 0 1 .336 .295l3.458 4.385a1 1 0 0 1 .17 .735l-.503 3.514"/><path d="M14.552 10.72l4.448 -2.72v8"/><path d="M20 15h-7"/></Icon>
}
export function IconCarGarage(p: IconProps) {
  return <Icon {...p}><path d="M5 12h14"/><path d="M3 6m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v0a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z"/><path d="M3 12v7a1 1 0 0 0 1 1h16a1 1 0 0 0 1 -1v-7"/></Icon>
}
export function IconBell(p: IconProps) {
  return <Icon {...p}><path d="M10 5a2 2 0 1 1 4 0a7 7 0 0 1 4 6v3a4 4 0 0 0 2 3h-16a4 4 0 0 0 2 -3v-3a7 7 0 0 1 4 -6"/><path d="M9 17v1a3 3 0 0 0 6 0v-1"/></Icon>
}
export function IconUser(p: IconProps) {
  return <Icon {...p}><circle cx="12" cy="7" r="4"/><path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"/></Icon>
}
export function IconSearch(p: IconProps) {
  return <Icon {...p}><circle cx="10" cy="10" r="7"/><line x1="21" y1="21" x2="15" y2="15"/></Icon>
}
export function IconMapPin(p: IconProps) {
  return <Icon {...p}><circle cx="12" cy="11" r="3"/><path d="M17.657 16.657l-4.243 4.243a2 2 0 0 1 -2.827 0l-4.244 -4.243a8 8 0 1 1 11.314 0z"/></Icon>
}
export function IconShare(p: IconProps) {
  return <Icon {...p}><path d="M13 4v4c-6.575 1.028 -9.02 6.788 -10 12c-.037 .206 5.384 -5.234 10 -4v4l8 -8l-8 -8z"/></Icon>
}
export function IconDownload(p: IconProps) {
  return <Icon {...p}><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2"/><polyline points="7 11 12 16 17 11"/><line x1="12" y1="4" x2="12" y2="16"/></Icon>
}
export function IconEdit(p: IconProps) {
  return <Icon {...p}><path d="M7 7h-1a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-1"/><path d="M20.385 6.585a2.1 2.1 0 0 0 -2.97 -2.97l-8.415 8.385v3h3l8.385 -8.415z"/><path d="M16 5l3 3"/></Icon>
}
export function IconTrash(p: IconProps) {
  return <Icon {...p}><line x1="4" y1="7" x2="20" y2="7"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/><path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12"/><path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3"/></Icon>
}
export function IconPhoto(p: IconProps) {
  return <Icon {...p}><line x1="15" y1="8" x2="15.01" y2="8"/><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M4 15l4 -4a3 5 0 0 1 3 0l5 5"/><path d="M14 14l1 -1a3 5 0 0 1 3 0l2 2"/></Icon>
}
export function IconCamera(p: IconProps) {
  return <Icon {...p}><path d="M5 7h1a2 2 0 0 0 2 -2a1 1 0 0 1 1 -1h6a1 1 0 0 1 1 1a2 2 0 0 0 2 2h1a2 2 0 0 1 2 2v9a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-9a2 2 0 0 1 2 -2"/><circle cx="12" cy="13" r="3"/></Icon>
}
export function IconFile(p: IconProps) {
  return <Icon {...p}><path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"/></Icon>
}
export function IconFileExport(p: IconProps) {
  return <Icon {...p}><path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M11.5 21h-4.5a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v5m-5 6h7m-3 -3l3 3l-3 3"/></Icon>
}
export function IconChartLine(p: IconProps) {
  return <Icon {...p}><line x1="4" y1="19" x2="20" y2="19"/><polyline points="4 15 8 9 12 11 16 6 20 10"/></Icon>
}
export function IconChartBar(p: IconProps) {
  return <Icon {...p}><rect x="3" y="12" width="4" height="8" rx="1"/><rect x="9" y="8" width="4" height="12" rx="1"/><rect x="15" y="4" width="4" height="16" rx="1"/><line x1="4" y1="20" x2="18" y2="20"/></Icon>
}
export function IconEye(p: IconProps) {
  return <Icon {...p}><circle cx="12" cy="12" r="2"/><path d="M22 12c-2.667 4.667 -6 7 -10 7s-7.333 -2.333 -10 -7c2.667 -4.667 6 -7 10 -7s7.333 2.333 10 7"/></Icon>
}
export function IconHeart(p: IconProps) {
  return <Icon {...p}><path d="M19.5 12.572l-7.5 7.428l-7.5 -7.428a5 5 0 1 1 7.5 -6.566a5 5 0 1 1 7.5 6.572"/></Icon>
}
export function IconHeartFilled(p: IconProps) {
  return <Icon {...p}><path d="M6.979 3.074a6 6 0 0 1 4.988 1.425l.037 .033l.034 -.03a6 6 0 0 1 4.733 -1.44l.246 .036a6 6 0 0 1 3.364 10.008l-.18 .185l-.048 .041l-7.45 7.379a1 1 0 0 1 -1.313 .082l-.094 -.082l-7.493 -7.422a6 6 0 0 1 .927 -9.215z" fill="currentColor" strokeWidth="0"/></Icon>
}
export function IconMessage(p: IconProps) {
  return <Icon {...p}><path d="M8 9h8"/><path d="M8 13h6"/><path d="M18 4a3 3 0 0 1 3 3v8a3 3 0 0 1 -3 3h-5l-5 3v-3h-2a3 3 0 0 1 -3 -3v-8a3 3 0 0 1 3 -3h12z"/></Icon>
}
export function IconLogout(p: IconProps) {
  return <Icon {...p}><path d="M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2"/><path d="M7 12h14l-3 -3m0 6l3 -3"/></Icon>
}
export function IconCrown(p: IconProps) {
  return <Icon {...p}><path d="M12 6l4 6l5 -4l-2 10h-14l-2 -10l5 4z"/></Icon>
}
export function IconBolt(p: IconProps) {
  return <Icon {...p}><polyline points="13 3 13 10 19 10 11 21 11 14 5 14 13 3"/></Icon>
}
export function IconAlertTriangle(p: IconProps) {
  return <Icon {...p}><path d="M12 9v4"/><path d="M10.363 3.591l-8.106 13.534a1.914 1.914 0 0 0 1.636 2.871h16.214a1.914 1.914 0 0 0 1.636 -2.871l-8.106 -13.534a1.914 1.914 0 0 0 -3.274 0z"/><path d="M12 16v.01"/></Icon>
}
export function IconInfoCircle(p: IconProps) {
  return <Icon {...p}><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12.01" y2="8"/><polyline points="11 12 12 12 12 16 13 16"/></Icon>
}
export function IconDots(p: IconProps) {
  return <Icon {...p}><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></Icon>
}
export function IconBookmark(p: IconProps) {
  return <Icon {...p}><path d="M9 4h6a2 2 0 0 1 2 2v14l-5 -3l-5 3v-14a2 2 0 0 1 2 -2"/></Icon>
}
export function IconLink(p: IconProps) {
  return <Icon {...p}><path d="M9 15l6 -6"/><path d="M11 6l.463 -.536a5 5 0 0 1 7.072 7.072l-.535 .464"/><path d="M13 18l-.464 .536a5 5 0 0 1 -7.071 -7.072l.535 -.464"/></Icon>
}
export function IconQRCode(p: IconProps) {
  return <Icon {...p}><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><path d="M14 14h.01"/><path d="M18 14h.01"/><path d="M14 18h.01"/><path d="M18 18h.01"/></Icon>
}
export function IconAdjustments(p: IconProps) {
  return <Icon {...p}><circle cx="14" cy="6" r="2"/><line x1="4" y1="6" x2="12" y2="6"/><line x1="16" y1="6" x2="20" y2="6"/><circle cx="8" cy="12" r="2"/><line x1="4" y1="12" x2="6" y2="12"/><line x1="10" y1="12" x2="20" y2="12"/><circle cx="17" cy="18" r="2"/><line x1="4" y1="18" x2="15" y2="18"/><line x1="19" y1="18" x2="20" y2="18"/></Icon>
}
export function IconTelegram(p: IconProps) {
  return <Icon {...p}><path d="M15 10l-4 4l6 6l4 -16l-18 7l4 2l2 6l3 -4"/></Icon>
}
export function IconPhone(p: IconProps) {
  return <Icon {...p}><path d="M5 4h4l2 5l-2.5 1.5a11 11 0 0 0 5 5l1.5 -2.5l5 2v4a2 2 0 0 1 -2 2a16 16 0 0 1 -15 -15a2 2 0 0 1 2 -2"/></Icon>
}
export function IconMail(p: IconProps) {
  return <Icon {...p}><rect x="3" y="5" width="18" height="14" rx="2"/><polyline points="3 7 12 13 21 7"/></Icon>
}
export function IconLanguage(p: IconProps) {
  return <Icon {...p}><path d="M4 5h7"/><path d="M9 3v2c0 4.418 -2.239 8 -5 8"/><path d="M5 9c-.003 2.144 2.952 3.908 6.7 4"/><path d="M12 20l4 -9l4 9"/><path d="M19.1 18h-6.2"/></Icon>
}
export function IconCurrencyDollar(p: IconProps) {
  return <Icon {...p}><path d="M16.7 8a3 3 0 0 0 -2.7 -2h-4a3 3 0 0 0 0 6h4a3 3 0 0 1 0 6h-4a3 3 0 0 1 -2.7 -2"/><path d="M12 3v3m0 12v3"/></Icon>
}
export function IconMoon(p: IconProps) {
  return <Icon {...p}><path d="M12 3c.132 0 .263 0 .393 0a7.5 7.5 0 0 0 7.92 12.446a9 9 0 1 1 -8.313 -12.454z"/></Icon>
}
export function IconLock(p: IconProps) {
  return <Icon {...p}><rect x="5" y="11" width="14" height="10" rx="2"/><circle cx="12" cy="16" r="1"/><path d="M8 11v-4a4 4 0 0 1 8 0v4"/></Icon>
}
export function IconShield(p: IconProps) {
  return <Icon {...p}><path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3"/></Icon>
}
export function IconArrowLeft(p: IconProps) {
  return <Icon {...p}><line x1="5" y1="12" x2="19" y2="12"/><path d="M5 12l6 -6"/><path d="M5 12l6 6"/></Icon>
}
export function IconCircleCheck(p: IconProps) {
  return <Icon {...p}><path d="M17 3.34a10 10 0 1 1 -14.995 8.984l-.005 -.324l.005 -.324a10 10 0 0 1 14.995 -8.336zm-1.293 5.953a1 1 0 0 0 -1.32 -.083l-.094 .083l-3.293 3.292l-1.293 -1.292l-.094 -.083a1 1 0 0 0 -1.403 1.403l.083 .094l2 2l.094 .083a1 1 0 0 0 1.226 0l.094 -.083l4 -4l.083 -.094a1 1 0 0 0 -.083 -1.32z" fill="currentColor" strokeWidth="0"/></Icon>
}
export function IconBan(p: IconProps) {
  return <Icon {...p}><circle cx="12" cy="12" r="9"/><line x1="5.7" y1="5.7" x2="18.3" y2="18.3"/></Icon>
}
export function IconArchive(p: IconProps) {
  return <Icon {...p}><rect x="3" y="4" width="18" height="4" rx="2"/><path d="M5 8v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-10"/><line x1="10" y1="12" x2="14" y2="12"/></Icon>
}
export function IconFlag(p: IconProps) {
  return <Icon {...p}><path d="M5 21v-16"/><path d="M5 9h8l3 -3l-3 -3h-8v6z" fill="currentColor" strokeWidth="0"/></Icon>
}
export function IconStar(p: IconProps) {
  return <Icon {...p}><path d="M12 17.75l-6.172 3.245l1.179 -6.873l-5 -4.867l6.9 -1l3.086 -6.253l3.086 6.253l6.9 1l-5 4.867l1.179 6.873z"/></Icon>
}
export function IconCloudUpload(p: IconProps) {
  return <Icon {...p}><path d="M7 18a4.6 4.4 0 0 1 0 -9a5 4.5 0 0 1 11 2h1a3.5 3.5 0 0 1 0 7h-1"/><polyline points="9 15 12 12 15 15"/><line x1="12" y1="12" x2="12" y2="21"/></Icon>
}
export function IconRefresh(p: IconProps) {
  return <Icon {...p}><path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4"/><path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4"/></Icon>
}
export function IconWifi(p: IconProps) {
  return <Icon {...p}><path d="M12 18l.01 0"/><path d="M9.172 15.172a4 4 0 0 1 5.656 0"/><path d="M6.343 12.343a8 8 0 0 1 11.314 0"/><path d="M3.515 9.515c4.686 -4.687 12.284 -4.687 17 0"/></Icon>
}
export function IconWifiOff(p: IconProps) {
  return <Icon {...p}><line x1="3" y1="3" x2="21" y2="21"/><path d="M10.584 10.587a4 4 0 0 0 4.828 4.828"/><path d="M6.343 12.343a8 8 0 0 1 10.362 -.346"/><path d="M3.515 9.515a12 12 0 0 1 3.544 -2.544m3.what 2a12 12 0 0 1 9.441 2.547"/><path d="M12 18l.01 0"/></Icon>
}
export function IconConfetti(p: IconProps) {
  return <Icon {...p}><path d="M4 5h2"/><path d="M5 4v2"/><path d="M11.5 4l-.5 2"/><path d="M18 5h2"/><path d="M19 4v2"/><path d="M15 9l-1 1"/><path d="M18 13l2 -.5"/><path d="M18 19h2"/><path d="M19 18v2"/><path d="M14 16.518l-6.518 -6.518l-4.39 9.58a1 1 0 0 0 1.329 1.329l9.579 -4.39z"/></Icon>
}
export function IconKey(p: IconProps) {
  return <Icon {...p}><circle cx="8" cy="15" r="4"/><line x1="11.314" y1="11.314" x2="20" y2="2.686"/><line x1="18" y1="5" x2="20" y2="7"/><line x1="15" y1="8" x2="17" y2="6"/></Icon>
}
export function IconLayoutGrid(p: IconProps) {
  return <Icon {...p}><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></Icon>
}
export function IconRuler(p: IconProps) {
  return <Icon {...p}><rect x="3" y="9" width="18" height="6" rx="1"/><path d="M7 9v4"/><path d="M12 9v2"/><path d="M17 9v4"/></Icon>
}
export function IconLayers(p: IconProps) {
  return <Icon {...p}><path d="M12 2l9 4.5l-9 4.5l-9 -4.5z"/><path d="M3 11l9 4.5l9 -4.5"/><path d="M3 16l9 4.5l9 -4.5"/></Icon>
}
export function IconActivity(p: IconProps) {
  return <Icon {...p}><path d="M3 12h4l3 -9l4 18l3 -9h4"/></Icon>
}
export function IconDroplet(p: IconProps) {
  return <Icon {...p}><path d="M12 3c-4.418 4.821 -6 7.679 -6 10a6 6 0 0 0 12 0c0 -2.321 -1.582 -5.179 -6 -10z"/></Icon>
}
export function IconFlame(p: IconProps) {
  return <Icon {...p}><path d="M12 12c2 -2.96 0 -7 -1 -8c0 3.038 -1.773 4.741 -3 6c-1.226 1.26 -2 3.24 -2 5a6 6 0 1 0 12 0c0 -1.532 -1.056 -3.94 -2 -5c-1.786 3 -2.791 3 -4 2z"/></Icon>
}
export function IconThermometer(p: IconProps) {
  return <Icon {...p}><path d="M10 13.5a4 4 0 1 0 4 0v-8.5a2 2 0 0 0 -4 0v8.5"/><line x1="10" y1="9" x2="14" y2="9"/></Icon>
}
export function IconBatteryCharging(p: IconProps) {
  return <Icon {...p}><path d="M16 7h1a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-1"/><path d="M10 7h-5a2 2 0 0 0 -2 2v6c0 1.1 .9 2 2 2h5"/><path d="M12 15l1 -4h-3l1 -4"/><path d="M20 11v2"/></Icon>
}
export function IconChevronUp(p: IconProps) {
  return <Icon {...p}><polyline points="6 15 12 9 18 15"/></Icon>
}
export function IconChevronDown(p: IconProps) {
  return <Icon {...p}><polyline points="6 9 12 15 18 9"/></Icon>
}

export function IconCalendar(p: IconProps) {
  return (
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" stroke={p.color ?? 'currentColor'} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>
    </svg>
  )
}

export function IconBellRing(p: IconProps) {
  return (
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" stroke={p.color ?? 'currentColor'} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/><path d="M21 8A9 9 0 0 0 3 8"/>
    </svg>
  )
}

export function IconCheckCircle(p: IconProps) {
  return (
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" stroke={p.color ?? 'currentColor'} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
    </svg>
  )
}

export function IconClock(p: IconProps) {
  return (
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none" stroke={p.color ?? 'currentColor'} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
    </svg>
  )
}
