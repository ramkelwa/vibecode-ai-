import {
  ClipboardList,
  FileBarChart,
  LayoutDashboard,
  Menu,
  Package,
  PlusCircle,
  Search,
  Shield,
} from 'lucide-react'

export type ViewKey =
  | 'overview'
  | 'history'
  | 'new-scan'
  | 'explorer'
  | 'inventory'
  | 'config'
  | 'virustotal'
  | 'reports'

const ITEMS: Array<{ key: ViewKey; label: string; short: string; icon: typeof Shield }> = [
  { key: 'overview', label: 'Overview', short: 'Overview', icon: LayoutDashboard },
  { key: 'new-scan', label: 'New scan', short: 'New scan', icon: PlusCircle },
  { key: 'history', label: 'Scan history', short: 'History', icon: ClipboardList },
  { key: 'explorer', label: 'Findings explorer', short: 'Findings', icon: Search },
  {
    key: 'inventory',
    label: 'Endpoint & script inventory',
    short: 'Inventory',
    icon: Package,
  },
  {
    key: 'config',
    label: 'Configuration & dependencies',
    short: 'Config',
    icon: Package,
  },
  { key: 'virustotal', label: 'VirusTotal', short: 'VirusTotal', icon: Shield },
  { key: 'reports', label: 'Report', short: 'Report', icon: FileBarChart },
]

/**
 * Top navigation, editorial style: wordmark at the left, an inline index of the
 * views at the right, and a single ink action. Same destinations and the same
 * accessible names as the previous side rail — only the placement changed.
 */
export default function Sidebar({
  active,
  onSelect,
  opened,
  onToggle,
}: {
  active: ViewKey
  onSelect: (key: ViewKey) => void
  opened?: boolean
  onToggle?: () => void
}) {
  return (
    <nav
      aria-label="Dashboard navigation"
      className="sticky top-0 z-40 border-b border-slate-900/10 bg-white/85 backdrop-blur-md"
    >
      <div className="mx-auto flex w-full max-w-[1440px] items-center justify-between gap-6 px-5 py-3 md:px-10">
        <div className="flex items-baseline gap-3">
          <Shield className="h-[17px] w-[17px] translate-y-[2px] text-slate-100" aria-hidden />
          <span className="text-[15px] font-semibold tracking-[-0.02em] text-slate-100">
            VibeShield
          </span>
          <span className="vin-kicker hidden sm:inline">AI Security</span>
        </div>

        <div className="hidden items-center gap-6 md:flex">
          {ITEMS.map(({ key, label, short }) => (
            <button
              key={key}
              type="button"
              onClick={() => onSelect(key)}
              aria-current={active === key ? 'page' : undefined}
              title={label}
              className="vin-nav-link"
            >
              {short}
            </button>
          ))}
          <button
            type="button"
            onClick={() => onSelect('new-scan')}
            className="vin-btn-primary px-4 py-1.5 text-xs"
          >
            Start scan
          </button>
        </div>

        <button
          type="button"
          onClick={onToggle}
          aria-label="Toggle navigation"
          aria-expanded={opened}
          className="vin-btn-ghost p-2 md:hidden"
        >
          <Menu className="h-4 w-4" aria-hidden />
        </button>
      </div>

      {opened && (
        <div className="border-t border-slate-900/10 px-5 pb-5 pt-1 md:hidden">
          {ITEMS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              type="button"
              onClick={() => onSelect(key)}
              aria-current={active === key ? 'page' : undefined}
              className="vin-nav-mobile"
            >
              <span className="flex items-center gap-2.5">
                <Icon className="h-3.5 w-3.5 opacity-60" aria-hidden />
                {label}
              </span>
              <span className="vin-kicker">{key === active ? '●' : '○'}</span>
            </button>
          ))}
          <p className="vin-kicker mt-5">Passive mode</p>
          <p className="vin-prose mt-1 max-w-xs">
            Read-only assessment. No active exploitation, no simulated results.
          </p>
        </div>
      )}
    </nav>
  )
}
