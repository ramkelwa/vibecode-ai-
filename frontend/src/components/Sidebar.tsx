import {
  Activity,
  ClipboardList,
  FileBarChart,
  LayoutDashboard,
  Menu,
  Package,
  Plus,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  X,
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
  { key: 'new-scan', label: 'New scan', short: 'New scan', icon: Plus },
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
    icon: Settings2,
  },
  { key: 'virustotal', label: 'VirusTotal', short: 'VirusTotal', icon: ShieldAlert },
  { key: 'reports', label: 'Report', short: 'Report', icon: FileBarChart },
]

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
      className="sticky top-0 z-40 border-b border-zinc-800/80 bg-zinc-950/80 backdrop-blur-md transition-colors"
    >
      <div className="mx-auto flex w-full max-w-[1440px] items-center justify-between gap-6 px-4 py-2.5 sm:px-6 md:px-10">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-sky-500/20 bg-sky-500/10 text-sky-400 shadow-[0_0_12px_rgba(56,189,248,0.15)]">
            <Shield className="h-4 w-4" aria-hidden />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold tracking-tight text-zinc-100">
                VibeShield
              </span>
              <span className="rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.2 text-[9px] font-semibold uppercase tracking-wider text-sky-400">
                AI
              </span>
            </div>
            <span className="hidden text-[10px] font-medium tracking-wider text-zinc-400 sm:inline uppercase">
              Security Console
            </span>
          </div>
        </div>

        {/* Desktop navigation tabs */}
        <div className="hidden items-center gap-1.5 md:flex">
          <div className="flex items-center gap-1 rounded-lg border border-zinc-800/60 bg-zinc-900/60 p-1">
            {ITEMS.map(({ key, label, short, icon: Icon }) => {
              const isSelected = active === key
              return (
                <button
                  key={key}
                  type="button"
                  onClick={() => onSelect(key)}
                  aria-current={isSelected ? 'page' : undefined}
                  title={label}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-all ${
                    isSelected
                      ? 'bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/60'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40'
                  }`}
                >
                  <Icon className={`h-3.5 w-3.5 ${isSelected ? 'text-sky-400' : 'opacity-70'}`} aria-hidden />
                  {short}
                </button>
              )
            })}
          </div>

          <button
            type="button"
            onClick={() => onSelect('new-scan')}
            className="vin-btn-primary ml-2 px-3.5 py-1.5 text-xs font-medium"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden />
            Start scan
          </button>
        </div>

        {/* Mobile toggle */}
        <button
          type="button"
          onClick={onToggle}
          aria-label="Toggle navigation"
          aria-expanded={opened}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900/60 text-zinc-300 md:hidden hover:bg-zinc-800 transition-colors"
        >
          {opened ? <X className="h-4 w-4" aria-hidden /> : <Menu className="h-4 w-4" aria-hidden />}
        </button>
      </div>

      {/* Mobile Drawer */}
      {opened && (
        <div className="border-t border-zinc-800/80 bg-zinc-950/95 px-5 pb-6 pt-3 shadow-2xl backdrop-blur-xl md:hidden">
          <div className="grid gap-1">
            {ITEMS.map(({ key, label, icon: Icon }) => {
              const isSelected = active === key
              return (
                <button
                  key={key}
                  type="button"
                  onClick={() => onSelect(key)}
                  aria-current={isSelected ? 'page' : undefined}
                  className={`flex items-center justify-between rounded-lg px-3.5 py-2.5 text-sm font-medium transition-all ${
                    isSelected
                      ? 'bg-zinc-800 text-zinc-100 border border-zinc-700/60'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                  }`}
                >
                  <span className="flex items-center gap-3">
                    <Icon className={`h-4 w-4 ${isSelected ? 'text-sky-400' : 'opacity-60'}`} aria-hidden />
                    {label}
                  </span>
                  <span className="text-xs text-zinc-500 font-mono">{isSelected ? '●' : '○'}</span>
                </button>
              )
            })}
          </div>

          <div className="mt-4 border-t border-zinc-800/60 pt-4">
            <button
              type="button"
              onClick={() => onSelect('new-scan')}
              className="vin-btn-primary w-full py-2.5 text-sm font-medium"
            >
              <Plus className="h-4 w-4" aria-hidden />
              Start new scan
            </button>
            <div className="mt-4 flex items-center gap-2 text-xs text-zinc-500">
              <Activity className="h-3.5 w-3.5 text-emerald-400" aria-hidden />
              <span>Passive assessment &middot; Zero simulated results</span>
            </div>
          </div>
        </div>
      )}
    </nav>
  )
}
