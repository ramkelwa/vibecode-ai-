import {
  ClipboardList,
  FileBarChart,
  LayoutDashboard,
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

const ITEMS: Array<{ key: ViewKey; label: string; icon: typeof Shield }> = [
  { key: 'overview', label: 'Overview', icon: LayoutDashboard },
  { key: 'new-scan', label: 'New scan', icon: PlusCircle },
  { key: 'history', label: 'Scan history', icon: ClipboardList },
  { key: 'explorer', label: 'Findings explorer', icon: Search },
  { key: 'inventory', label: 'Endpoint & script inventory', icon: Package },
  { key: 'config', label: 'Configuration & dependencies', icon: Package },
  { key: 'virustotal', label: 'VirusTotal', icon: Shield },
  { key: 'reports', label: 'Report', icon: FileBarChart },
]

export default function Sidebar({
  active,
  onSelect,
  opened,
}: {
  active: ViewKey
  onSelect: (key: ViewKey) => void
  opened?: boolean
}) {
  return (
    <nav
      aria-label="Dashboard navigation"
      className={`flex w-56 shrink-0 flex-col gap-1 border-r border-slate-800 bg-slate-950 p-3 ${
        opened ? '' : 'hidden md:flex'
      } md:flex`}
    >
      <div className="mb-4 flex items-center gap-2 px-2 pt-1">
        <Shield className="h-5 w-5 text-sky-500" aria-hidden />
        <span className="text-sm font-semibold tracking-tight text-slate-200">VibeShield</span>
      </div>
      {ITEMS.map(({ key, label, icon: Icon }) => (
        <button
          key={key}
          type="button"
          onClick={() => onSelect(key)}
          aria-current={active === key ? 'page' : undefined}
          className={`flex items-center gap-2 rounded px-2 py-1.5 text-left text-sm ${
            active === key
              ? 'bg-sky-900/50 text-sky-300'
              : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
          }`}
        >
          <Icon className="h-4 w-4 shrink-0" aria-hidden />
          {label}
        </button>
      ))}
    </nav>
  )
}
