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
      className={`relative z-20 m-3 w-60 shrink-0 flex-col gap-1 self-start rounded-2xl border border-slate-900/10 bg-[linear-gradient(165deg,rgba(255,255,255,0.96),rgba(240,252,236,0.97))] p-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_18px_40px_-30px_rgba(11,31,29,0.35)] backdrop-blur-xl md:sticky md:top-3 md:flex ${
        opened ? 'flex' : 'hidden md:flex'
      }`}
    >
      <div className="mb-5 flex items-center gap-2.5 px-1.5 pt-1">
        {/* Layered shield mark with a floating glass plate. */}
        <span className="relative grid h-10 w-10 place-items-center rounded-xl border border-sky-300/25 bg-[linear-gradient(160deg,rgba(45,106,86,0.22),rgba(106,159,140,0.18))] shadow-[inset_0_1px_0_rgba(255,255,255,0.35),0_6px_0_-1px_rgba(11,31,29,0.9),0_14px_24px_-12px_rgba(45,106,86,0.8)]">
          <span className="absolute inset-0 rounded-xl bg-gradient-to-b from-white/60 to-transparent opacity-60" />
          <Shield className="relative h-5 w-5 text-cyan-700 drop-shadow-[0_0_8px_rgba(45,106,86,0.8)]" aria-hidden />
        </span>
        <span className="leading-tight">
          <span className="block text-sm font-semibold tracking-tight text-slate-100">
            VibeShield
          </span>
          <span className="vin-kicker block !text-[9px] !tracking-[0.24em] text-cyan-700/60">
            AI Security
          </span>
        </span>
      </div>

      <p className="vin-kicker mb-2 px-2.5">Workspace</p>

      {ITEMS.map(({ key, label, icon: Icon }) => (
        <button
          key={key}
          type="button"
          onClick={() => onSelect(key)}
          aria-current={active === key ? 'page' : undefined}
          className="vin-nav-item"
        >
          <Icon
            className={`h-4 w-4 shrink-0 ${
              active === key ? 'text-cyan-700 drop-shadow-[0_0_6px_rgba(45,106,86,0.7)]' : 'opacity-70'
            }`}
            aria-hidden
          />
          <span className="truncate">{label}</span>
        </button>
      ))}

      <div className="mt-5 rounded-xl border border-slate-900/5 bg-slate-900/5 p-3">
        <p className="vin-kicker mb-1 !text-[9px]">Passive mode</p>
        <p className="text-[11px] leading-relaxed text-slate-500">
          Read-only assessment. No active exploitation, no simulated results.
        </p>
      </div>
    </nav>
  )
}
