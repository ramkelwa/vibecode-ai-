import { useMemo, useState } from 'react'
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Search,
  X,
} from 'lucide-react'
import type { Finding, Severity } from '../api'
import { ConfidenceBadge, EmptyState, ErrorState, Panel, SeverityBadge } from './ui'

const PAGE_SIZE = 10
const SEVERITIES: Array<Severity | 'all'> = ['all', 'critical', 'high', 'medium', 'low', 'info']
const CONFIDENCES = ['all', 'certain', 'firm', 'uncertain', 'unknown']
const SORTS = [
  { key: 'severity', label: 'Severity (high first)' },
  { key: 'title', label: 'Title (A→Z)' },
  { key: 'module', label: 'Source module' },
] as const

export default function FindingsExplorer({
  findings,
  loading,
  error,
  onRetry,
}: {
  findings: Finding[]
  loading: boolean
  error: string | null
  onRetry: () => void
}) {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<string>('all')
  const [confidence, setConfidence] = useState<string>('all')
  const [category, setCategory] = useState<string>('all')
  const [sort, setSort] = useState<string>('severity')
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<Finding | null>(null)

  const categories = useMemo(
    () => Array.from(new Set(findings.map((f) => f.category))).sort(),
    [findings],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    let list = findings.filter((f) => {
      if (q) {
        const haystack = `${f.title} ${f.description} ${f.affected_asset} ${f.source_module}`.toLowerCase()
        if (!haystack.includes(q)) return false
      }
      if (severity !== 'all' && f.severity !== severity) return false
      if (confidence !== 'all' && f.confidence !== confidence) return false
      if (category !== 'all' && f.category !== category) return false
      return true
    })
    list = [...list].sort((a, b) => {
      if (sort === 'title') return a.title.localeCompare(b.title)
      if (sort === 'module')
        return a.source_module.localeCompare(b.source_module) || a.title.localeCompare(b.title)
      const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return (
        (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5) || a.title.localeCompare(b.title)
      )
    })
    return list
  }, [findings, search, severity, confidence, category, sort])

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const safePage = Math.min(page, pageCount - 1)
  const pageItems = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE)

  const resetPaging = () => {
    setPage(0)
    setSelected(null)
  }

  return (
    <div className="space-y-6">
      <Panel
        title="Findings explorer"
        testId="explorer-panel"
        actions={
          <span
            className="rounded-full border border-zinc-800 bg-zinc-900 px-3 py-1 text-xs font-medium text-zinc-400"
            data-testid="explorer-count"
          >
            {filtered.length} of {findings.length} findings
          </span>
        }
      >
        {/* Search & Filter Toolbar */}
        <div className="mb-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-5">
          <div className="sm:col-span-2">
            <label className="flex flex-col gap-1 text-xs font-medium text-zinc-400">
              Search findings
              <div className="relative">
                <Search className="absolute left-3 top-3 h-3.5 w-3.5 text-zinc-500" aria-hidden />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    resetPaging()
                  }}
                  placeholder="title, asset, module…"
                  aria-label="Search findings"
                  className="vin-input w-full pl-9 text-sm"
                />
              </div>
            </label>
          </div>

          <SelectFilter
            label="Severity"
            value={severity}
            options={SEVERITIES.map((s) => ({ value: s, label: s }))}
            onChange={(v) => {
              setSeverity(v)
              resetPaging()
            }}
          />

          <SelectFilter
            label="Confidence"
            value={confidence}
            options={CONFIDENCES.map((c) => ({ value: c, label: c }))}
            onChange={(v) => {
              setConfidence(v)
              resetPaging()
            }}
          />

          <SelectFilter
            label="Category"
            value={category}
            options={[{ value: 'all', label: 'all' }, ...categories.map((c) => ({ value: c, label: c }))]}
            onChange={(v) => {
              setCategory(v)
              resetPaging()
            }}
          />
        </div>

        {/* Sort toolbar */}
        <div className="mb-4 flex items-center justify-between border-b border-zinc-800/40 pb-3 text-xs">
          <div className="flex items-center gap-2">
            <ArrowUpDown className="h-3.5 w-3.5 text-zinc-500" aria-hidden />
            <span className="font-medium text-zinc-400">Sort</span>
            <select
              value={sort}
              onChange={(e) => {
                setSort(e.target.value)
                resetPaging()
              }}
              aria-label="Sort findings"
              className="vin-input py-1 px-2.5 text-xs font-medium bg-zinc-900 border-zinc-700/60"
            >
              {SORTS.map((s) => (
                <option key={s.key} value={s.key}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* List states */}
        {error ? (
          <div className="space-y-3">
            <ErrorState message={error} onRetry={onRetry} />
            <EmptyState
              message="Findings unavailable."
              hint="The explorer shows real stored findings only; retry reloads them from the API."
            />
          </div>
        ) : loading && findings.length === 0 ? (
          <p className="text-sm text-zinc-400 py-4" role="status">
            Loading findings…
          </p>
        ) : findings.length === 0 ? (
          <EmptyState
            message="No findings recorded for this scan."
            hint="Either the scan has not run yet or its modules found nothing — the explorer never shows simulated results."
          />
        ) : filtered.length === 0 ? (
          <EmptyState message="No findings match the current filters." hint="Adjust search or filters." />
        ) : (
          <>
            <ul
              className="divide-y divide-zinc-800/60 rounded-lg border border-zinc-800/60 bg-zinc-900/30"
              data-testid="explorer-list"
            >
              {pageItems.map((f) => (
                <li key={f.id}>
                  <button
                    type="button"
                    onClick={() => setSelected(f)}
                    className="flex w-full items-center gap-3 px-3.5 py-3 text-left text-sm transition-colors hover:bg-zinc-800/40 focus:outline-none focus:bg-zinc-800/50"
                    aria-label={`finding ${f.title}`}
                  >
                    <SeverityBadge severity={f.severity} />
                    <span className="min-w-0 flex-1 truncate font-medium text-zinc-200">
                      {f.title}
                    </span>
                    <ConfidenceBadge confidence={f.confidence} />
                    <span className="hidden font-mono text-xs text-zinc-400 md:block max-w-[140px] truncate shrink-0">
                      {f.source_module}
                    </span>
                  </button>
                </li>
              ))}
            </ul>

            {/* Pagination Controls */}
            {pageCount > 1 && (
              <div
                className="mt-4 flex items-center justify-between text-xs text-zinc-400 pt-2"
                data-testid="explorer-pagination"
              >
                <span>
                  Page {safePage + 1} of {pageCount}
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    aria-label="Previous page"
                    disabled={safePage === 0}
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    className="vin-btn-ghost p-1.5 disabled:opacity-40"
                  >
                    <ChevronLeft className="h-4 w-4" aria-hidden />
                  </button>
                  <button
                    type="button"
                    aria-label="Next page"
                    disabled={safePage >= pageCount - 1}
                    onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                    className="vin-btn-ghost p-1.5 disabled:opacity-40"
                  >
                    <ChevronRight className="h-4 w-4" aria-hidden />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </Panel>

      {/* Selected Finding Detail Drawer/Card */}
      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function SelectFilter({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: string
  options: Array<{ value: string; label: string }>
  onChange: (v: string) => void
}) {
  return (
    <label className="flex flex-col gap-1 text-xs font-medium text-zinc-400">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={label}
        className="vin-input py-2 text-xs font-medium bg-zinc-900 border-zinc-700/60"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  )
}

export function FindingDetail({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <Panel
      title="Finding detail"
      testId="finding-detail"
      actions={
        <button
          type="button"
          onClick={onClose}
          aria-label="Close finding detail"
          className="vin-btn-ghost px-3 py-1 text-xs"
        >
          <X className="h-3.5 w-3.5" aria-hidden />
          Close
        </button>
      }
    >
      <div className="space-y-4">
        <h3 className="text-base font-semibold text-zinc-100">{finding.title}</h3>

        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-4 text-xs">
          <DetailRow label="Severity" value={<SeverityBadge severity={finding.severity} />} />
          <DetailRow label="Confidence" value={<ConfidenceBadge confidence={finding.confidence} />} />
          <DetailRow label="Verification status" value={<span className="font-mono text-zinc-300">{finding.verification_status}</span>} />
          <DetailRow label="Category" value={<span className="text-zinc-300">{finding.category}</span>} />
          <DetailRow label="Source module" value={<span className="font-mono text-zinc-300">{finding.source_module}</span>} />
          <DetailRow
            label="Affected asset"
            value={<span className="break-all font-mono text-zinc-300">{finding.affected_asset}</span>}
          />
          <DetailRow label="CWE" value={<span className="font-mono text-sky-400">{finding.cwe ?? 'not reported'}</span>} />

          <DetailRow
            label="Evidence (redacted by the source module)"
            value={
              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] text-zinc-300">
                {JSON.stringify(finding.evidence ?? {}, null, 2)}
              </pre>
            }
            full
          />

          {finding.description && <DetailRow label="Observation" value={<p className="text-zinc-300 leading-relaxed">{finding.description}</p>} full />}
          {finding.impact && <DetailRow label="Impact" value={<p className="text-zinc-300 leading-relaxed">{finding.impact}</p>} full />}
          {finding.remediation && (
            <DetailRow
              label="Remediation guidance"
              value={
                <div className="rounded-lg border border-sky-500/30 bg-sky-950/20 p-3 text-sky-200">
                  <p className="leading-relaxed">{finding.remediation}</p>
                </div>
              }
              full
              testId="finding-remediation"
            />
          )}
        </dl>

        <p className="text-[11px] text-zinc-500">
          Evidence is shown exactly as the source module stored it (secret-like values are redacted at
          capture time). Verification status is provided by the scanner modules and is never upgraded
          by the UI.
        </p>
      </div>
    </Panel>
  )
}

function DetailRow({
  label,
  value,
  full,
  testId,
}: {
  label: string
  value: React.ReactNode
  full?: boolean
  testId?: string
}) {
  return (
    <div className={full ? 'col-span-full' : ''} data-testid={testId}>
      <dt className="text-zinc-400 font-medium mb-0.5">{label}</dt>
      <dd className="text-zinc-300">{value}</dd>
    </div>
  )
}
