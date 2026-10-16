import { useMemo, useState } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'
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
      if (sort === 'module') return a.source_module.localeCompare(b.source_module) || a.title.localeCompare(b.title)
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
    <div className="space-y-4">
      <Panel
        title="Findings explorer"
        testId="explorer-panel"
        actions={
          <span className="text-xs text-slate-500" data-testid="explorer-count">
            {filtered.length} of {findings.length} findings
          </span>
        }
      >
        <div className="mb-3 grid grid-cols-1 gap-2 md:grid-cols-5">
          <label className="flex flex-col gap-1 text-xs text-slate-500 md:col-span-2">
            Search
            <input
              type="search"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                resetPaging()
              }}
              placeholder="title, asset, module…"
              aria-label="Search findings"
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm outline-none focus:border-sky-600"
            />
          </label>
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
        <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500">Sort</span>
          <select
            value={sort}
            onChange={(e) => {
              setSort(e.target.value)
              resetPaging()
            }}
            aria-label="Sort findings"
            className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs outline-none focus:border-sky-600"
          >
            {SORTS.map((s) => (
              <option key={s.key} value={s.key}>
                {s.label}
              </option>
            ))}
          </select>
        </div>

        {error ? (
          <div className="space-y-2">
            <ErrorState message={error} onRetry={onRetry} />
            <EmptyState
              message="Findings unavailable."
              hint="The explorer shows real stored findings only; retry reloads them from the API."
            />
          </div>
        ) : loading && findings.length === 0 ? (
          <p className="text-sm text-slate-500" role="status">
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
            <ul className="divide-y divide-slate-900" data-testid="explorer-list">
              {pageItems.map((f) => (
                <li key={f.id}>
                  <button
                    type="button"
                    onClick={() => setSelected(f)}
                    className="flex w-full items-center gap-2 py-2 text-left text-sm hover:text-sky-400"
                    aria-label={`finding ${f.title}`}
                  >
                    <SeverityBadge severity={f.severity} />
                    <span className="min-w-0 flex-1 truncate">{f.title}</span>
                    <ConfidenceBadge confidence={f.confidence} />
                    <span className="hidden w-32 shrink-0 truncate font-mono text-xs text-slate-600 md:block">
                      {f.source_module}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            {pageCount > 1 && (
              <div className="mt-3 flex items-center justify-between" data-testid="explorer-pagination">
                <span className="text-xs text-slate-500">
                  Page {safePage + 1} of {pageCount}
                </span>
                <span className="flex gap-2">
                  <button
                    type="button"
                    aria-label="Previous page"
                    disabled={safePage === 0}
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    className="rounded border border-slate-700 p-1 text-slate-400 disabled:opacity-40"
                  >
                    <ChevronLeft className="h-4 w-4" aria-hidden />
                  </button>
                  <button
                    type="button"
                    aria-label="Next page"
                    disabled={safePage >= pageCount - 1}
                    onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                    className="rounded border border-slate-700 p-1 text-slate-400 disabled:opacity-40"
                  >
                    <ChevronRight className="h-4 w-4" aria-hidden />
                  </button>
                </span>
              </div>
            )}
          </>
        )}
      </Panel>

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
    <label className="flex flex-col gap-1 text-xs text-slate-500">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={label}
        className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm outline-none focus:border-sky-600"
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
          className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-400 hover:text-slate-200"
        >
          Close
        </button>
      }
    >
      <h3 className="text-sm font-medium text-slate-200">{finding.title}</h3>
      <dl className="mt-2 grid grid-cols-1 gap-x-6 gap-y-1.5 text-xs md:grid-cols-2">
        <Row label="Severity" value={<SeverityBadge severity={finding.severity} />} />
        <Row label="Confidence" value={<ConfidenceBadge confidence={finding.confidence} />} />
        <Row label="Verification status" value={finding.verification_status} />
        <Row label="Category" value={finding.category} />
        <Row label="Source module" value={<span className="font-mono">{finding.source_module}</span>} />
        <Row
          label="Affected asset"
          value={<span className="break-all font-mono">{finding.affected_asset}</span>}
        />
        <Row label="CWE" value={finding.cwe ?? 'not reported'} />
        <Row
          label="Evidence (redacted by the source module)"
          value={
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-950 p-2 text-[11px] text-slate-400">
              {JSON.stringify(finding.evidence ?? {}, null, 2)}
            </pre>
          }
        />
        {finding.description && <Row label="Observation" value={finding.description} full />}
        {finding.impact && <Row label="Impact" value={finding.impact} full />}
        {finding.remediation && (
          <Row
            label="Remediation guidance"
            value={finding.remediation}
            full
            testId="finding-remediation"
          />
        )}
      </dl>
      <p className="mt-3 text-[11px] text-slate-600">
        Evidence is shown exactly as the source module stored it (secret-like values are redacted at
        capture time). Verification status is provided by the scanner modules and is never upgraded
        by the UI.
      </p>
    </Panel>
  )
}

function Row({
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
    <div className={full ? 'md:col-span-2' : ''} data-testid={testId}>
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-300">{value}</dd>
    </div>
  )
}
