import { useState } from 'react'
import { api, ApiError, type ScanSummary } from '../api'
import { PROJECT_MODULES, WEBSITE_MODULES } from './moduleList'
import { Panel } from './ui'

export const isValidTargetUrl = (url: string): boolean => {
  const v = url.trim()
  if (!/^https?:\/\//i.test(v)) return false
  try {
    const u = new URL(v)
    return !!u.hostname
  } catch {
    return false
  }
}

export const isValidProjectDir = (dir: string): boolean => {
  const v = dir.trim()
  return v.length > 1 && (v.includes('/') || v.includes('\\'))
}

type Kind = 'website' | 'project'

export default function NewScanForm({
  allowedToScan,
  onError,
  onSubmitted,
}: {
  allowedToScan: boolean
  onError: (message: string) => void
  onSubmitted: (scan: ScanSummary) => void
}) {
  const [kind, setKind] = useState<Kind>('website')
  const [targetUrl, setTargetUrl] = useState('')
  const [projectDir, setProjectDir] = useState('')
  const [websiteModules, setWebsiteModules] = useState<string[]>([...WEBSITE_MODULES])
  const [projectModules, setProjectModules] = useState<string[]>([...PROJECT_MODULES])
  const [pending, setPending] = useState(false)
  const [validationHint, setValidationHint] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [submittedScan, setSubmittedScan] = useState<ScanSummary | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (pending) return // no duplicate submissions while a request is in flight
    setFormError(null)
    setValidationHint(null)

    if (kind === 'website' && !isValidTargetUrl(targetUrl)) {
      setValidationHint('Enter a valid http:// or https:// URL with a hostname.')
      return
    }
    if (kind === 'project' && !isValidProjectDir(projectDir)) {
      setValidationHint('Enter an absolute project directory path (e.g. /home/you/projects/app).')
      return
    }

    setPending(true)
    try {
      const { scan } =
        kind === 'website'
          ? await api.createScan(targetUrl.trim(), websiteModules)
          : await api.createProjectScan(projectDir.trim(), projectModules)
      setSubmittedScan(scan)
      onSubmitted(scan)
    } catch (err: unknown) {
      // Show the backend's actual validation/authorization message.
      const message =
        err instanceof ApiError
          ? err.detail
          : err instanceof Error
            ? err.message
            : String(err)
      setFormError(message)
      onError(message)
    } finally {
      setPending(false)
    }
  }

  const toggle = (
    list: string[],
    setList: (v: string[]) => void,
    m: string,
  ) => setList(list.includes(m) ? list.filter((x) => x !== m) : [...list, m])

  return (
    <Panel title="Start a new scan" testId="new-scan-panel">
      <div className="mb-3 flex gap-2" role="tablist" aria-label="scan type">
        {(['website', 'project'] as const).map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            aria-selected={kind === k}
            onClick={() => setKind(k)}
            className={`rounded px-3 py-1 text-xs font-medium ${
              kind === k ? 'bg-sky-900/60 text-sky-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {k === 'website' ? 'Passive website scan' : 'Authorized project scan'}
          </button>
        ))}
      </div>

      <form onSubmit={submit} className="flex flex-col gap-3">
        {kind === 'website' ? (
          <>
            <div className="flex gap-2">
              <input
                type="text"
                required
                aria-label="Target URL"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://target.example.com"
                className="flex-1 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-600"
              />
              <button
                type="submit"
                disabled={pending || !allowedToScan}
                aria-busy={pending}
                className="rounded bg-sky-700 px-4 py-2 text-sm font-medium hover:bg-sky-600 disabled:opacity-50"
              >
                {pending ? 'Submitting…' : 'Start scan'}
              </button>
            </div>
            <fieldset className="flex flex-wrap gap-3 text-xs">
              <legend className="mb-1 text-slate-500">Modules</legend>
              {WEBSITE_MODULES.map((m) => (
                <label key={m} className="flex items-center gap-1.5 text-slate-300">
                  <input
                    type="checkbox"
                    checked={websiteModules.includes(m)}
                    onChange={() => toggle(websiteModules, setWebsiteModules, m)}
                    className="accent-sky-600"
                  />
                  {m}
                </label>
              ))}
            </fieldset>
            <p className="text-xs text-slate-500" data-testid="scope-notice">
              <span className="font-medium text-slate-400">Scope & authorization:</span> scans only
              this single URL at a limited rate (passive GETs, no active exploitation). By starting
              a scan you confirm you are authorized to test this target.
            </p>
          </>
        ) : (
          <>
            <div className="flex gap-2">
              <input
                type="text"
                required
                aria-label="Project directory"
                value={projectDir}
                onChange={(e) => setProjectDir(e.target.value)}
                placeholder="/home/you/projects/my-app"
                className="flex-1 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-600"
              />
              <button
                type="submit"
                disabled={pending || !allowedToScan}
                aria-busy={pending}
                className="rounded bg-sky-700 px-4 py-2 text-sm font-medium hover:bg-sky-600 disabled:opacity-50"
              >
                {pending ? 'Submitting…' : 'Start project scan'}
              </button>
            </div>
            <fieldset className="flex flex-wrap gap-3 text-xs">
              <legend className="mb-1 text-slate-500">Modules</legend>
              {PROJECT_MODULES.map((m) => (
                <label key={m} className="flex items-center gap-1.5 text-slate-300">
                  <input
                    type="checkbox"
                    checked={projectModules.includes(m)}
                    onChange={() => toggle(projectModules, setProjectModules, m)}
                    className="accent-sky-600"
                  />
                  {m}
                </label>
              ))}
            </fieldset>
            <p className="text-xs text-slate-500" data-testid="scope-notice-project">
              <span className="font-medium text-slate-400">Scope & authorization:</span> dependency
              audits and static source analysis against one local directory that the backend
              operator has authorized via AUTHORIZED_PROJECT_ROOTS. Nothing inside the project is
              executed; unavailable audit tools are recorded, not invented.
            </p>
          </>
        )}

        {validationHint && (
          <p className="text-sm text-amber-400" role="alert" data-testid="validation-hint">
            {validationHint}
          </p>
        )}
        {formError && (
          <p className="text-sm text-red-400" role="alert" data-testid="form-error">
            {formError}
          </p>
        )}
        {!allowedToScan && (
          <p className="text-sm text-amber-400" role="note">
            Scan persistence is unavailable (backend database down) — new scans are disabled.
          </p>
        )}
        {submittedScan && (
          <p className="text-sm text-emerald-400" data-testid="submitted-scan-id">
            Scan created — ID{' '}
            <span className="font-mono">{submittedScan.id}</span> ({submittedScan.status}). Progress
            updates in the Overview and History views.
          </p>
        )}
      </form>
    </Panel>
  )
}
