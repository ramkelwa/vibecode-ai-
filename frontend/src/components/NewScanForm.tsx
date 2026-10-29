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

export type ScanKind = 'website' | 'file' | 'project'

export type ScanSubmission =
  | { kind: 'website'; scan: ScanSummary; targetUrl: string; includeVirusTotal: boolean }
  | { kind: 'file'; scan: null; file: File }
  | { kind: 'project'; scan: ScanSummary; targetUrl: null }

export default function NewScanForm({
  allowedToScan,
  virustotalConfigured = false,
  onError,
  onSubmitted,
}: {
  allowedToScan: boolean
  virustotalConfigured?: boolean
  onError: (message: string) => void
  onSubmitted: (submission: ScanSubmission) => void
}) {
  const [kind, setKind] = useState<ScanKind>('website')
  const [targetUrl, setTargetUrl] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [projectDir, setProjectDir] = useState('')
  const [websiteModules, setWebsiteModules] = useState<string[]>([...WEBSITE_MODULES])
  const [projectModules, setProjectModules] = useState<string[]>([...PROJECT_MODULES])
  const [pending, setPending] = useState(false)
  const [validationHint, setValidationHint] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [submittedScan, setSubmittedScan] = useState<ScanSummary | null>(null)
  const [sharePromptOpen, setSharePromptOpen] = useState(false)

  const createScan = async (allowVirusTotal: boolean) => {
    if (pending) return
    setSharePromptOpen(false)
    setFormError(null)
    setPending(true)
    try {
      if (kind === 'file') {
        if (!selectedFile) throw new Error('Choose a file or APK first.')
        if (selectedFile.size > 32 * 1024 * 1024) {
          throw new Error('VirusTotal file submissions are limited to 32 MiB.')
        }
        if (!allowVirusTotal) return
        onSubmitted({ kind: 'file', scan: null, file: selectedFile })
        return
      }

      const { scan } =
        kind === 'website'
          ? await api.createScan(targetUrl.trim(), websiteModules)
          : await api.createProjectScan(projectDir.trim(), projectModules)
      setSubmittedScan(scan)
      if (kind === 'website') {
        onSubmitted({
          kind: 'website',
          scan,
          targetUrl: targetUrl.trim(),
          includeVirusTotal: allowVirusTotal,
        })
      } else {
        onSubmitted({ kind: 'project', scan, targetUrl: null })
      }
    } catch (err: unknown) {
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

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (pending) return
    setFormError(null)
    setValidationHint(null)
    if (kind === 'website' && !isValidTargetUrl(targetUrl)) {
      setValidationHint('Enter a valid http:// or https:// URL with a hostname.')
      return
    }
    if (kind === 'file' && !selectedFile) {
      setValidationHint('Choose a file or APK to scan.')
      return
    }
    if (kind === 'project' && !isValidProjectDir(projectDir)) {
      setValidationHint('Enter an absolute project directory path (e.g. /home/you/projects/app).')
      return
    }
    if ((kind === 'website' || kind === 'file') && virustotalConfigured) {
      setSharePromptOpen(true)
      return
    }
    if (kind === 'file') {
      setFormError('VirusTotal is not configured. Configure its API key before scanning files or APKs.')
      return
    }
    void createScan(false)
  }

  const toggle = (list: string[], setList: (value: string[]) => void, module: string) =>
    setList(list.includes(module) ? list.filter((item) => item !== module) : [...list, module])

  return (
    <Panel title="Start a new scan" testId="new-scan-panel">
      <div className="mb-3 flex flex-wrap gap-2" role="tablist" aria-label="scan type">
        {(['website', 'file', 'project'] as const).map((scanKind) => (
          <button
            key={scanKind}
            type="button"
            role="tab"
            aria-selected={kind === scanKind}
            disabled={sharePromptOpen || pending}
            onClick={() => setKind(scanKind)}
            className={`rounded px-3 py-1 text-xs font-medium ${
              kind === scanKind ? 'bg-sky-900/60 text-sky-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {scanKind === 'website'
              ? 'Website URL'
              : scanKind === 'file'
                ? 'File / APK'
                : 'Authorized project scan'}
          </button>
        ))}
      </div>

      <form onSubmit={submit} className="flex flex-col gap-3">
        {kind === 'website' && (
          <>
            <label htmlFor="scan-target-url" className="text-xs font-medium text-slate-400">
              Website URL
            </label>
            <div className="flex flex-wrap gap-2">
              <input
                id="scan-target-url"
                type="text"
                required
                aria-label="Target URL"
                disabled={sharePromptOpen || pending}
                value={targetUrl}
                onChange={(event) => setTargetUrl(event.target.value)}
                placeholder="https://target.example.com"
                className="min-w-60 flex-1 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-600"
              />
              <button
                type="submit"
                disabled={pending || !allowedToScan}
                aria-busy={pending}
                className="rounded bg-sky-700 px-4 py-2 text-sm font-medium hover:bg-sky-600 disabled:opacity-50"
              >
                {pending ? 'Starting…' : 'Start combined scan'}
              </button>
            </div>
            <fieldset className="flex flex-wrap gap-3 text-xs">
              <legend className="mb-1 text-slate-500">VibeShield website modules</legend>
              {WEBSITE_MODULES.map((module) => (
                <label key={module} className="flex items-center gap-1.5 text-slate-300">
                  <input
                    type="checkbox"
                    checked={websiteModules.includes(module)}
                    onChange={() => toggle(websiteModules, setWebsiteModules, module)}
                    className="accent-sky-600"
                  />
                  {module}
                </label>
              ))}
            </fieldset>
            <p className="text-xs text-slate-500" data-testid="scope-notice">
              By starting the scan you confirm you are authorized to test this target. VibeShield
              performs a passive, rate-limited website scan. VirusTotal checks its
              public report and automatically requests a new analysis if none exists, after your
              confirmation below.
            </p>
          </>
        )}

        {kind === 'file' && (
          <>
            <label htmlFor="scan-file" className="text-xs font-medium text-slate-400">
              Choose a file or APK (maximum 32 MiB)
            </label>
            <input
              id="scan-file"
              type="file"
              disabled={sharePromptOpen || pending || !virustotalConfigured}
              onChange={(event) => setSelectedFile(event.currentTarget.files?.[0] ?? null)}
              className="block w-full text-sm text-slate-300 file:mr-3 file:rounded file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-xs file:text-slate-200 disabled:opacity-50"
            />
            {selectedFile && (
              <p className="break-all text-xs text-slate-400">
                Selected: {selectedFile.name} ({(selectedFile.size / (1024 * 1024)).toFixed(2)} MiB)
              </p>
            )}
            <p className="text-xs text-slate-500">
              VibeShield&apos;s own website scanner does not inspect binary files. The combined
              report will label these results as VirusTotal-only. Your file is uploaded only after
              you confirm, and VirusTotal may retain or share it.
            </p>
            <button
              type="submit"
              disabled={pending || !virustotalConfigured}
              aria-busy={pending}
              className="self-start rounded bg-sky-700 px-4 py-2 text-sm font-medium hover:bg-sky-600 disabled:opacity-50"
            >
              {pending ? 'Starting…' : 'Start file / APK scan'}
            </button>
          </>
        )}

        {kind === 'project' && (
          <>
            <div className="flex gap-2">
              <input
                type="text"
                required
                aria-label="Project directory"
                disabled={sharePromptOpen || pending}
                value={projectDir}
                onChange={(event) => setProjectDir(event.target.value)}
                placeholder="C:\\Users\\you\\projects\\app"
                className="flex-1 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-600"
              />
              <button
                type="submit"
                disabled={pending || !allowedToScan}
                aria-busy={pending}
                className="rounded bg-sky-700 px-4 py-2 text-sm font-medium hover:bg-sky-600 disabled:opacity-50"
              >
                {pending ? 'Starting…' : 'Start project scan'}
              </button>
            </div>
            <fieldset className="flex flex-wrap gap-3 text-xs">
              <legend className="mb-1 text-slate-500">Modules</legend>
              {PROJECT_MODULES.map((module) => (
                <label key={module} className="flex items-center gap-1.5 text-slate-300">
                  <input
                    type="checkbox"
                    checked={projectModules.includes(module)}
                    onChange={() => toggle(projectModules, setProjectModules, module)}
                    className="accent-sky-600"
                  />
                  {module}
                </label>
              ))}
            </fieldset>
            <p className="text-xs text-slate-500" data-testid="scope-notice-project">
              Authorized dependency audits and static source analysis against a directory allowed
              via AUTHORIZED_PROJECT_ROOTS. Project folder contents are not sent to VirusTotal.
            </p>
          </>
        )}

        {validationHint && <p className="text-sm text-amber-400" role="alert" data-testid="validation-hint">{validationHint}</p>}
        {formError && <p className="text-sm text-red-400" role="alert" data-testid="form-error">{formError}</p>}
        {!allowedToScan && kind !== 'file' && (
          <p className="text-sm text-amber-400" role="note">
            Scan persistence is unavailable (backend database down) — new scans are disabled for website and project targets.
          </p>
        )}
        {submittedScan && (
          <p className="text-sm text-emerald-400" data-testid="submitted-scan-id">
            VibeShield scan created — ID <span className="font-mono">{submittedScan.id}</span>{' '}
            ({submittedScan.status}). Results will be assembled below.
          </p>
        )}
      </form>

      {sharePromptOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Confirm combined VirusTotal scan"
          className="mt-3 rounded border border-amber-900 bg-amber-950/40 p-3 text-sm text-amber-200"
          data-testid="vt-url-consent"
        >
          <p className="mb-2 font-medium">Confirm the combined scan and VirusTotal sharing</p>
          <p className="mb-3 text-xs">
            {kind === 'website'
              ? 'VibeShield will scan the website. VirusTotal will receive the complete URL (including query parameters) to check its existing public report; if none exists, VibeShield will automatically submit the URL for a new VirusTotal analysis.'
              : `The complete file "${selectedFile?.name ?? ''}" and its hash will be sent to VirusTotal to check for an existing report. If none exists, the file will be automatically uploaded for analysis.`}
            {' '}VirusTotal may retain or publicly share submitted targets. Do not use private links,
            credentials, confidential files, or URLs containing secrets. A VirusTotal result is
            third-party intelligence and does not prove a site or file is safe.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => void createScan(true)}
              className="rounded bg-amber-700 px-3 py-1 text-xs font-medium text-white hover:bg-amber-600"
            >
              I agree — start combined scan
            </button>
            {kind === 'website' && (
              <button
                type="button"
                onClick={() => void createScan(false)}
                className="rounded border border-amber-800 px-3 py-1 text-xs text-amber-200"
              >
                VibeShield only
              </button>
            )}
            <button
              type="button"
              onClick={() => setSharePromptOpen(false)}
              className="rounded border border-slate-700 px-3 py-1 text-xs text-slate-300"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </Panel>
  )
}
