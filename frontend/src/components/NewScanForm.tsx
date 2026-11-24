import { useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  FileCode,
  FolderGit2,
  Globe,
  Loader2,
  Lock,
  Play,
  Shield,
  Upload,
} from 'lucide-react'
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
      {/* Modern tab strip */}
      <div
        className="mb-6 flex flex-wrap items-center gap-1.5 rounded-lg border border-zinc-800/60 bg-zinc-900/60 p-1"
        role="tablist"
        aria-label="scan type"
      >
        {(
          [
            { id: 'website', label: 'Website URL', icon: Globe },
            { id: 'file', label: 'File / APK', icon: FileCode },
            { id: 'project', label: 'Authorized project scan', icon: FolderGit2 },
          ] as const
        ).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={kind === id}
            disabled={sharePromptOpen || pending}
            onClick={() => setKind(id)}
            className={`flex items-center gap-2 rounded-md px-4 py-2 text-xs font-medium transition-all ${
              kind === id
                ? 'bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/60'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40'
            }`}
          >
            <Icon className={`h-3.5 w-3.5 ${kind === id ? 'text-sky-400' : 'opacity-70'}`} aria-hidden />
            {label}
          </button>
        ))}
      </div>

      <form onSubmit={submit} className="flex flex-col gap-5">
        {kind === 'website' && (
          <>
            <div className="flex flex-col gap-2">
              <label htmlFor="scan-target-url" className="text-xs font-medium text-zinc-400">
                Target Website URL
              </label>
              <div className="flex flex-wrap gap-2.5">
                <div className="relative flex-1 min-w-[280px]">
                  <Globe className="absolute left-3.5 top-3 h-4 w-4 text-zinc-500" aria-hidden />
                  <input
                    id="scan-target-url"
                    type="text"
                    required
                    aria-label="Target URL"
                    disabled={sharePromptOpen || pending}
                    value={targetUrl}
                    onChange={(event) => setTargetUrl(event.target.value)}
                    placeholder="https://target.example.com"
                    className="vin-input w-full pl-10 text-sm"
                  />
                </div>
                <button
                  type="submit"
                  disabled={pending || !allowedToScan}
                  aria-busy={pending}
                  className="vin-btn-primary px-5 py-2.5 text-sm font-medium shrink-0"
                >
                  {pending ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                      Starting…
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4" aria-hidden />
                      Start combined scan
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Modules Grid */}
            <fieldset className="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-4">
              <legend className="px-2 text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                VibeShield website modules
              </legend>
              <div className="mt-2 grid grid-cols-2 gap-2.5 sm:grid-cols-3 md:grid-cols-4 text-xs">
                {WEBSITE_MODULES.map((module) => {
                  const checked = websiteModules.includes(module)
                  return (
                    <label
                      key={module}
                      className={`flex items-center gap-2 rounded-md border p-2 cursor-pointer transition-colors ${
                        checked
                          ? 'border-sky-500/30 bg-sky-500/5 text-zinc-200'
                          : 'border-zinc-800/40 bg-zinc-900/40 text-zinc-400 hover:border-zinc-700/60'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggle(websiteModules, setWebsiteModules, module)}
                        className="rounded border-zinc-700 bg-zinc-800 text-sky-500 focus:ring-sky-500/20"
                      />
                      <span className="truncate">{module}</span>
                    </label>
                  )
                })}
              </div>
            </fieldset>

            <div className="flex items-start gap-2.5 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-xs text-zinc-400">
              <Shield className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" aria-hidden />
              <p data-testid="scope-notice">
                By starting the scan you confirm you are authorized to test this target. VibeShield
                performs a passive, rate-limited website scan. VirusTotal checks its
                public report and automatically requests a new analysis if none exists, after your
                confirmation below.
              </p>
            </div>
          </>
        )}

        {kind === 'file' && (
          <>
            <div className="flex flex-col gap-2">
              <label htmlFor="scan-file" className="text-xs font-medium text-zinc-400">
                Choose a file or APK (maximum 32 MiB)
              </label>
              <div className="relative">
                <input
                  id="scan-file"
                  type="file"
                  aria-label="Choose a file or APK"
                  disabled={sharePromptOpen || pending || !virustotalConfigured}
                  onChange={(event) => setSelectedFile(event.currentTarget.files?.[0] ?? null)}
                  className="vin-input block w-full text-sm file:mr-3 file:rounded-md file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-zinc-200 hover:file:bg-zinc-700"
                />
              </div>
              {selectedFile && (
                <div className="flex items-center gap-2 text-xs text-zinc-300 bg-zinc-900/60 p-2.5 rounded-md border border-zinc-800/60">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden />
                  <span className="truncate">
                    Selected: {selectedFile.name} ({(selectedFile.size / (1024 * 1024)).toFixed(2)} MiB)
                  </span>
                </div>
              )}
            </div>

            <div className="flex items-start gap-2.5 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-xs text-zinc-400">
              <Lock className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" aria-hidden />
              <p>
                VibeShield&apos;s own website scanner does not inspect binary files. The combined
                report will label these results as VirusTotal-only. Your file is uploaded only after
                you confirm, and VirusTotal may retain or share it.
              </p>
            </div>

            <button
              type="submit"
              disabled={pending || !virustotalConfigured}
              aria-busy={pending}
              className="vin-btn-primary self-start px-5 py-2.5 text-sm font-medium"
            >
              {pending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                  Starting…
                </>
              ) : (
                <>
                  <Upload className="h-4 w-4" aria-hidden />
                  Start file / APK scan
                </>
              )}
            </button>
          </>
        )}

        {kind === 'project' && (
          <>
            <div className="flex flex-col gap-2">
              <label htmlFor="scan-project-dir" className="text-xs font-medium text-zinc-400">
                Project Directory Path
              </label>
              <div className="flex gap-2.5">
                <div className="relative flex-1">
                  <FolderGit2 className="absolute left-3.5 top-3 h-4 w-4 text-zinc-500" aria-hidden />
                  <input
                    id="scan-project-dir"
                    type="text"
                    required
                    aria-label="Project directory"
                    disabled={sharePromptOpen || pending}
                    value={projectDir}
                    onChange={(event) => setProjectDir(event.target.value)}
                    placeholder="C:\Users\you\projects\app"
                    className="vin-input w-full pl-10 text-sm"
                  />
                </div>
                <button
                  type="submit"
                  disabled={pending || !allowedToScan}
                  aria-busy={pending}
                  className="vin-btn-primary px-5 py-2.5 text-sm font-medium shrink-0"
                >
                  {pending ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                      Starting…
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4" aria-hidden />
                      Start project scan
                    </>
                  )}
                </button>
              </div>
            </div>

            <fieldset className="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-4">
              <legend className="px-2 text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                Modules
              </legend>
              <div className="mt-2 flex flex-wrap gap-3 text-xs">
                {PROJECT_MODULES.map((module) => {
                  const checked = projectModules.includes(module)
                  return (
                    <label
                      key={module}
                      className={`flex items-center gap-2 rounded-md border p-2 cursor-pointer transition-colors ${
                        checked
                          ? 'border-sky-500/30 bg-sky-500/5 text-zinc-200'
                          : 'border-zinc-800/40 bg-zinc-900/40 text-zinc-400 hover:border-zinc-700/60'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggle(projectModules, setProjectModules, module)}
                        className="rounded border-zinc-700 bg-zinc-800 text-sky-500 focus:ring-sky-500/20"
                      />
                      <span>{module}</span>
                    </label>
                  )
                })}
              </div>
            </fieldset>

            <p className="text-xs text-zinc-500" data-testid="scope-notice-project">
              Authorized dependency audits and static source analysis against a directory allowed
              via AUTHORIZED_PROJECT_ROOTS. Project folder contents are not sent to VirusTotal.
            </p>
          </>
        )}

        {validationHint && (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-950/20 px-3.5 py-2.5 text-sm text-amber-300" role="alert" data-testid="validation-hint">
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden />
            <span>{validationHint}</span>
          </div>
        )}
        {formError && (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-950/20 px-3.5 py-2.5 text-sm text-red-300" role="alert" data-testid="form-error">
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden />
            <span>{formError}</span>
          </div>
        )}
        {!allowedToScan && kind !== 'file' && (
          <p className="text-sm text-amber-300 rounded-lg border border-amber-500/30 bg-amber-950/20 p-3" role="note">
            Scan persistence is unavailable (backend database down) — new scans are disabled for website and project targets.
          </p>
        )}
        {submittedScan && (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-950/20 px-4 py-3 text-sm text-emerald-300" data-testid="submitted-scan-id">
            <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden />
            <span>
              VibeShield scan created — ID <span className="font-mono font-semibold">{submittedScan.id}</span>{' '}
              ({submittedScan.status}). Results will be assembled below.
            </span>
          </div>
        )}
      </form>

      {/* Confirmation Dialog */}
      {sharePromptOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Confirm combined VirusTotal scan"
          className="mt-6 rounded-xl border border-amber-500/40 bg-zinc-900/95 p-5 shadow-2xl backdrop-blur-xl"
          data-testid="vt-url-consent"
        >
          <div className="flex items-center gap-2 text-amber-400 font-semibold mb-2">
            <AlertTriangle className="h-4 w-4" aria-hidden />
            <span>Confirm the combined scan and VirusTotal sharing</span>
          </div>
          <p className="mb-4 text-xs leading-relaxed text-zinc-300">
            {kind === 'website'
              ? 'VibeShield will scan the website. VirusTotal will receive the complete URL (including query parameters) to check its existing public report; if none exists, VibeShield will automatically submit the URL for a new VirusTotal analysis.'
              : `The complete file "${selectedFile?.name ?? ''}" and its hash will be sent to VirusTotal to check for an existing report. If none exists, the file will be automatically uploaded for analysis.`}
            {' '}VirusTotal may retain or publicly share submitted targets. Do not use private links,
            credentials, confidential files, or URLs containing secrets. A VirusTotal result is
            third-party intelligence and does not prove a site or file is safe.
          </p>
          <div className="flex flex-wrap gap-2.5">
            <button
              type="button"
              onClick={() => void createScan(true)}
              className="vin-btn-primary bg-amber-500 text-zinc-950 hover:bg-amber-400 border-amber-400/50 px-4 py-2 text-xs font-semibold"
            >
              I agree — start combined scan
            </button>
            {kind === 'website' && (
              <button
                type="button"
                onClick={() => void createScan(false)}
                className="vin-btn-ghost border-amber-500/30 text-amber-300 hover:bg-amber-500/10 px-4 py-2 text-xs"
              >
                VibeShield only
              </button>
            )}
            <button
              type="button"
              onClick={() => setSharePromptOpen(false)}
              className="vin-btn-ghost px-4 py-2 text-xs"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </Panel>
  )
}
