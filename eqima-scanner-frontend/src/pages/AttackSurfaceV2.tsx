import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import api from '../api/client'
import keycloak from '../auth/keycloak'
import {
  Search, Loader, CheckCircle, AlertTriangle, Shield,
  Globe, FileWarning, Wifi, Clock, ChevronDown, ChevronRight,
  Database, ExternalLink, Radar
} from 'lucide-react'

type Job = {
  id: string
  domain: string
  status: 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED'
  currentPhase: string
  progress: number
  assetCount: number
  findingCount: number
  riskScore: number
  startedAt: string
  completedAt: string
  error: string
}

type Asset = {
  id: string
  type: string
  value: string
  ip: string
  asn: string
  country: string
  org: string
  active: boolean
  riskScore: number
}

type Finding = {
  id: string
  assetValue: string
  category: string
  title: string
  description: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  evidence: string
  remediation: string
  discoveredAt: string
}

type SseEvent = { type: string; data: string }

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-900/60 text-red-300 border-red-700',
  HIGH:     'bg-orange-900/60 text-orange-300 border-orange-700',
  MEDIUM:   'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  LOW:      'bg-blue-900/60 text-blue-300 border-blue-700',
  INFO:     'bg-gray-800 text-gray-400 border-gray-700',
}

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const CAT_ICONS: Record<string, JSX.Element> = {
  SENSITIVE_FILE: <FileWarning size={13}/>,
  MISSING_HEADER: <Shield size={13}/>,
  WEAK_TLS:       <Wifi size={13}/>,
  DNS_ISSUE:      <Globe size={13}/>,
  EXPOSED_TECH:   <Database size={13}/>,
  WAYBACK_URL:    <Clock size={13}/>,
}

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border font-mono uppercase shrink-0 ${SEV_COLORS[sev] ?? SEV_COLORS.INFO}`}>
      {sev}
    </span>
  )
}

function ScoreGauge({ score }: { score: number }) {
  const pct = Math.min(score / 10, 100)
  const color = score > 400 ? 'bg-red-500' : score > 200 ? 'bg-orange-500' : score > 80 ? 'bg-yellow-500' : 'bg-green-500'
  const label = score > 400 ? 'Critique' : score > 200 ? 'Élevé' : score > 80 ? 'Moyen' : 'Faible'
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-mono font-bold ${color.replace('bg-', 'text-')}`}>{score} — {label}</span>
    </div>
  )
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border-b border-gray-800/50">
      <div
        className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-800/30 cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <span className="text-gray-600 w-3">{open ? <ChevronDown size={12}/> : <ChevronRight size={12}/>}</span>
        <SevBadge sev={f.severity} />
        <span className="text-gray-500 shrink-0">{CAT_ICONS[f.category] ?? <Shield size={13}/>}</span>
        <span className="text-xs text-gray-200 flex-1 truncate">{f.title}</span>
        <span className="text-[10px] font-mono text-gray-600 shrink-0">{f.assetValue}</span>
      </div>
      {open && (
        <div className="px-10 pb-4 pt-1 space-y-3 bg-gray-900/40">
          <div>
            <p className="text-[10px] uppercase tracking-widest text-gray-600 font-mono mb-1">Description</p>
            <p className="text-xs text-gray-300 leading-relaxed">{f.description}</p>
          </div>
          {f.evidence && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-gray-600 font-mono mb-1">Evidence</p>
              <pre className="text-[11px] font-mono text-yellow-300 bg-gray-800/60 rounded px-3 py-2 whitespace-pre-wrap break-all">{f.evidence}</pre>
            </div>
          )}
          {f.remediation && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-gray-600 font-mono mb-1">Remédiation</p>
              <p className="text-xs text-green-300 leading-relaxed font-mono">{f.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function AttackSurfaceV2() {
  const [domain, setDomain] = useState('')
  const [jobId, setJobId] = useState<string | null>(null)
  const [launching, setLaunching] = useState(false)
  const [sseLog, setSseLog] = useState<SseEvent[]>([])
  const [ssePhase, setSsePhase] = useState('')
  const logRef = useRef<HTMLDivElement>(null)

  // Poll job status while running
  const { data: job, refetch: refetchJob } = useQuery<Job>({
    queryKey: ['surface-job', jobId],
    queryFn: () => api.get(`/v1/surface/scan/${jobId}`).then(r => r.data),
    enabled: !!jobId,
    refetchInterval: (q) => {
      const j = q.state.data as Job | undefined
      return j?.status === 'RUNNING' || j?.status === 'PENDING' ? 3000 : false
    },
  })

  // Fetch results when done
  const { data: results } = useQuery<{ assets: Asset[]; findings: Finding[] }>({
    queryKey: ['surface-results', jobId],
    queryFn: () => api.get(`/v1/surface/scan/${jobId}/results`).then(r => r.data),
    enabled: !!jobId && job?.status === 'DONE',
    staleTime: Infinity,
  })

  // Previous jobs
  const { data: pastJobs = [] } = useQuery<Job[]>({
    queryKey: ['surface-jobs'],
    queryFn: () => api.get('/v1/surface/scans').then(r => r.data),
    staleTime: 30_000,
  })

  // SSE stream
  useEffect(() => {
    if (!jobId) return

    const token = keycloak.token ?? ''
    const es = new EventSource(`${import.meta.env.VITE_API_URL ?? 'https://api-scanner.eqima.org'}/v1/surface/scan/${jobId}/stream?access_token=${token}`)

    const handle = (type: string) => (e: MessageEvent) => {
      if (type === 'phase') setSsePhase(e.data)
      setSseLog(prev => [...prev.slice(-150), { type, data: e.data }])
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
    }

    es.addEventListener('phase',    handle('phase'))
    es.addEventListener('step',     handle('step'))
    es.addEventListener('finding',  handle('finding'))
    es.addEventListener('progress', handle('progress'))
    es.addEventListener('done',     handle('done'))
    es.addEventListener('error',    handle('error'))
    es.onerror = () => { es.close(); refetchJob() }

    return () => es.close()
  }, [jobId])

  const launch = async () => {
    if (!domain.trim()) return
    setLaunching(true)
    setSseLog([])
    setSsePhase('')
    try {
      const { data } = await api.post(`/v1/surface/scan?domain=${encodeURIComponent(domain.trim())}`)
      setJobId(data.jobId)
    } finally {
      setLaunching(false)
    }
  }

  const findings   = results?.findings ?? []
  const assets     = results?.assets ?? []
  const byCategory = SEV_ORDER.reduce<Record<string, Finding[]>>((acc, sev) => {
    acc[sev] = findings.filter(f => f.severity === sev)
    return acc
  }, {})

  const subdomains = assets.filter(a => a.type === 'SUBDOMAIN')
  const ips        = assets.filter(a => a.type === 'IP')

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Scan form */}
      <div className="px-6 py-5 border-b border-gray-800 bg-gray-950/60 shrink-0">
        <div className="flex gap-2 max-w-2xl">
          <input
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && launch()}
            placeholder="Domaine cible : example.com"
            className="flex-1 bg-gray-800 border border-gray-700 text-red-300 font-mono text-sm px-4 py-2.5 rounded-lg focus:outline-none focus:border-red-600"
          />
          <button
            onClick={launch}
            disabled={!domain.trim() || launching || job?.status === 'RUNNING'}
            className="flex items-center gap-2 bg-red-700 hover:bg-red-600 disabled:opacity-40 text-white text-sm px-5 py-2.5 rounded-lg transition-colors font-medium"
          >
            {launching ? <Loader size={14} className="animate-spin"/> : <Radar size={14}/>}
            Lancer le scan complet
          </button>
        </div>
        <p className="text-[10px] text-gray-600 font-mono mt-1.5">
          Phase 1 passive (DNS, crt.sh, ASN, Wayback) → Phase 2 active (TLS, HTTP, fichiers sensibles) → Phase 3 scoring
        </p>
      </div>

      <div className="flex-1 flex overflow-hidden">

        {/* Left: live log + job list */}
        <div className="w-80 border-r border-gray-800 flex flex-col shrink-0">

          {/* Live log */}
          {jobId && (
            <div className="flex flex-col border-b border-gray-800" style={{ minHeight: '40%', maxHeight: '55%' }}>
              <div className="flex items-center justify-between px-4 py-2 bg-gray-800/40">
                <span className="text-[10px] uppercase tracking-widest text-gray-500 font-mono">Log temps réel</span>
                {job?.status === 'RUNNING' && <Loader size={10} className="animate-spin text-red-400"/>}
                {job?.status === 'DONE'    && <CheckCircle size={10} className="text-green-400"/>}
                {job?.status === 'FAILED'  && <AlertTriangle size={10} className="text-red-400"/>}
              </div>
              {job && (
                <div className="px-4 py-1.5 border-b border-gray-800/50">
                  <div className="flex items-center gap-2 mb-1">
                    <div className="flex-1 h-1 bg-gray-800 rounded overflow-hidden">
                      <div className="h-full bg-red-600 transition-all" style={{ width: `${job.progress}%` }}/>
                    </div>
                    <span className="text-[10px] font-mono text-gray-500">{job.progress}%</span>
                  </div>
                  <p className="text-[10px] text-gray-500 font-mono truncate">{job.currentPhase}</p>
                </div>
              )}
              <div ref={logRef} className="flex-1 overflow-auto px-3 py-2 space-y-0.5 font-mono text-[10px]">
                {sseLog.map((e, i) => (
                  <div key={i} className={
                    e.type === 'phase'   ? 'text-red-400 font-bold pt-1' :
                    e.type === 'finding' ? 'text-orange-300' :
                    e.type === 'error'   ? 'text-red-400' :
                    e.type === 'done'    ? 'text-green-400 font-bold' :
                    'text-gray-500'
                  }>
                    {e.type === 'phase' ? '▶ ' : e.type === 'finding' ? '⚠ ' : '  '}{
                      (() => {
                        try { const p = JSON.parse(e.data); return p.title ?? p.phase ?? e.data }
                        catch { return e.data }
                      })()
                    }
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Past jobs */}
          <div className="flex-1 overflow-auto">
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-mono px-4 py-2 border-b border-gray-800">
              Scans précédents
            </p>
            {pastJobs.map(j => (
              <button
                key={j.id}
                onClick={() => setJobId(j.id)}
                className={`w-full text-left px-4 py-2.5 border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${jobId === j.id ? 'bg-gray-800/50 border-l-2 border-l-red-600' : ''}`}
              >
                <p className="text-xs text-gray-200 font-mono truncate">{j.domain}</p>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className={`text-[10px] font-mono ${j.status === 'DONE' ? 'text-green-400' : j.status === 'FAILED' ? 'text-red-400' : 'text-yellow-400'}`}>
                    {j.status}
                  </span>
                  {j.findingCount > 0 && (
                    <span className="text-[10px] text-orange-400">{j.findingCount} findings</span>
                  )}
                  {j.riskScore > 0 && (
                    <span className="text-[10px] text-gray-600">score {j.riskScore}</span>
                  )}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Right: results */}
        <div className="flex-1 overflow-auto px-0 py-0">

          {/* Scanning state */}
          {job?.status === 'RUNNING' && (
            <div className="flex flex-col items-center justify-center h-full text-gray-600">
              <Loader size={40} className="animate-spin text-red-700 mb-4"/>
              <p className="font-mono text-sm text-gray-400">{ssePhase || 'Scan en cours…'}</p>
              <p className="text-xs mt-1">{job.domain}</p>
            </div>
          )}

          {/* Error */}
          {job?.status === 'FAILED' && (
            <div className="m-6 bg-red-950/40 border border-red-800 rounded-lg px-5 py-4 text-red-300 font-mono text-sm">
              Erreur : {job.error}
            </div>
          )}

          {/* Done: results */}
          {job?.status === 'DONE' && results && (
            <div className="p-6 space-y-6">

              {/* Summary */}
              <div className="grid grid-cols-4 gap-3">
                {[
                  { label: 'Assets découverts', value: job.assetCount, color: 'text-cyan-400' },
                  { label: 'Findings',           value: job.findingCount, color: 'text-orange-400' },
                  { label: 'Sous-domaines',      value: subdomains.length, color: 'text-green-400' },
                  { label: 'Score de risque',    value: job.riskScore, color: job.riskScore > 400 ? 'text-red-400' : job.riskScore > 200 ? 'text-orange-400' : 'text-yellow-400' },
                ].map(s => (
                  <div key={s.label} className="bg-gray-800/40 border border-gray-700 rounded-lg px-4 py-3">
                    <p className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</p>
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest mt-0.5">{s.label}</p>
                  </div>
                ))}
              </div>

              <ScoreGauge score={job.riskScore} />

              {/* Findings by severity */}
              <div>
                <p className="text-[10px] uppercase tracking-widest text-gray-500 font-mono mb-3">Findings par sévérité</p>
                <div className="border border-gray-800 rounded-lg overflow-hidden">
                  {/* Header */}
                  <div className="flex items-center gap-3 px-4 py-2 bg-gray-800/60 text-[10px] uppercase tracking-widest text-gray-500 font-mono">
                    <span className="w-3"/>
                    <span className="w-20">Sévérité</span>
                    <span className="w-6"/>
                    <span className="flex-1">Titre</span>
                    <span className="w-40">Asset</span>
                  </div>
                  {SEV_ORDER.filter(s => byCategory[s]?.length > 0).map(sev => (
                    <details key={sev} open={sev === 'CRITICAL' || sev === 'HIGH'}>
                      <summary className="flex items-center gap-2 px-4 py-2 bg-gray-800/20 cursor-pointer hover:bg-gray-800/40 list-none border-t border-gray-800">
                        <SevBadge sev={sev} />
                        <span className="text-xs text-gray-400 font-mono">{byCategory[sev].length} finding{byCategory[sev].length > 1 ? 's' : ''}</span>
                      </summary>
                      {byCategory[sev].map(f => <FindingRow key={f.id} f={f}/>)}
                    </details>
                  ))}
                  {findings.length === 0 && (
                    <div className="px-6 py-8 text-center text-gray-600 text-xs font-mono">Aucun finding</div>
                  )}
                </div>
              </div>

              {/* Assets */}
              <div className="grid grid-cols-2 gap-4">
                {/* Subdomains */}
                <div>
                  <p className="text-[10px] uppercase tracking-widest text-gray-500 font-mono mb-2">
                    Sous-domaines ({subdomains.length})
                  </p>
                  <div className="border border-gray-800 rounded-lg overflow-hidden max-h-64 overflow-y-auto">
                    {subdomains.map(a => (
                      <div key={a.id} className="flex items-center gap-2 px-3 py-2 border-b border-gray-800/50 text-xs">
                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${a.active ? 'bg-green-400' : 'bg-gray-600'}`}/>
                        <span className="font-mono text-cyan-300 flex-1 truncate">{a.value}</span>
                        <span className="text-gray-600 shrink-0">{a.ip}</span>
                      </div>
                    ))}
                    {subdomains.length === 0 && (
                      <div className="px-4 py-4 text-center text-gray-600 text-[11px] font-mono">Aucun sous-domaine</div>
                    )}
                  </div>
                </div>

                {/* IP Ranges */}
                <div>
                  <p className="text-[10px] uppercase tracking-widest text-gray-500 font-mono mb-2">
                    Blocs IP / ASN ({ips.length})
                  </p>
                  <div className="border border-gray-800 rounded-lg overflow-hidden max-h-64 overflow-y-auto">
                    {ips.map(a => (
                      <div key={a.id} className="flex items-center gap-2 px-3 py-2 border-b border-gray-800/50 text-xs">
                        <span className="font-mono text-yellow-300 flex-1 truncate">{a.value}</span>
                        <span className="text-gray-600 text-[10px] shrink-0">{a.asn}</span>
                      </div>
                    ))}
                    {ips.length === 0 && (
                      <div className="px-4 py-4 text-center text-gray-600 text-[11px] font-mono">Aucun bloc IP</div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Empty */}
          {!jobId && (
            <div className="flex flex-col items-center justify-center h-full text-gray-700">
              <Radar size={56} className="mb-4 opacity-20"/>
              <p className="font-mono text-sm">Saisissez un domaine et lancez le scan</p>
              <p className="text-xs mt-1">DNS · crt.sh · ASN · Wayback · TLS · HTTP · Fichiers sensibles</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}