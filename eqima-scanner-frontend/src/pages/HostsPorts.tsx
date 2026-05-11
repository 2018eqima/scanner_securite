import { useQuery } from '@tanstack/react-query'
import api from '../api/client'
import { Server, Search, Loader, Shield, AlertTriangle, Info, Clock, Wrench } from 'lucide-react'
import { useState } from 'react'

type PortEntry = {
  port: number
  protocol: string
  service: string
  state: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  reason: string
  remediation: string[]
}

type ScanResult = {
  target: string
  resolvedIp: string
  scanDuration: number
  overallRisk: string
  ports: PortEntry[]
  riskSummary: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
    total: number
  }
  error?: string
}

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-900/60 text-red-300 border-red-700',
  HIGH:     'bg-orange-900/60 text-orange-300 border-orange-700',
  MEDIUM:   'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  LOW:      'bg-blue-900/60 text-blue-300 border-blue-700',
  INFO:     'bg-gray-800 text-gray-400 border-gray-700',
}

const RISK_ICONS: Record<string, JSX.Element> = {
  CRITICAL: <AlertTriangle size={13} className="text-red-400" />,
  HIGH:     <AlertTriangle size={13} className="text-orange-400" />,
  MEDIUM:   <AlertTriangle size={13} className="text-yellow-400" />,
  LOW:      <Info size={13} className="text-blue-400" />,
  INFO:     <Info size={13} className="text-gray-500" />,
}

const RISK_BORDER: Record<string, string> = {
  CRITICAL: 'border-red-800',
  HIGH:     'border-orange-800',
  MEDIUM:   'border-yellow-800',
  LOW:      'border-blue-800',
  INFO:     'border-gray-700',
}

function RiskBadge({ risk }: { risk: string }) {
  const cls = RISK_COLORS[risk] ?? RISK_COLORS.INFO
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border font-mono uppercase ${cls}`}>
      {risk}
    </span>
  )
}

function PortCard({ p }: { p: PortEntry }) {
  const border = RISK_BORDER[p.risk] ?? RISK_BORDER.INFO
  return (
    <div className={`border ${border} rounded-lg overflow-hidden`}>
      {/* Header */}
      <div className={`flex items-center gap-3 px-4 py-3 border-b ${border} bg-gray-800/40`}>
        <span className="font-mono font-bold text-cyan-300 text-lg">{p.port}</span>
        <span className="font-mono text-yellow-400 text-sm">{p.service || '—'}</span>
        <span className="font-mono text-gray-600 text-xs uppercase">{p.protocol}</span>
        <RiskBadge risk={p.risk} />
      </div>

      {/* Body: 2 columns */}
      <div className="grid grid-cols-2 divide-x divide-gray-800">
        {/* Left: Risques */}
        <div className="p-4">
          <p className="text-[10px] uppercase tracking-widest text-gray-500 font-mono mb-2 flex items-center gap-1.5">
            {RISK_ICONS[p.risk]} Risques associés
          </p>
          <p className="text-xs text-gray-300 leading-relaxed">{p.reason}</p>
        </div>

        {/* Right: Plan d'actions */}
        <div className="p-4">
          <p className="text-[10px] uppercase tracking-widest text-gray-500 font-mono mb-2 flex items-center gap-1.5">
            <Wrench size={10}/> Plan d'actions
          </p>
          <ol className="space-y-2">
            {(p.remediation ?? []).map((step, i) => (
              <li key={i} className="flex gap-2 text-xs text-gray-300">
                <span className="shrink-0 w-4 h-4 flex items-center justify-center rounded-full bg-gray-700 text-gray-400 font-mono text-[10px] font-bold mt-0.5">
                  {i + 1}
                </span>
                <span className="leading-relaxed">{step}</span>
              </li>
            ))}
          </ol>
        </div>
      </div>
    </div>
  )
}

function SummaryCard({ label, count, color }: { label: string; count: number; color: string }) {
  if (count === 0) return null
  return (
    <div className={`rounded-lg border px-4 py-3 text-center min-w-[80px] ${color}`}>
      <p className="text-2xl font-bold font-mono">{count}</p>
      <p className="text-[10px] uppercase tracking-widest mt-0.5 opacity-80">{label}</p>
    </div>
  )
}

export function HostsPorts() {
  const [input, setInput] = useState('')
  const [target, setTarget] = useState<string | null>(null)

  const { data, isFetching, error } = useQuery<ScanResult>({
    queryKey: ['ports-scan', target],
    queryFn: () => api.get(`/v1/ports/scan?target=${encodeURIComponent(target!)}`).then(r => r.data),
    enabled: !!target,
    staleTime: 2 * 60_000,
    retry: false,
  })

  const handleScan = () => {
    if (input.trim()) setTarget(input.trim())
  }

  const criticals = data?.ports.filter(p => p.risk === 'CRITICAL') ?? []
  const highs     = data?.ports.filter(p => p.risk === 'HIGH')     ?? []
  const mediums   = data?.ports.filter(p => p.risk === 'MEDIUM')   ?? []
  const lows      = data?.ports.filter(p => p.risk === 'LOW')      ?? []
  const infos     = data?.ports.filter(p => p.risk === 'INFO')     ?? []

  const groups = [
    { label: 'Critique', ports: criticals, risk: 'CRITICAL' },
    { label: 'Élevé',    ports: highs,     risk: 'HIGH' },
    { label: 'Moyen',    ports: mediums,   risk: 'MEDIUM' },
    { label: 'Faible',   ports: lows,      risk: 'LOW' },
    { label: 'Info',     ports: infos,     risk: 'INFO' },
  ].filter(g => g.ports.length > 0)

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Header */}
      <div className="bg-gray-950 border-b border-gray-800 px-6 py-4 flex items-center gap-3">
        <Server size={22} className="text-cyan-400" />
        <div>
          <h1 className="font-bold text-white text-lg leading-tight">Hosts &amp; Ports</h1>
          <p className="text-gray-400 text-xs">Scan des ports ouverts et détection des services non sécurisés</p>
        </div>
      </div>

      {/* Search bar */}
      <div className="px-6 py-5 border-b border-gray-800 bg-gray-950/50">
        <div className="max-w-xl flex gap-2">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
            placeholder="Adresse IP ou nom de domaine…"
            className="flex-1 bg-gray-800 border border-gray-700 text-cyan-300 font-mono text-sm px-4 py-2.5 rounded-lg focus:outline-none focus:border-cyan-600"
          />
          <button
            onClick={handleScan}
            disabled={!input.trim() || isFetching}
            className="flex items-center gap-2 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-white text-sm px-5 py-2.5 rounded-lg transition-colors font-medium"
          >
            {isFetching
              ? <Loader size={15} className="animate-spin" />
              : <Search size={15} />
            }
            Scanner
          </button>
        </div>
        <p className="text-[10px] text-gray-600 font-mono mt-2">
          Ports scannés : FTP, SSH, Telnet, SMTP, HTTP/S, SMB, RDP, MySQL, PostgreSQL, Redis, MongoDB…
        </p>
      </div>

      {/* Content */}
      <div className="px-6 py-6 max-w-6xl">

        {/* Loading */}
        {isFetching && (
          <div className="flex flex-col items-center justify-center py-24 text-gray-500">
            <Loader size={36} className="animate-spin mb-4 text-cyan-700" />
            <p className="font-mono text-sm">Scan en cours — cela peut prendre 15–30 secondes…</p>
            <p className="font-mono text-xs mt-1 text-gray-700">Cible : {target}</p>
          </div>
        )}

        {/* Error */}
        {error && !isFetching && (
          <div className="bg-red-950/40 border border-red-800 rounded-lg px-5 py-4 text-red-300 font-mono text-sm">
            Erreur : {(error as Error).message}
          </div>
        )}

        {/* API-level error */}
        {data?.error && !isFetching && (
          <div className="bg-red-950/40 border border-red-800 rounded-lg px-5 py-4 text-red-300 font-mono text-sm">
            {data.error}
          </div>
        )}

        {/* Results */}
        {data && !data.error && !isFetching && (
          <>
            {/* Meta */}
            <div className="flex items-center gap-4 mb-5 text-xs text-gray-500 font-mono">
              <span>Cible : <span className="text-cyan-400">{data.target}</span></span>
              {data.resolvedIp !== data.target && (
                <span>IP : <span className="text-cyan-400">{data.resolvedIp}</span></span>
              )}
              <span className="flex items-center gap-1">
                <Clock size={11} /> {data.scanDuration.toFixed(1)}s
              </span>
              <span>{data.riskSummary.total} port{data.riskSummary.total !== 1 ? 's' : ''} ouvert{data.riskSummary.total !== 1 ? 's' : ''}</span>
            </div>

            {/* Summary cards */}
            {data.riskSummary.total > 0 ? (
              <>
                <div className="flex gap-3 flex-wrap mb-6">
                  <SummaryCard label="Critical" count={data.riskSummary.critical} color="text-red-300 border-red-800 bg-red-950/30" />
                  <SummaryCard label="High"     count={data.riskSummary.high}     color="text-orange-300 border-orange-800 bg-orange-950/30" />
                  <SummaryCard label="Medium"   count={data.riskSummary.medium}   color="text-yellow-300 border-yellow-800 bg-yellow-950/30" />
                  <SummaryCard label="Low"      count={data.riskSummary.low}      color="text-blue-300 border-blue-800 bg-blue-950/30" />
                  <SummaryCard label="Info"     count={data.riskSummary.info}     color="text-gray-400 border-gray-700 bg-gray-800" />
                </div>

                {/* Groups */}
                {groups.map(group => (
                  <div key={group.risk} className="mb-8">
                    <div className="flex items-center gap-2 mb-3">
                      {RISK_ICONS[group.risk]}
                      <h3 className="text-xs font-bold uppercase tracking-widest text-gray-400 font-mono">
                        {group.label} ({group.ports.length})
                      </h3>
                    </div>
                    <div className="space-y-4">
                      {group.ports.map((p, i) => <PortCard key={i} p={p} />)}
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center py-20 text-gray-600">
                <Shield size={48} className="mb-3 opacity-20" />
                <p className="font-mono text-sm">Aucun port ouvert détecté</p>
                <p className="text-xs mt-1 text-gray-700">La cible est peut-être hors ligne ou filtre les connexions</p>
              </div>
            )}
          </>
        )}

        {/* Empty state */}
        {!target && !isFetching && (
          <div className="flex flex-col items-center justify-center py-24 text-gray-700">
            <Server size={56} className="mb-4 opacity-20" />
            <p className="font-mono text-sm">Saisissez une adresse IP ou un domaine pour lancer le scan</p>
          </div>
        )}
      </div>
    </div>
  )
}