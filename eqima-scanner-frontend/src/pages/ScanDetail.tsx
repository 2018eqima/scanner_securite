import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { scanApi } from '../api/scans'
import { useScanEvents } from '../hooks/useScanEvents'
import { StatusBadge } from '../components/StatusBadge'
import { SeverityBadge } from '../components/SeverityBadge'
import { ProgressBar } from '../components/ProgressBar'
import { SslCard } from '../components/SslCard'
import { TechStackCard } from '../components/TechStackCard'
import { Finding, Severity } from '../types'
import {
  ArrowLeft, Download, Radio, Terminal, AlertTriangle,
  Info, ChevronDown, ChevronUp
} from 'lucide-react'

const SEVERITIES: Severity[] = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

export function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const { data: session, isLoading } = useQuery({
    queryKey: ['scans', id],
    queryFn: () => scanApi.get(id!),
    refetchInterval: (q) => {
      const status = q.state.data?.status
      return status === 'RUNNING' || status === 'PENDING' ? 3000 : false
    },
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['scans', id, 'findings'],
    queryFn: () => scanApi.findings(id!),
    enabled: session?.status === 'COMPLETED',
  })

  const { events, done: sseDone } = useScanEvents(
    session?.status === 'RUNNING' || session?.status === 'PENDING' ? id! : null
  )

  if (isLoading || !session) {
    return <div className="flex justify-center items-center h-full text-gray-400">Chargement…</div>
  }

  const filtered = severityFilter === 'ALL'
    ? findings
    : findings.filter(f => f.severity === severityFilter)

  const counts = SEVERITIES.reduce((acc, s) => ({
    ...acc,
    [s]: findings.filter(f => f.severity === s).length,
  }), {} as Record<Severity, number>)

  return (
    <div className="p-8 max-w-5xl mx-auto">
      {/* Header */}
      <button onClick={() => navigate(-1)} className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 mb-6">
        <ArrowLeft size={15} /> Retour
      </button>

      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{session.targetName}</h1>
          <p className="text-gray-500 text-sm mt-1">{session.targetUrl}</p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={session.status} />
          {session.status === 'COMPLETED' && (
            <a
              href={scanApi.reportUrl(session.id)}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 bg-brand-600 text-white px-4 py-2 rounded-lg hover:bg-brand-700 text-sm font-medium"
            >
              <Download size={15} /> Rapport PDF
            </a>
          )}
        </div>
      </div>

      {/* Info + progression */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <p className="text-xs text-gray-400 mb-1">Début</p>
          <p className="text-sm font-medium">{new Date(session.startedAt).toLocaleString('fr-FR')}</p>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <p className="text-xs text-gray-400 mb-1">Fin</p>
          <p className="text-sm font-medium">
            {session.completedAt ? new Date(session.completedAt).toLocaleString('fr-FR') : '—'}
          </p>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <p className="text-xs text-gray-400 mb-1">Progression</p>
          <div className="flex items-center gap-2 mt-1">
            <ProgressBar value={session.progress} />
            <span className="text-sm font-medium shrink-0">{session.progress}%</span>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <p className="text-xs text-gray-400 mb-1">Findings</p>
          <p className="text-2xl font-bold text-orange-600">{session.totalFindings}</p>
        </div>
      </div>

      {/* Live events (scan en cours) */}
      {(session.status === 'RUNNING' || session.status === 'PENDING') && (
        <div className="bg-gray-900 rounded-xl p-4 mb-6">
          <p className="flex items-center gap-2 text-sm font-medium mb-3">
            {sseDone
              ? <><Radio size={14} className="text-yellow-400 animate-pulse" /> <span className="text-yellow-400">Reconnexion SSE…</span></>
              : <><Radio size={14} className="text-green-400 animate-pulse" /> <span className="text-green-400">Événements live</span></>
            }
          </p>
          <div className="space-y-1 max-h-48 overflow-y-auto font-mono text-xs">
            {events.length === 0
              ? <p className="text-gray-500">En attente du premier événement…</p>
              : events.map((e, i) => (
                  <p key={i} className={e.type === 'ERROR' ? 'text-red-400' : 'text-gray-300'}>
                    <span className="text-gray-500">[{e.type}]</span>{' '}
                    {e.message}
                    {e.progress != null ? ` — ${e.progress}%` : ''}
                  </p>
                ))
            }
          </div>
        </div>
      )}

      {/* Stack technique */}
      {session.status === 'COMPLETED' && (
        <TechStackCard techData={session.techData} />
      )}

      {/* SSL */}
      {session.status === 'COMPLETED' && (
        <SslCard sslGrade={session.sslGrade} sslData={session.sslData} />
      )}

      {/* Findings */}
      {session.status === 'COMPLETED' && (
        <div>
          {/* Résumé sévérité */}
          <div className="flex gap-3 mb-4">
            <FilterBtn label="Tous" count={findings.length} active={severityFilter === 'ALL'} onClick={() => setSeverityFilter('ALL')} />
            {SEVERITIES.map(s => (
              <FilterBtn key={s} label={s} count={counts[s]} active={severityFilter === s} onClick={() => setSeverityFilter(s)} />
            ))}
          </div>

          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-2">
              <Terminal size={16} className="text-gray-400" />
              <h2 className="font-semibold text-gray-800">
                Findings {severityFilter !== 'ALL' ? `— ${severityFilter}` : ''} ({filtered.length})
              </h2>
            </div>
            {filtered.length === 0 ? (
              <div className="text-center py-12 text-gray-400 flex flex-col items-center gap-2">
                <Info size={32} />
                <p>Aucun finding {severityFilter !== 'ALL' ? `de sévérité ${severityFilter}` : ''}</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-100">
                {filtered.map(f => (
                  <FindingRow
                    key={f.id}
                    finding={f}
                    expanded={expandedId === f.id}
                    onToggle={() => setExpandedId(expandedId === f.id ? null : f.id)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function FilterBtn({ label, count, active, onClick }: {
  label: string; count: number; active: boolean; onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
        active
          ? 'bg-brand-600 text-white border-brand-600'
          : 'bg-white text-gray-600 border-gray-200 hover:border-brand-400'
      }`}
    >
      {label}
      <span className={`text-xs px-1.5 py-0.5 rounded-full ${active ? 'bg-brand-500 text-white' : 'bg-gray-100 text-gray-500'}`}>
        {count}
      </span>
    </button>
  )
}

function FindingRow({ finding: f, expanded, onToggle }: {
  finding: Finding; expanded: boolean; onToggle: () => void
}) {
  return (
    <div>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-4 px-6 py-4 text-left hover:bg-gray-50"
      >
        <SeverityBadge severity={f.severity} />
        <div className="flex-1 min-w-0">
          <p className="font-medium text-gray-900 truncate">{f.name}</p>
          <p className="text-xs text-gray-400 truncate">{f.url}</p>
        </div>
        {f.cweid && (
          <span className="text-xs text-gray-400 shrink-0">CWE-{f.cweid}</span>
        )}
        {expanded ? <ChevronUp size={16} className="text-gray-400 shrink-0" /> : <ChevronDown size={16} className="text-gray-400 shrink-0" />}
      </button>

      {expanded && (
        <div className="px-6 pb-5 space-y-3 bg-gray-50 border-t border-gray-100">
          {f.description && (
            <Section title="Description" icon={<Info size={13} />}>
              <p>{f.description}</p>
            </Section>
          )}
          {f.solution && (
            <Section title="Solution" icon={<AlertTriangle size={13} />}>
              <p>{f.solution}</p>
            </Section>
          )}
          {f.evidence && (
            <Section title="Preuve">
              <pre className="bg-gray-900 text-green-400 text-xs p-3 rounded-lg overflow-auto">{f.evidence}</pre>
            </Section>
          )}
        </div>
      )}
    </div>
  )
}

function Section({ title, icon, children }: {
  title: string; icon?: React.ReactNode; children: React.ReactNode
}) {
  return (
    <div className="pt-3">
      <p className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
        {icon}{title}
      </p>
      <div className="text-sm text-gray-700 leading-relaxed">{children}</div>
    </div>
  )
}