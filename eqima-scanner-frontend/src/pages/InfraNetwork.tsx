import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import {
  Network, Server, Shield, AlertTriangle, CheckCircle,
  Play, Loader, ChevronDown, ChevronRight, Globe, RefreshCw
} from 'lucide-react'

type GvmStatus = {
  available: boolean
  version?: string
  host?: string
  port?: number
  error?: string
}

type InfraTask = {
  id: string
  name: string
  status: string
  progress: number
  lastReport: string
}

type InfraResult = {
  id: string
  name: string
  host: string
  port: string
  severity: string
  threat: string
  description: string
  nvtOid: string
}

const THREAT_COLORS: Record<string, string> = {
  Critical: 'bg-red-900/60 text-red-300 border-red-700',
  High:     'bg-orange-900/60 text-orange-300 border-orange-700',
  Medium:   'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  Low:      'bg-blue-900/60 text-blue-300 border-blue-700',
  Log:      'bg-gray-800 text-gray-400 border-gray-700',
}

function ThreatBadge({ threat }: { threat: string }) {
  const cls = THREAT_COLORS[threat] ?? THREAT_COLORS.Log
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border font-mono uppercase ${cls}`}>
      {threat || 'Log'}
    </span>
  )
}

function ResultRow({ r }: { r: InfraResult }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={`border-b border-gray-800 ${r.threat === 'Critical' || r.threat === 'High' ? 'bg-red-950/10' : ''}`}>
      <div
        className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-800/40 cursor-pointer group"
        onClick={() => r.description && setOpen(o => !o)}
      >
        <span className="w-4 shrink-0 text-gray-600">
          {r.description ? (open ? <ChevronDown size={14}/> : <ChevronRight size={14}/>) : null}
        </span>
        <ThreatBadge threat={r.threat} />
        <span className="font-mono text-xs text-cyan-300 shrink-0 w-32 truncate">{r.host}</span>
        <span className="font-mono text-xs text-yellow-400 shrink-0 w-20">{r.port}</span>
        <span className="text-xs text-gray-300 flex-1 truncate">{r.name}</span>
        {r.severity && (
          <span className="text-xs font-mono text-gray-500 shrink-0">{r.severity}</span>
        )}
      </div>
      {open && r.description && (
        <div className="px-12 pb-3 text-xs text-gray-400 font-mono whitespace-pre-wrap bg-gray-900/40">
          {r.description}
        </div>
      )}
    </div>
  )
}

export function InfraNetwork() {
  const queryClient = useQueryClient()
  const [target, setTarget] = useState('')
  const [name, setName] = useState('')
  const [selectedTask, setSelectedTask] = useState<string | null>(null)

  const { data: status } = useQuery<GvmStatus>({
    queryKey: ['infra-status'],
    queryFn: () => api.get('/v1/infra/status').then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: tasks = [], isLoading: tasksLoading, refetch: refetchTasks } = useQuery<InfraTask[]>({
    queryKey: ['infra-tasks'],
    queryFn: () => api.get('/v1/infra/tasks').then(r => r.data),
    enabled: status?.available === true,
    refetchInterval: (q) => {
      const data = q.state.data as InfraTask[] | undefined
      const hasRunning = data?.some(t => t.status === 'Running' || t.status === 'Requested')
      return hasRunning ? 10_000 : false
    },
  })

  const { data: results = [], isLoading: resultsLoading } = useQuery<InfraResult[]>({
    queryKey: ['infra-results', selectedTask],
    queryFn: () => api.get(`/v1/infra/tasks/${selectedTask}/results`).then(r => r.data),
    enabled: !!selectedTask,
    staleTime: 30_000,
  })

  const { mutate: launchScan, isPending: launching } = useMutation({
    mutationFn: () => api.post('/v1/infra/scan', { target, name: name || target }).then(r => r.data),
    onSuccess: () => {
      setTarget('')
      setName('')
      queryClient.invalidateQueries({ queryKey: ['infra-tasks'] })
    },
  })

  const criticalCount = results.filter(r => r.threat === 'Critical').length
  const highCount = results.filter(r => r.threat === 'High').length

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 flex flex-col">
      {/* Header */}
      <div className="bg-gray-950 border-b border-gray-800 px-6 py-4 flex items-center gap-3">
        <Network size={22} className="text-cyan-400" />
        <div>
          <h1 className="font-bold text-white text-lg leading-tight">Infra réseau, OS &amp; Services</h1>
          <p className="text-gray-400 text-xs">Scan de vulnérabilités infrastructure via OpenVAS/GVM</p>
        </div>

        {/* Status badge */}
        <div className="ml-auto flex items-center gap-2">
          {status?.available
            ? <span className="flex items-center gap-1.5 text-xs text-green-400 font-mono">
                <CheckCircle size={13} /> GVM {status.version} — disponible
              </span>
            : <span className="flex items-center gap-1.5 text-xs text-red-400 font-mono">
                <AlertTriangle size={13} /> GVM indisponible
                {status?.error && <span className="text-gray-600 ml-1">({status.error})</span>}
              </span>
          }
        </div>
      </div>

      <div className="flex-1 flex gap-0 overflow-hidden">
        {/* Panneau gauche : nouveau scan + liste tâches */}
        <div className="w-72 border-r border-gray-800 flex flex-col shrink-0">
          {/* Formulaire nouveau scan */}
          <div className="px-4 py-4 border-b border-gray-800">
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-mono mb-3">Nouveau scan</p>
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="IP, CIDR ou hostname"
              className="w-full bg-gray-800 border border-gray-700 text-cyan-300 font-mono text-sm px-3 py-2 rounded mb-2 focus:outline-none focus:border-cyan-600"
            />
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Nom (optionnel)"
              className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm px-3 py-2 rounded mb-3 focus:outline-none focus:border-cyan-600"
            />
            <button
              onClick={() => launchScan()}
              disabled={!target || launching || !status?.available}
              className="w-full flex items-center justify-center gap-2 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-white text-sm py-2 rounded transition-colors"
            >
              {launching ? <Loader size={14} className="animate-spin" /> : <Play size={14} />}
              Lancer le scan
            </button>
            {!status?.available && (
              <p className="text-[10px] text-red-400 mt-1 text-center">OpenVAS non disponible</p>
            )}
          </div>

          {/* Liste des tâches */}
          <div className="flex-1 overflow-auto">
            <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800">
              <p className="text-[10px] text-gray-500 uppercase tracking-widest font-mono">Tâches</p>
              <button onClick={() => refetchTasks()} className="text-gray-600 hover:text-gray-300">
                <RefreshCw size={12} />
              </button>
            </div>
            {tasksLoading && (
              <div className="flex justify-center py-6"><Loader size={20} className="animate-spin text-gray-600" /></div>
            )}
            {!status?.available && !tasksLoading && (
              <div className="px-4 py-6 text-center text-gray-600 text-xs font-mono">
                OpenVAS non démarré
              </div>
            )}
            {(tasks as InfraTask[]).map(task => (
              <div
                key={task.id}
                onClick={() => setSelectedTask(task.id)}
                className={`px-4 py-3 border-b border-gray-800/50 cursor-pointer hover:bg-gray-800/40 transition-colors ${
                  selectedTask === task.id ? 'bg-gray-800/60 border-l-2 border-l-cyan-600' : ''
                }`}
              >
                <div className="flex items-center justify-between">
                  <p className="text-sm text-gray-200 truncate">{task.name}</p>
                  <TaskStatusBadge status={task.status} />
                </div>
                {task.status === 'Running' && task.progress > 0 && (
                  <div className="mt-1 h-1 bg-gray-700 rounded overflow-hidden">
                    <div className="h-full bg-cyan-600 transition-all" style={{ width: `${task.progress}%` }} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Panneau droit : résultats */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {selectedTask ? (
            <>
              {/* Stats */}
              {results.length > 0 && (
                <div className="flex items-center gap-6 px-6 py-3 bg-gray-950 border-b border-gray-800">
                  <span className="text-xs text-gray-400 font-mono">{results.length} résultats</span>
                  {criticalCount > 0 && (
                    <span className="text-xs font-bold text-red-400">{criticalCount} Critical</span>
                  )}
                  {highCount > 0 && (
                    <span className="text-xs font-bold text-orange-400">{highCount} High</span>
                  )}
                </div>
              )}

              {/* Header colonnes */}
              <div className="flex items-center gap-3 px-4 py-2 bg-gray-800/60 border-b border-gray-800 text-[10px] uppercase tracking-widest text-gray-500 font-mono shrink-0">
                <span className="w-4" />
                <span className="w-16">Menace</span>
                <span className="w-32">Host</span>
                <span className="w-20">Port</span>
                <span className="flex-1">Vulnérabilité</span>
                <span className="w-12">Score</span>
              </div>

              <div className="flex-1 overflow-auto">
                {resultsLoading && (
                  <div className="flex justify-center py-12"><Loader size={24} className="animate-spin text-gray-600" /></div>
                )}
                {!resultsLoading && results.length === 0 && (
                  <div className="flex flex-col items-center justify-center py-20 text-gray-600">
                    <Shield size={40} className="mb-3 opacity-30" />
                    <p className="text-sm font-mono">Aucun résultat — scan en cours ou aucune vulnérabilité</p>
                  </div>
                )}
                {(results as InfraResult[]).map((r, i) => <ResultRow key={r.id || i} r={r} />)}
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center flex-1 text-gray-600">
              <Server size={48} className="mb-4 opacity-20" />
              <p className="font-mono text-sm">Sélectionnez une tâche pour voir les résultats</p>
              <p className="text-xs mt-1 text-gray-700">ou lancez un nouveau scan à gauche</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function TaskStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    Done:      'text-green-400',
    Running:   'text-cyan-400',
    Requested: 'text-yellow-400',
    Stopped:   'text-gray-400',
    'New':     'text-blue-400',
  }
  const cls = map[status] ?? 'text-gray-500'
  return <span className={`text-[10px] font-mono ${cls}`}>{status}</span>
}