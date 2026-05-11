import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scanApi } from '../api/scans'
import { StatusBadge } from '../components/StatusBadge'
import { ProgressBar } from '../components/ProgressBar'
import { ScanSession } from '../types'
import { Plus, Loader, RotateCcw, FileText, TrendingUp, TrendingDown, Minus } from 'lucide-react'

function computeDeltas(sessions: ScanSession[]): Map<string, number | null> {
  // Grouper par targetUrl, trié par date décroissante (sessions l'est déjà)
  const byUrl = new Map<string, ScanSession[]>()
  sessions.forEach(s => {
    const key = s.targetUrl
    if (!byUrl.has(key)) byUrl.set(key, [])
    byUrl.get(key)!.push(s)
  })

  const deltas = new Map<string, number | null>()
  sessions.forEach(s => {
    const group = byUrl.get(s.targetUrl) || []
    const idx = group.findIndex(x => x.id === s.id)
    const prev = group[idx + 1] // le suivant dans la liste triée DESC = scan précédent
    if (prev && s.status === 'COMPLETED' && prev.status === 'COMPLETED') {
      deltas.set(s.id, s.totalFindings - prev.totalFindings)
    } else {
      deltas.set(s.id, null)
    }
  })
  return deltas
}

function DeltaBadge({ delta }: { delta: number | null }) {
  if (delta === null) return null
  if (delta === 0) return (
    <span className="flex items-center gap-0.5 text-xs text-gray-400 ml-1">
      <Minus size={11} /> 0
    </span>
  )
  if (delta > 0) return (
    <span className="flex items-center gap-0.5 text-xs text-red-500 font-semibold ml-1">
      <TrendingUp size={11} /> +{delta}
    </span>
  )
  return (
    <span className="flex items-center gap-0.5 text-xs text-green-600 font-semibold ml-1">
      <TrendingDown size={11} /> {delta}
    </span>
  )
}

export function ScansList() {
  const navigate     = useNavigate()
  const queryClient  = useQueryClient()

  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: scanApi.list,
    refetchInterval: 5000,
  })

  const { mutate: relaunch, isPending: relaunching } = useMutation({
    mutationFn: ({ url, name }: { url: string; name: string }) =>
      scanApi.start(url, name),
    onSuccess: (newSession) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      navigate(`/scans/${newSession.id}`)
    },
  })

  const deltas = computeDeltas(sessions)

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Tous les scans</h1>
          <p className="text-gray-500 text-sm mt-1">{sessions.length} scan(s) au total</p>
        </div>
        <button
          onClick={() => navigate('/scans/new')}
          className="flex items-center gap-2 bg-brand-600 text-white px-4 py-2 rounded-lg hover:bg-brand-700 text-sm font-medium"
        >
          <Plus size={16} /> Nouveau scan
        </button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {isLoading ? (
          <div className="flex justify-center py-16"><Loader className="animate-spin text-gray-400" /></div>
        ) : sessions.length === 0 ? (
          <div className="text-center py-16 text-gray-400">
            <p>Aucun scan. <button className="text-brand-600 hover:underline" onClick={() => navigate('/scans/new')}>Lancer le premier →</button></p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-500 text-xs uppercase tracking-wide">
              <tr>
                <th className="px-6 py-3 text-left">Cible</th>
                <th className="px-6 py-3 text-left">URL</th>
                <th className="px-6 py-3 text-left">Statut</th>
                <th className="px-6 py-3 text-left">Progression</th>
                <th className="px-6 py-3 text-left">Findings</th>
                <th className="px-6 py-3 text-left">Lancé le</th>
                <th className="px-6 py-3 text-left">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sessions.map(s => (
                <tr
                  key={s.id}
                  className="hover:bg-gray-50 cursor-pointer"
                  onClick={() => navigate(`/scans/${s.id}`)}
                >
                  <td className="px-6 py-4 font-medium text-gray-900">{s.targetName}</td>
                  <td className="px-6 py-4 text-gray-500 max-w-xs truncate text-xs font-mono">{s.targetUrl}</td>
                  <td className="px-6 py-4"><StatusBadge status={s.status} /></td>
                  <td className="px-6 py-4 w-36">
                    <div className="flex items-center gap-2">
                      <ProgressBar value={s.progress} />
                      <span className="text-xs text-gray-500">{s.progress}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      {s.totalFindings > 0
                        ? <span className="font-bold text-orange-600">{s.totalFindings}</span>
                        : <span className="text-gray-300">—</span>}
                      <DeltaBadge delta={deltas.get(s.id) ?? null} />
                    </div>
                  </td>
                  <td className="px-6 py-4 text-gray-400 text-xs">
                    {new Date(s.startedAt).toLocaleString('fr-FR')}
                  </td>
                  <td className="px-6 py-4" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-2">
                      {/* PDF */}
                      {s.status === 'COMPLETED' && (
                        <a
                          href={scanApi.reportUrl(s.id)}
                          target="_blank"
                          rel="noreferrer"
                          title="Télécharger le rapport PDF"
                          className="p-1.5 rounded-lg text-gray-400 hover:text-brand-600 hover:bg-brand-50 transition-colors"
                        >
                          <FileText size={16} />
                        </a>
                      )}
                      {/* Relancer */}
                      {(s.status === 'COMPLETED' || s.status === 'FAILED') && (
                        <button
                          onClick={() => relaunch({ url: s.targetUrl, name: s.targetName })}
                          disabled={relaunching}
                          title="Relancer le scan"
                          className="p-1.5 rounded-lg text-gray-400 hover:text-brand-600 hover:bg-brand-50 transition-colors disabled:opacity-40"
                        >
                          <RotateCcw size={16} className={relaunching ? 'animate-spin' : ''} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}