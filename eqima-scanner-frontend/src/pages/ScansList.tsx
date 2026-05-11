import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scanApi } from '../api/scans'
import { StatusBadge } from '../components/StatusBadge'
import { ProgressBar } from '../components/ProgressBar'
import { Plus, Loader } from 'lucide-react'

export function ScansList() {
  const navigate = useNavigate()
  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: scanApi.list,
    refetchInterval: 5000,
  })

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
                    {s.totalFindings > 0
                      ? <span className="font-bold text-orange-600">{s.totalFindings}</span>
                      : <span className="text-gray-300">—</span>}
                  </td>
                  <td className="px-6 py-4 text-gray-400 text-xs">
                    {new Date(s.startedAt).toLocaleString('fr-FR')}
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