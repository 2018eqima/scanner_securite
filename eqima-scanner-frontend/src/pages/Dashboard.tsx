import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scanApi } from '../api/scans'
import { StatusBadge } from '../components/StatusBadge'
import { ProgressBar } from '../components/ProgressBar'
import { ScanSession } from '../types'
import { Plus, AlertTriangle, CheckCircle, Loader, Clock } from 'lucide-react'

export function Dashboard() {
  const navigate = useNavigate()
  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: scanApi.list,
    refetchInterval: 5000,
  })

  const stats = {
    total:     sessions.length,
    running:   sessions.filter(s => s.status === 'RUNNING').length,
    completed: sessions.filter(s => s.status === 'COMPLETED').length,
    failed:    sessions.filter(s => s.status === 'FAILED').length,
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-500 text-sm mt-1">Vue d'ensemble des scans de sécurité</p>
        </div>
        <button
          onClick={() => navigate('/scans/new')}
          className="flex items-center gap-2 bg-brand-600 text-white px-4 py-2 rounded-lg hover:bg-brand-700 text-sm font-medium"
        >
          <Plus size={16} /> Nouveau scan
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <StatCard label="Total scans"  value={stats.total}     icon={<Clock size={20} className="text-gray-400" />}       color="bg-gray-50" />
        <StatCard label="En cours"     value={stats.running}   icon={<Loader size={20} className="text-blue-500 animate-spin" />} color="bg-blue-50" />
        <StatCard label="Terminés"     value={stats.completed} icon={<CheckCircle size={20} className="text-green-500" />} color="bg-green-50" />
        <StatCard label="Échecs"       value={stats.failed}    icon={<AlertTriangle size={20} className="text-red-500" />} color="bg-red-50" />
      </div>

      {/* Table des scans */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100">
          <h2 className="font-semibold text-gray-800">Scans récents</h2>
        </div>
        {isLoading ? (
          <div className="flex justify-center py-16 text-gray-400">
            <Loader className="animate-spin" />
          </div>
        ) : sessions.length === 0 ? (
          <div className="text-center py-16 text-gray-400">
            <p className="mb-3">Aucun scan lancé</p>
            <button
              onClick={() => navigate('/scans/new')}
              className="text-brand-600 text-sm font-medium hover:underline"
            >
              Lancer le premier scan →
            </button>
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
                <th className="px-6 py-3 text-left">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sessions.map(s => (
                <SessionRow key={s.id} session={s} onClick={() => navigate(`/scans/${s.id}`)} />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function StatCard({ label, value, icon, color }: {
  label: string; value: number; icon: React.ReactNode; color: string
}) {
  return (
    <div className={`${color} rounded-xl p-5 border border-gray-100`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-500 font-medium uppercase tracking-wide">{label}</span>
        {icon}
      </div>
      <p className="text-3xl font-bold text-gray-800">{value}</p>
    </div>
  )
}

function SessionRow({ session: s, onClick }: { session: ScanSession; onClick: () => void }) {
  return (
    <tr className="hover:bg-gray-50 cursor-pointer" onClick={onClick}>
      <td className="px-6 py-4 font-medium text-gray-900">{s.targetName}</td>
      <td className="px-6 py-4 text-gray-500 max-w-xs truncate">{s.targetUrl}</td>
      <td className="px-6 py-4"><StatusBadge status={s.status} /></td>
      <td className="px-6 py-4 w-32">
        <div className="flex items-center gap-2">
          <ProgressBar value={s.progress} />
          <span className="text-xs text-gray-500 shrink-0">{s.progress}%</span>
        </div>
      </td>
      <td className="px-6 py-4">
        {s.totalFindings > 0
          ? <span className="font-semibold text-orange-600">{s.totalFindings}</span>
          : <span className="text-gray-400">—</span>}
      </td>
      <td className="px-6 py-4 text-gray-400 text-xs">
        {new Date(s.startedAt).toLocaleString('fr-FR')}
      </td>
    </tr>
  )
}