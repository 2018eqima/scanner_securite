import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scanApi } from '../api/scans'
import { ScanSession } from '../types'
import { Crosshair, Loader, ChevronRight } from 'lucide-react'

export function AttackSurfaceSelector() {
  const navigate = useNavigate()
  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: scanApi.list,
  })

  const completed = sessions.filter((s: ScanSession) => s.status === 'COMPLETED')

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-8">
      <div className="max-w-2xl mx-auto">
        <div className="flex items-center gap-3 mb-8">
          <Crosshair size={28} className="text-red-400" />
          <div>
            <h1 className="text-2xl font-bold">Attack Surface Discovery</h1>
            <p className="text-gray-400 text-sm">Sélectionnez un scan terminé pour explorer sa surface d'attaque</p>
          </div>
        </div>

        {isLoading && (
          <div className="flex justify-center py-16">
            <Loader className="animate-spin text-gray-500" />
          </div>
        )}

        {!isLoading && completed.length === 0 && (
          <div className="text-center py-16 text-gray-500">
            <Crosshair size={48} className="mx-auto mb-4 opacity-30" />
            <p>Aucun scan terminé disponible.</p>
            <button
              onClick={() => navigate('/scans/new')}
              className="mt-4 text-sm text-green-400 hover:underline"
            >
              Lancer un scan →
            </button>
          </div>
        )}

        <div className="space-y-2">
          {completed.map((s: ScanSession) => (
            <button
              key={s.id}
              onClick={() => navigate(`/scans/${s.id}/attack-surface`)}
              className="w-full flex items-center gap-4 bg-gray-800 hover:bg-gray-750 border border-gray-700 hover:border-green-600 rounded-lg px-5 py-4 text-left transition-colors group"
            >
              <Crosshair size={18} className="text-gray-500 group-hover:text-green-400 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="font-semibold text-gray-100">{s.targetName}</p>
                <p className="text-xs text-gray-500 font-mono truncate">{s.targetUrl}</p>
              </div>
              <div className="text-right shrink-0">
                <p className="text-xs text-gray-400">{new Date(s.startedAt).toLocaleString('fr-FR')}</p>
                {s.totalFindings > 0 && (
                  <p className="text-xs text-orange-400 font-semibold">{s.totalFindings} findings</p>
                )}
              </div>
              <ChevronRight size={16} className="text-gray-600 group-hover:text-green-400 shrink-0" />
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}