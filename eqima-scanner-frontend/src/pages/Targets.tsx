import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { targetApi } from '../api/targets'
import { ShieldCheck, Globe, Zap, Play, Loader } from 'lucide-react'

export function Targets() {
  const navigate = useNavigate()
  const { data: targets = [], isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: targetApi.list,
  })

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-full">
        <Loader className="animate-spin text-gray-400" />
      </div>
    )
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Cibles</h1>
        <p className="text-gray-500 text-sm mt-1">Applications configurées pour le scan</p>
      </div>

      <div className="grid grid-cols-2 gap-5">
        {targets.map(t => (
          <div
            key={t.id}
            className="bg-white border border-gray-200 rounded-xl p-6 hover:shadow-md transition-shadow"
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-brand-50 rounded-xl flex items-center justify-center">
                  <ShieldCheck className="text-brand-600" size={24} />
                </div>
                <div>
                  <h2 className="font-semibold text-gray-900">{t.name}</h2>
                  <p className="text-xs text-gray-400">{t.id}</p>
                </div>
              </div>
              <button
                onClick={() => navigate('/scans/new')}
                className="flex items-center gap-1.5 text-xs bg-brand-600 text-white px-3 py-1.5 rounded-lg hover:bg-brand-700 font-medium"
              >
                <Play size={12} /> Scanner
              </button>
            </div>

            <div className="mb-4">
              <p className="text-xs font-medium text-gray-500 flex items-center gap-1 mb-2">
                <Globe size={12} /> URLs ({t.urls.length})
              </p>
              <div className="space-y-1">
                {t.urls.map(url => (
                  <p key={url} className="text-xs font-mono text-gray-600 bg-gray-50 px-3 py-1.5 rounded-lg truncate">
                    {url}
                  </p>
                ))}
              </div>
            </div>

            <div>
              <p className="text-xs font-medium text-gray-500 flex items-center gap-1 mb-2">
                <Zap size={12} /> Modules
              </p>
              <div className="flex flex-wrap gap-1.5">
                {t.modules.map(m => (
                  <span
                    key={m}
                    className="text-xs bg-indigo-50 text-indigo-700 px-2.5 py-0.5 rounded-full font-medium"
                  >
                    {m}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}