import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { targetApi } from '../api/targets'
import { scanApi } from '../api/scans'
import { Target } from '../types'
import { ShieldCheck, Globe, ChevronRight, Loader } from 'lucide-react'

export function NewScan() {
  const navigate  = useNavigate()
  const [step, setStep]               = useState<'target' | 'options'>('target')
  const [selected, setSelected]       = useState<Target | null>(null)
  const [selectedUrls, setSelectedUrls] = useState<string[]>([])
  const [launching, setLaunching]     = useState(false)
  const [error, setError]             = useState<string | null>(null)

  const { data: targets = [], isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: targetApi.list,
  })

  function selectTarget(t: Target) {
    setSelected(t)
    setSelectedUrls(t.urls)
    setStep('options')
  }

  function toggleUrl(url: string) {
    setSelectedUrls(prev =>
      prev.includes(url) ? prev.filter(u => u !== url) : [...prev, url]
    )
  }

  async function launch() {
    if (!selected || selectedUrls.length === 0) return
    setLaunching(true)
    setError(null)
    try {
      const session = await scanApi.start(selected.id, selectedUrls)
      navigate(`/scans/${session.id}`)
    } catch {
      setError('Impossible de lancer le scan. Vérifiez que le backend est accessible.')
      setLaunching(false)
    }
  }

  return (
    <div className="p-8 max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Nouveau scan</h1>
        <p className="text-gray-500 text-sm mt-1">Sélectionnez une cible et lancez le scan</p>
      </div>

      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm mb-8">
        <span className={step === 'target' ? 'font-semibold text-brand-600' : 'text-gray-400'}>
          1. Choisir la cible
        </span>
        <ChevronRight size={14} className="text-gray-300" />
        <span className={step === 'options' ? 'font-semibold text-brand-600' : 'text-gray-400'}>
          2. Options
        </span>
      </div>

      {/* Step 1 — Sélection cible */}
      {step === 'target' && (
        <div>
          {isLoading ? (
            <div className="flex justify-center py-16"><Loader className="animate-spin text-gray-400" /></div>
          ) : (
            <div className="grid gap-4">
              {targets.map(t => (
                <button
                  key={t.id}
                  onClick={() => selectTarget(t)}
                  className="flex items-center gap-4 bg-white border border-gray-200 rounded-xl p-5 hover:border-brand-500 hover:shadow-sm text-left transition-all"
                >
                  <div className="w-12 h-12 bg-brand-50 rounded-xl flex items-center justify-center shrink-0">
                    <ShieldCheck className="text-brand-600" size={22} />
                  </div>
                  <div className="flex-1">
                    <p className="font-semibold text-gray-900">{t.name}</p>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {t.urls.map(url => (
                        <span key={url} className="text-xs text-gray-400 bg-gray-50 px-2 py-0.5 rounded">
                          {url}
                        </span>
                      ))}
                    </div>
                  </div>
                  <ChevronRight size={18} className="text-gray-300" />
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Step 2 — Options */}
      {step === 'options' && selected && (
        <div className="bg-white border border-gray-200 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 bg-brand-50 rounded-xl flex items-center justify-center">
              <ShieldCheck className="text-brand-600" size={20} />
            </div>
            <div>
              <p className="font-semibold text-gray-900">{selected.name}</p>
              <button onClick={() => setStep('target')} className="text-xs text-brand-600 hover:underline">
                Changer de cible
              </button>
            </div>
          </div>

          <div className="mb-6">
            <p className="text-sm font-medium text-gray-700 mb-3 flex items-center gap-2">
              <Globe size={15} /> URLs à scanner
            </p>
            <div className="space-y-2">
              {selected.urls.map(url => (
                <label key={url} className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedUrls.includes(url)}
                    onChange={() => toggleUrl(url)}
                    className="w-4 h-4 text-brand-600 rounded border-gray-300"
                  />
                  <span className="text-sm text-gray-700 font-mono">{url}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="mb-6">
            <p className="text-sm font-medium text-gray-700 mb-2">Modules activés</p>
            <div className="flex flex-wrap gap-2">
              {selected.modules.map(m => (
                <span key={m} className="text-xs bg-brand-50 text-brand-700 px-3 py-1 rounded-full font-medium">
                  {m}
                </span>
              ))}
            </div>
          </div>

          {error && (
            <div className="mb-4 bg-red-50 border border-red-200 text-red-700 text-sm px-4 py-3 rounded-lg">
              {error}
            </div>
          )}

          <button
            onClick={launch}
            disabled={launching || selectedUrls.length === 0}
            className="w-full flex items-center justify-center gap-2 bg-brand-600 text-white py-3 rounded-lg hover:bg-brand-700 disabled:opacity-50 font-medium"
          >
            {launching ? <><Loader size={16} className="animate-spin" /> Lancement…</> : 'Lancer le scan'}
          </button>
        </div>
      )}
    </div>
  )
}