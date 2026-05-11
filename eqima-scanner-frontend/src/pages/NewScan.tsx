import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { scanApi } from '../api/scans'
import { ShieldCheck, Globe, Loader, AlertCircle } from 'lucide-react'

export function NewScan() {
  const navigate   = useNavigate()
  const [url, setUrl]         = useState('')
  const [name, setName]       = useState('')
  const [launching, setLaunching] = useState(false)
  const [error, setError]     = useState<string | null>(null)

  async function launch(e: React.FormEvent) {
    e.preventDefault()
    if (!url.trim()) return
    setLaunching(true)
    setError(null)
    try {
      const session = await scanApi.start(url.trim(), name.trim() || undefined)
      navigate(`/scans/${session.id}`)
    } catch {
      setError('Impossible de lancer le scan. Vérifiez que le backend est accessible.')
      setLaunching(false)
    }
  }

  return (
    <div className="p-8 max-w-2xl mx-auto">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Nouveau scan</h1>
        <p className="text-gray-500 text-sm mt-1">Saisissez l'URL à analyser avec OWASP ZAP</p>
      </div>

      <form onSubmit={launch} className="bg-white border border-gray-200 rounded-xl p-6 space-y-5">
        {/* Icône */}
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 bg-brand-50 rounded-xl flex items-center justify-center">
            <ShieldCheck className="text-brand-600" size={20} />
          </div>
          <p className="font-semibold text-gray-900">Configuration du scan</p>
        </div>

        {/* URL */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1.5 flex items-center gap-1.5">
            <Globe size={14} /> URL cible <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://example.com"
            required
            className="w-full px-3 py-2.5 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
          />
          <p className="text-xs text-gray-400 mt-1">
            Entrez l'URL complète — le protocole https:// sera ajouté automatiquement si absent.
          </p>
        </div>

        {/* Nom optionnel */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1.5">
            Nom du scan <span className="text-gray-400 font-normal">(optionnel)</span>
          </label>
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="Ex : Audit production Octobre"
            className="w-full px-3 py-2.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
          />
        </div>

        {/* Info ZAP */}
        <div className="bg-blue-50 border border-blue-100 rounded-lg px-4 py-3 text-xs text-blue-700">
          Le scan exécute un <strong>spider</strong> puis un <strong>scan actif</strong> via OWASP ZAP.
          La durée varie selon la taille de l'application (quelques minutes à plusieurs heures).
        </div>

        {/* Erreur */}
        {error && (
          <div className="flex items-center gap-2 bg-red-50 border border-red-200 text-red-700 text-sm px-4 py-3 rounded-lg">
            <AlertCircle size={16} className="shrink-0" />
            {error}
          </div>
        )}

        {/* Bouton */}
        <button
          type="submit"
          disabled={launching || !url.trim()}
          className="w-full flex items-center justify-center gap-2 bg-brand-600 text-white py-3 rounded-lg hover:bg-brand-700 disabled:opacity-50 font-medium transition-colors"
        >
          {launching
            ? <><Loader size={16} className="animate-spin" /> Lancement en cours…</>
            : 'Lancer le scan'}
        </button>
      </form>
    </div>
  )
}