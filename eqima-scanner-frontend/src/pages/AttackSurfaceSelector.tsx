import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scanApi, SubdomainResult } from '../api/scans'
import { ScanSession } from '../types'
import {
  Crosshair, Loader, ChevronRight, Search, Globe,
  CheckCircle, XCircle, Play, AlertTriangle, RefreshCw
} from 'lucide-react'

export function AttackSurfaceSelector() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [domain, setDomain] = useState('eqima.org')
  const [inputDomain, setInputDomain] = useState('eqima.org')
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // Scans terminés
  const { data: sessions = [] } = useQuery({
    queryKey: ['scans'],
    queryFn: scanApi.list,
  })
  const completed = sessions.filter((s: ScanSession) => s.status === 'COMPLETED')

  // Découverte de sous-domaines
  const { data: subdomains, isLoading: discovering, error: discoverError, refetch } = useQuery<SubdomainResult[]>({
    queryKey: ['subdomains', domain],
    queryFn: () => scanApi.discoverSubdomains(domain),
    enabled: !!domain,
    staleTime: 5 * 60_000,
  })

  const activeSubdomains = subdomains?.filter(s => s.active) ?? []
  const inactiveSubdomains = subdomains?.filter(s => !s.active) ?? []

  // Lancer les scans sélectionnés
  const { mutate: launchScans, isPending: launching } = useMutation({
    mutationFn: async (urls: string[]) => {
      const results = []
      for (const url of urls) {
        const host = url.replace('https://', '').replace('http://', '')
        const session = await scanApi.start(url, host)
        results.push(session)
      }
      return results
    },
    onSuccess: (sessions) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      if (sessions.length === 1) {
        navigate(`/scans/${sessions[0].id}`)
      } else {
        navigate('/scans')
      }
    },
  })

  const toggleSelect = (url: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(url)) next.delete(url)
      else next.add(url)
      return next
    })
  }

  const selectAll = () => setSelected(new Set(activeSubdomains.map(s => s.httpsUrl)))
  const selectNone = () => setSelected(new Set())

  const handleDiscover = () => {
    setDomain(inputDomain.trim().replace(/https?:\/\//, '').replace(/\/$/, ''))
    setSelected(new Set())
  }

  const handleLaunch = () => {
    if (selected.size === 0) return
    launchScans(Array.from(selected))
  }

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 flex flex-col">
      {/* Header */}
      <div className="bg-gray-950 border-b border-gray-800 px-6 py-5 flex items-center gap-3">
        <Crosshair size={24} className="text-red-400" />
        <div>
          <h1 className="text-xl font-bold text-white">Attack Surface Discovery</h1>
          <p className="text-gray-400 text-xs">Découverte automatique de sous-domaines + surface d'attaque ZAP</p>
        </div>
      </div>

      <div className="flex-1 flex gap-0">
        {/* Panneau gauche : découverte */}
        <div className="w-1/2 border-r border-gray-800 flex flex-col">
          <div className="px-6 py-4 border-b border-gray-800">
            <p className="text-xs text-gray-500 uppercase tracking-widest mb-3 font-mono">Découverte de sous-domaines</p>
            <div className="flex gap-2">
              <input
                value={inputDomain}
                onChange={e => setInputDomain(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleDiscover()}
                placeholder="eqima.org"
                className="flex-1 bg-gray-800 border border-gray-700 text-green-300 font-mono text-sm px-3 py-2 rounded focus:outline-none focus:border-green-500"
              />
              <button
                onClick={handleDiscover}
                disabled={discovering}
                className="flex items-center gap-2 bg-green-700 hover:bg-green-600 disabled:opacity-50 text-white text-sm px-4 py-2 rounded transition-colors"
              >
                {discovering ? <Loader size={14} className="animate-spin" /> : <Search size={14} />}
                Scanner
              </button>
            </div>
          </div>

          {/* Résultats */}
          <div className="flex-1 overflow-auto">
            {discovering && (
              <div className="flex flex-col items-center justify-center py-20 text-gray-500">
                <Loader size={32} className="animate-spin text-green-500 mb-3" />
                <p className="font-mono text-sm">Interrogation de crt.sh…</p>
                <p className="text-xs mt-1">Résolution DNS en cours</p>
              </div>
            )}

            {discoverError && (
              <div className="flex flex-col items-center justify-center py-20 text-gray-500">
                <AlertTriangle size={32} className="text-orange-400 mb-3" />
                <p className="text-sm text-orange-300">Erreur lors de la découverte</p>
                <button onClick={() => refetch()} className="mt-3 text-xs text-green-400 hover:underline flex items-center gap-1">
                  <RefreshCw size={12} /> Réessayer
                </button>
              </div>
            )}

            {!discovering && !discoverError && subdomains && (
              <>
                {/* Actions de sélection */}
                <div className="flex items-center justify-between px-4 py-2 bg-gray-800/40 border-b border-gray-800">
                  <span className="text-xs text-gray-400 font-mono">
                    <span className="text-green-400 font-bold">{activeSubdomains.length}</span> actifs,{' '}
                    <span className="text-gray-500">{inactiveSubdomains.length}</span> inactifs
                  </span>
                  <div className="flex gap-3 text-xs">
                    <button onClick={selectAll} className="text-green-400 hover:underline">Tout sélectionner</button>
                    <button onClick={selectNone} className="text-gray-400 hover:underline">Désélectionner</button>
                  </div>
                </div>

                {/* Actifs */}
                {activeSubdomains.map(sub => (
                  <SubdomainRow
                    key={sub.subdomain}
                    sub={sub}
                    selected={selected.has(sub.httpsUrl)}
                    onToggle={() => toggleSelect(sub.httpsUrl)}
                    completedScan={completed.find(s => s.targetUrl === sub.httpsUrl || s.targetUrl === sub.httpUrl)}
                    onViewSurface={(id) => navigate(`/scans/${id}/attack-surface`)}
                  />
                ))}

                {/* Inactifs (collapsed) */}
                {inactiveSubdomains.length > 0 && (
                  <details className="group">
                    <summary className="px-4 py-2 text-xs text-gray-600 cursor-pointer hover:text-gray-400 font-mono list-none flex items-center gap-2">
                      <ChevronRight size={12} className="group-open:rotate-90 transition-transform" />
                      {inactiveSubdomains.length} sous-domaines inactifs (DNS non résolu)
                    </summary>
                    {inactiveSubdomains.map(sub => (
                      <SubdomainRow key={sub.subdomain} sub={sub} selected={false} onToggle={() => {}} />
                    ))}
                  </details>
                )}
              </>
            )}

            {!discovering && !discoverError && !subdomains && (
              <div className="flex flex-col items-center justify-center py-20 text-gray-600">
                <Globe size={40} className="mb-3 opacity-30" />
                <p className="text-sm font-mono">Entrez un domaine et lancez la découverte</p>
              </div>
            )}
          </div>

          {/* Bouton lancer */}
          {selected.size > 0 && (
            <div className="px-4 py-4 border-t border-gray-800 bg-gray-950">
              <button
                onClick={handleLaunch}
                disabled={launching}
                className="w-full flex items-center justify-center gap-2 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white font-semibold py-3 rounded-lg transition-colors"
              >
                {launching
                  ? <Loader size={16} className="animate-spin" />
                  : <Play size={16} />}
                Lancer {selected.size} scan{selected.size > 1 ? 's' : ''} ZAP
              </button>
            </div>
          )}
        </div>

        {/* Panneau droit : scans terminés */}
        <div className="w-1/2 flex flex-col">
          <div className="px-6 py-4 border-b border-gray-800">
            <p className="text-xs text-gray-500 uppercase tracking-widest font-mono">Surface d'attaque — Scans terminés</p>
          </div>
          <div className="flex-1 overflow-auto">
            {completed.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 text-gray-600">
                <Crosshair size={40} className="mb-3 opacity-30" />
                <p className="text-sm font-mono">Aucun scan terminé</p>
                <button
                  onClick={() => navigate('/scans/new')}
                  className="mt-3 text-xs text-green-400 hover:underline"
                >
                  Lancer un scan →
                </button>
              </div>
            ) : (
              completed.map((s: ScanSession) => (
                <button
                  key={s.id}
                  onClick={() => navigate(`/scans/${s.id}/attack-surface`)}
                  className="w-full flex items-center gap-3 border-b border-gray-800 px-4 py-3 text-left hover:bg-gray-800/40 group transition-colors"
                >
                  <Crosshair size={16} className="text-gray-600 group-hover:text-green-400 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-gray-200">{s.targetName}</p>
                    <p className="text-xs text-gray-500 font-mono truncate">{s.targetUrl}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-[10px] text-gray-500">{new Date(s.startedAt).toLocaleDateString('fr-FR')}</p>
                    {s.totalFindings > 0 && (
                      <p className="text-xs text-orange-400 font-bold">{s.totalFindings} findings</p>
                    )}
                  </div>
                  <ChevronRight size={14} className="text-gray-600 group-hover:text-green-400 shrink-0" />
                </button>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function SubdomainRow({
  sub, selected, onToggle, completedScan, onViewSurface
}: {
  sub: SubdomainResult
  selected: boolean
  onToggle: () => void
  completedScan?: ScanSession
  onViewSurface?: (id: string) => void
}) {
  return (
    <div
      className={`flex items-center gap-3 px-4 py-2.5 border-b border-gray-800/50 cursor-pointer group transition-colors ${
        sub.active ? 'hover:bg-gray-800/40' : 'opacity-40'
      } ${selected ? 'bg-green-900/20 border-l-2 border-l-green-600' : ''}`}
      onClick={sub.active ? onToggle : undefined}
    >
      {/* Checkbox */}
      <div className={`w-4 h-4 rounded border shrink-0 flex items-center justify-center transition-colors ${
        selected ? 'bg-green-600 border-green-600' : 'border-gray-600'
      }`}>
        {selected && <span className="text-white text-[10px] font-bold">✓</span>}
      </div>

      {/* Status icon */}
      {sub.active
        ? <CheckCircle size={14} className="text-green-500 shrink-0" />
        : <XCircle size={14} className="text-gray-600 shrink-0" />}

      {/* Subdomain */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          {sub.countryCode && (
            <img
              src={`https://flagcdn.com/16x12/${sub.countryCode}.png`}
              alt={sub.country}
              title={`${sub.country}${sub.city ? ' — ' + sub.city : ''}${sub.org ? '\n' + sub.org : ''}`}
              className="shrink-0"
              width={16} height={12}
            />
          )}
          <p className="text-sm font-mono text-green-300 truncate">{sub.subdomain}</p>
        </div>
        <p className="text-[10px] text-gray-500 font-mono">
          {sub.ip}
          {sub.city && <span className="text-gray-600"> · {sub.city}</span>}
          {sub.org && <span className="text-gray-600 truncate"> · {sub.org}</span>}
        </p>
      </div>

      {/* Badge scan existant */}
      {completedScan && onViewSurface && (
        <button
          onClick={e => { e.stopPropagation(); onViewSurface(completedScan.id) }}
          className="shrink-0 text-[10px] bg-orange-900/40 text-orange-300 border border-orange-700/40 px-2 py-0.5 rounded hover:bg-orange-900/60 transition-colors font-mono"
        >
          surface →
        </button>
      )}
    </div>
  )
}