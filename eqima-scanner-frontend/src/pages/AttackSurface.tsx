import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useParams, useNavigate } from 'react-router-dom'
import { scanApi } from '../api/scans'
import {
  Crosshair, Globe, ArrowLeft, ChevronDown, ChevronRight,
  AlertTriangle, CheckCircle, ExternalLink, Search, Filter
} from 'lucide-react'

type Endpoint = {
  url: string
  method: string
  methods?: string[]
  statusCode: number
  contentType?: string
  params?: string[]
  postParams?: string[]
  interesting: boolean
}

type AttackSurfaceData = {
  targetUrl: string
  targetName: string
  sessionStatus: string
  totalEndpoints: number
  interestingEndpoints: number
  formsDetected: number
  httpMethods: string[]
  endpoints: Endpoint[]
}

const METHOD_COLORS: Record<string, string> = {
  GET:    'bg-green-100 text-green-700',
  POST:   'bg-blue-100 text-blue-700',
  PUT:    'bg-yellow-100 text-yellow-700',
  DELETE: 'bg-red-100 text-red-700',
  PATCH:  'bg-purple-100 text-purple-700',
  HEAD:   'bg-gray-100 text-gray-600',
  OPTIONS:'bg-gray-100 text-gray-600',
}

function statusColor(code: number): string {
  if (code >= 500) return 'text-red-600 font-bold'
  if (code >= 400) return 'text-orange-500 font-semibold'
  if (code >= 300) return 'text-blue-500'
  if (code >= 200) return 'text-green-600'
  return 'text-gray-400'
}

function MethodBadge({ method }: { method: string }) {
  const cls = METHOD_COLORS[method] ?? 'bg-gray-100 text-gray-600'
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${cls}`}>
      {method}
    </span>
  )
}

function EndpointRow({ ep }: { ep: Endpoint }) {
  const [open, setOpen] = useState(false)
  const methods = ep.methods?.length ? ep.methods : [ep.method]
  const hasDetails = (ep.params?.length ?? 0) > 0 || (ep.postParams?.length ?? 0) > 0 || ep.contentType

  return (
    <div className={`border-b border-gray-800 ${ep.interesting ? 'bg-red-950/20' : ''}`}>
      <div
        className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-800/50 cursor-pointer group"
        onClick={() => hasDetails && setOpen(o => !o)}
      >
        {/* expand toggle */}
        <span className="w-4 shrink-0 text-gray-600">
          {hasDetails
            ? (open ? <ChevronDown size={14} /> : <ChevronRight size={14} />)
            : <span className="block w-4" />}
        </span>

        {/* interesting flag */}
        {ep.interesting
          ? <AlertTriangle size={14} className="text-red-400 shrink-0" />
          : <span className="w-3.5 shrink-0" />}

        {/* methods */}
        <div className="flex gap-1 shrink-0">
          {methods.map(m => <MethodBadge key={m} method={m} />)}
        </div>

        {/* url */}
        <span className="font-mono text-xs text-green-300 flex-1 truncate">{ep.url}</span>

        {/* status */}
        {ep.statusCode > 0 && (
          <span className={`text-xs font-mono shrink-0 ${statusColor(ep.statusCode)}`}>
            {ep.statusCode}
          </span>
        )}

        {/* external link */}
        <a
          href={ep.url}
          target="_blank"
          rel="noreferrer"
          onClick={e => e.stopPropagation()}
          className="shrink-0 text-gray-600 hover:text-green-400 opacity-0 group-hover:opacity-100 transition-opacity"
        >
          <ExternalLink size={12} />
        </a>
      </div>

      {open && hasDetails && (
        <div className="px-12 pb-3 text-xs text-gray-400 space-y-1.5 font-mono">
          {ep.contentType && (
            <div><span className="text-gray-500">Content-Type:</span> <span className="text-cyan-400">{ep.contentType}</span></div>
          )}
          {ep.params && ep.params.length > 0 && (
            <div>
              <span className="text-gray-500">GET params: </span>
              {ep.params.map(p => (
                <span key={p} className="inline-block bg-gray-700 text-yellow-300 px-1.5 rounded mr-1 mb-1">{p}</span>
              ))}
            </div>
          )}
          {ep.postParams && ep.postParams.length > 0 && (
            <div>
              <span className="text-gray-500">POST params: </span>
              {ep.postParams.map(p => (
                <span key={p} className="inline-block bg-blue-900/60 text-blue-300 px-1.5 rounded mr-1 mb-1">{p}</span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function AttackSurface() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [filterInteresting, setFilterInteresting] = useState(false)
  const [filterMethod, setFilterMethod] = useState('')

  const { data, isLoading, error } = useQuery<AttackSurfaceData>({
    queryKey: ['attack-surface', id],
    queryFn: () => scanApi.attackSurface(id!),
    enabled: !!id,
    staleTime: 60_000,
  })

  const filtered = (data?.endpoints ?? []).filter(ep => {
    if (filterInteresting && !ep.interesting) return false
    if (filterMethod && ep.method !== filterMethod && !ep.methods?.includes(filterMethod)) return false
    if (search) {
      const q = search.toLowerCase()
      return ep.url.toLowerCase().includes(q)
        || ep.params?.some(p => p.toLowerCase().includes(q))
        || ep.postParams?.some(p => p.toLowerCase().includes(q))
    }
    return true
  })

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 flex flex-col">
      {/* Top bar */}
      <div className="bg-gray-950 border-b border-gray-800 px-6 py-4 flex items-center gap-4">
        <button
          onClick={() => navigate(id ? `/scans/${id}` : '/scans')}
          className="text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft size={20} />
        </button>
        <Crosshair className="text-red-400" size={22} />
        <div>
          <h1 className="font-bold text-white text-lg leading-tight">Attack Surface Discovery</h1>
          {data && (
            <p className="text-gray-400 text-xs font-mono">{data.targetUrl}</p>
          )}
        </div>

        {data && (
          <div className="ml-auto flex items-center gap-6 text-sm">
            <Stat label="Endpoints" value={data.totalEndpoints} color="text-green-400" />
            <Stat label="Intéressants" value={data.interestingEndpoints} color="text-red-400" />
            <Stat label="Formulaires" value={data.formsDetected} color="text-yellow-400" />
            <div className="flex gap-1">
              {data.httpMethods.map(m => <MethodBadge key={m} method={m} />)}
            </div>
          </div>
        )}
      </div>

      {/* Filters */}
      {data && (
        <div className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center gap-4">
          <div className="flex items-center gap-2 flex-1">
            <Search size={14} className="text-gray-500" />
            <input
              type="text"
              placeholder="Filtrer par URL ou paramètre…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-gray-800 text-gray-100 text-sm px-3 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-green-500 w-80 font-mono"
            />
          </div>
          <button
            onClick={() => setFilterInteresting(f => !f)}
            className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded border transition-colors ${
              filterInteresting
                ? 'bg-red-900/40 border-red-600 text-red-300'
                : 'border-gray-700 text-gray-400 hover:border-gray-500'
            }`}
          >
            <AlertTriangle size={12} /> Intéressants seulement
          </button>
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-gray-500" />
            <select
              value={filterMethod}
              onChange={e => setFilterMethod(e.target.value)}
              className="bg-gray-800 text-gray-100 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none font-mono"
            >
              <option value="">Toutes méthodes</option>
              {data.httpMethods.map(m => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>
          <span className="text-gray-500 text-xs ml-auto">
            {filtered.length} / {data.totalEndpoints} endpoints
          </span>
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {isLoading && (
          <div className="flex flex-col items-center justify-center py-32 text-gray-400">
            <Crosshair size={48} className="animate-pulse text-red-500 mb-4" />
            <p className="font-mono text-sm">Analyse de la surface d'attaque…</p>
            <p className="text-xs text-gray-600 mt-1">Interrogation de ZAP en cours</p>
          </div>
        )}

        {error && (
          <div className="flex flex-col items-center justify-center py-32 text-gray-400">
            <AlertTriangle size={40} className="text-orange-400 mb-4" />
            <p className="font-mono text-sm text-orange-300">Impossible de charger la surface d'attaque</p>
            <p className="text-xs text-gray-600 mt-1">Le scan est-il terminé ? ZAP est-il disponible ?</p>
          </div>
        )}

        {!isLoading && !error && data && filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center py-32 text-gray-500">
            <Globe size={40} className="mb-4" />
            <p className="font-mono text-sm">Aucun endpoint trouvé</p>
          </div>
        )}

        {!isLoading && !error && data && filtered.length > 0 && (
          <div>
            {/* Header row */}
            <div className="flex items-center gap-3 px-4 py-2 bg-gray-800/60 text-gray-500 text-[10px] uppercase tracking-widest border-b border-gray-800 font-mono">
              <span className="w-4" />
              <span className="w-3.5" />
              <span className="w-16">Méthode</span>
              <span className="flex-1">URL</span>
              <span className="w-12 text-right">Status</span>
              <span className="w-5" />
            </div>
            {filtered.map((ep, i) => (
              <EndpointRow key={i} ep={ep} />
            ))}
          </div>
        )}
      </div>

      {/* Legend */}
      {data && (
        <div className="bg-gray-950 border-t border-gray-800 px-6 py-2 flex items-center gap-6 text-xs text-gray-600 font-mono">
          <span className="flex items-center gap-1.5"><AlertTriangle size={11} className="text-red-400" /> endpoint sensible</span>
          <span className="flex items-center gap-1.5"><CheckCircle size={11} className="text-green-600" /> endpoint standard</span>
          <span>Cliquer sur une ligne pour voir les paramètres</span>
        </div>
      )}
    </div>
  )
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center">
      <p className={`text-xl font-bold font-mono ${color}`}>{value}</p>
      <p className="text-gray-500 text-[10px] uppercase tracking-wide">{label}</p>
    </div>
  )
}