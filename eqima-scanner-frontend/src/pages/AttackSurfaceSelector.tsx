import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scanApi, SubdomainResult } from '../api/scans'
import { ScanSession } from '../types'
import {
  Crosshair, Loader, ChevronRight, Search, Globe,
  CheckCircle, XCircle, Play, AlertTriangle, RefreshCw,
  BookOpen, Eye, Radar, BarChart3, Settings, ChevronDown, Zap
} from 'lucide-react'
import { AttackSurfaceV2 } from './AttackSurfaceV2'

export function AttackSurfaceSelector() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<'discovery' | 'v2' | 'roadmap'>('v2')
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

      {/* Tabs */}
      <div className="bg-gray-950 border-b border-gray-800 px-6 flex gap-1">
        <button
          onClick={() => setTab('discovery')}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
            tab === 'discovery'
              ? 'border-red-500 text-red-400'
              : 'border-transparent text-gray-500 hover:text-gray-300'
          }`}
        >
          <Radar size={14} /> Découverte active
        </button>
        <button
          onClick={() => setTab('v2')}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
            tab === 'v2'
              ? 'border-red-500 text-red-400'
              : 'border-transparent text-gray-500 hover:text-gray-300'
          }`}
        >
          <Zap size={14} /> Scan complet v2
        </button>
        <button
          onClick={() => setTab('roadmap')}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
            tab === 'roadmap'
              ? 'border-red-500 text-red-400'
              : 'border-transparent text-gray-500 hover:text-gray-300'
          }`}
        >
          <BookOpen size={14} /> Spécifications &amp; Roadmap
        </button>
      </div>

      {tab === 'v2' && <AttackSurfaceV2 />}
      {tab === 'roadmap' && <RoadmapView />}

      {tab === 'discovery' && <div className="flex-1 flex gap-0">
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
      </div>}
    </div>
  )
}

// ── Roadmap / Spécifications ──────────────────────────────────────────────────

type PhaseSection = { title: string; items: string[] }
type Phase = { id: string; icon: React.ReactNode; label: string; color: string; sections: PhaseSection[] }

const PHASES: Phase[] = [
  {
    id: 'phase1', icon: <Eye size={16}/>, label: 'Phase 1 — Reconnaissance passive', color: 'border-blue-700 bg-blue-950/20',
    sections: [
      { title: '1.1 DNS & Infrastructure', items: [
        'Résolution DNS complète : A, AAAA, MX, NS, TXT, SOA, CNAME, PTR',
        'Énumération de sous-domaines : brute-force via wordlist (SecLists DNS)',
        'Certificate Transparency via crt.sh API (https://crt.sh/?q=%.{domain}&output=json)',
        'Lookup DNSDumpster, SecurityTrails si clé API disponible',
        'Détection de zone transfer (AXFR)',
        'Analyse SPF/DKIM/DMARC (vecteurs de phishing/spoofing)',
        'Reverse DNS sur toutes les IPs découvertes',
      ]},
      { title: '1.2 ASN & Ranges IP', items: [
        'Lookup ASN via api.bgpview.io',
        'Extraction des plages IP annoncées par l\'ASN cible',
        'Identification des blocs CIDR appartenant à l\'organisation',
      ]},
      { title: '1.3 Certificate Transparency', items: [
        'Extraction de tous les SANs des certificats TLS (crt.sh)',
        'Détection de sous-domaines cachés dans les SANs',
        'Analyse des certificats expirés ou mal configurés',
      ]},
      { title: '1.4 OSINT', items: [
        'Recherche Google Dorks automatisée (site:, filetype:, inurl:)',
        'Shodan API : ports, services, CVEs connues sur les IPs',
        'Censys API : TLS, services exposés',
        'Wayback Machine : URLs historiques (web.archive.org/cdx/search/cdx)',
        'GitHub search : dépôts liés au domaine, secrets exposés',
      ]},
    ],
  },
  {
    id: 'phase2', icon: <Radar size={16}/>, label: 'Phase 2 — Reconnaissance active', color: 'border-orange-700 bg-orange-950/20',
    sections: [
      { title: '2.1 Scan de ports & services', items: [
        'Intégration OpenVAS : Discovery Scan sur toutes les IPs (Phase 1)',
        'Via GVM API (GMP over TLS) : create_target → create_task → start_task → poll → get_reports',
        'Ports standards + non standards (top 10 000)',
        'Identification des services et versions (bannières)',
        'Détection OS fingerprint',
      ]},
      { title: '2.2 Analyse TLS/SSL', items: [
        'Version TLS supportée (TLS 1.0/1.1 = vulnérable)',
        'Cipher suites faibles',
        'Validité, chaîne de confiance, CN vs SANs',
        'HSTS présent/absent, includeSubDomains, preload',
      ]},
      { title: '2.3 HTTP Fingerprinting', items: [
        'Headers de sécurité : CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS',
        'Cookies : Secure, HttpOnly, SameSite',
        'Détection de technologies : X-Powered-By, Server, générateurs de meta',
        'Wappalyzer-like fingerprinting sur les réponses HTTP',
      ]},
      { title: '2.4 Découverte d\'endpoints (crawl actif)', items: [
        'Intégration OWASP ZAP : Spider classique + Ajax Spider pour SPA (React, Vue, Angular)',
        'Via ZAP REST API : récupérer l\'arbre complet des URLs, méthodes, paramètres, codes de réponse',
        'Fichiers sensibles : /.env, /.git/HEAD, /config.js, /backup.zip, /api/swagger.json, /openapi.yaml, /actuator, /actuator/env, /phpinfo.php, /adminer.php, /.DS_Store',
        'Détection de directory listing',
        'Endpoints API : /api/, /graphql, /v1/, /v2/, /rest/, /swagger-ui/, /redoc/',
      ]},
    ],
  },
  {
    id: 'phase3', icon: <BarChart3 size={16}/>, label: 'Phase 3 — Analyse & Scoring', color: 'border-yellow-700 bg-yellow-950/20',
    sections: [
      { title: '3.1 Scoring par asset', items: [
        'Ports dangereux exposés (22 public, 3389, 5432, 27017…) → score élevé',
        'Fichiers sensibles accessibles → score critique',
        'Headers de sécurité manquants → score moyen',
        'TLS faible ou expiré → score élevé',
        'Technologie avec CVE connue (via NVD API) → score variable selon CVSS',
      ]},
      { title: '3.2 Déduplication & corrélation', items: [
        'Dédupliquer les URLs et endpoints inter-sources',
        'Corréler : IP → sous-domaines → services → endpoints → technologies → CVEs',
        'Construire un graphe d\'actifs (Asset Graph)',
      ]},
      { title: '3.3 Détection de surface d\'attaque prioritaire', items: [
        'Formulaires sans CSRF token',
        'Endpoints POST/PUT/DELETE sans authentification apparente',
        'APIs exposant des données sans rate-limiting détectable',
        'Endpoints anciens (Wayback) toujours actifs',
      ]},
    ],
  },
  {
    id: 'phase4', icon: <Settings size={16}/>, label: 'Phase 4 — Orchestration & Architecture', color: 'border-green-700 bg-green-950/20',
    sections: [
      { title: 'Backend Spring Boot', items: [
        'AttackSurfaceOrchestrator : service principal gérant le workflow par phases',
        'Exécution parallèle Phase 1 via CompletableFuture',
        'Phase 2 déclenchée après agrégation Phase 1',
        'Polling asynchrone OpenVAS + ZAP (toutes les 30s)',
        'Entités PostgreSQL : ScanJob, DiscoveredHost, DiscoveredEndpoint, SecurityHeader, TlsAnalysis, TechnologyFingerprint, SensitiveFile, RiskScore',
        'REST : POST /api/scans, GET /api/scans/{id}, GET /api/scans/{id}/results, GET /api/scans/{id}/export',
        'SSE : GET /api/scans/{id}/stream pour suivi temps réel',
      ]},
      { title: 'Intégration OpenVAS (GVM API)', items: [
        'Connexion via socket TLS ou XML over TCP (port 9390)',
        'Authentification GMP (<authenticate>)',
        'Workflow : create_target → create_task → start_task → get_tasks (polling) → get_reports',
        'Parser rapport XML GMP : hosts, ports, services, vulnérabilités',
      ]},
      { title: 'Intégration OWASP ZAP', items: [
        'ZAP en mode daemon : zap.sh -daemon -port 8090 -config api.key=xxx',
        'Spider : spider/scan → spider/status → spider/results',
        'Ajax Spider : ajaxSpider/scan → ajaxSpider/status → ajaxSpider/results',
        'Récupérer : core/urls, core/messages (paramètres et méthodes)',
        'Scan passif automatique + récupération des alertes',
      ]},
      { title: 'Frontend React', items: [
        'Vue "Scan en cours" : timeline des phases avec progression SSE temps réel',
        'Asset Map : graphe interactif des assets (D3.js ou Cytoscape)',
        'Tableau hosts avec ports/services',
        'Tableau endpoints avec méthode, statut, score de risque, paramètres',
        'Tableau findings : fichiers sensibles, headers manquants, TLS faibles',
        'Scoring global avec breakdown par catégorie',
        'Filtres : par sévérité, type d\'asset, phase de découverte',
        'Export : JSON complet, rapport PDF exécutif',
      ]},
      { title: 'Contraintes techniques', items: [
        'Toutes les clés API (Shodan, Censys, SecurityTrails) configurables via .env',
        'Timeouts configurables par phase',
        'Mode "passif uniquement" (sans contact cible) activable en option',
        'Rate limiting sur les requêtes sortantes pour éviter le blocage IP',
        'Logging structuré de toutes les requêtes sortantes (audit trail)',
        'Keycloak : accès restreint au rôle SECURITY_ANALYST',
        'OpenVAS image : registry.community.greenbone.net/community/gvmd:stable',
        'ZAP image : ghcr.io/zaproxy/zaproxy:stable',
      ]},
    ],
  },
]

function PhaseCard({ phase }: { phase: Phase }) {
  const [open, setOpen] = useState(true)
  return (
    <div className={`border rounded-xl overflow-hidden ${phase.color}`}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-white/5 transition-colors"
      >
        <span className="text-gray-300">{phase.icon}</span>
        <span className="font-bold text-sm text-white tracking-wide flex-1">{phase.label}</span>
        <ChevronDown size={14} className={`text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="px-5 pb-5 grid grid-cols-1 md:grid-cols-2 gap-4">
          {phase.sections.map((sec, i) => (
            <div key={i} className="bg-gray-900/50 rounded-lg p-4">
              <p className="text-[10px] uppercase tracking-widest font-mono text-gray-500 mb-2">{sec.title}</p>
              <ul className="space-y-1.5">
                {sec.items.map((item, j) => (
                  <li key={j} className="flex gap-2 text-xs text-gray-300">
                    <span className="shrink-0 text-gray-600 mt-0.5">›</span>
                    <span className="leading-relaxed font-mono">{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function RoadmapView() {
  return (
    <div className="flex-1 overflow-auto px-6 py-6 max-w-7xl">
      {/* Intro */}
      <div className="mb-6 bg-gray-800/40 border border-gray-700 rounded-xl px-6 py-5">
        <div className="flex items-start gap-3">
          <BookOpen size={20} className="text-red-400 mt-0.5 shrink-0" />
          <div>
            <h2 className="text-white font-bold text-base mb-1">Attack Surface Discovery — Module v2</h2>
            <p className="text-gray-400 text-sm leading-relaxed">
              Moteur de découverte de surface d'attaque complet en 4 phases séquentielles et parallélisables.
              Les résultats alimentent automatiquement <span className="text-cyan-400 font-mono">OpenVAS</span> (scan de vulnérabilités infrastructure)
              et <span className="text-green-400 font-mono">OWASP ZAP</span> (crawl et analyse web).
            </p>
            <div className="flex gap-3 mt-3 flex-wrap">
              {[
                { label: 'Spring Boot 3.x', color: 'text-green-400 border-green-800 bg-green-950/30' },
                { label: 'React / Vite', color: 'text-cyan-400 border-cyan-800 bg-cyan-950/30' },
                { label: 'PostgreSQL 16', color: 'text-blue-400 border-blue-800 bg-blue-950/30' },
                { label: 'Docker Compose', color: 'text-yellow-400 border-yellow-800 bg-yellow-950/30' },
                { label: 'OpenVAS GVM', color: 'text-orange-400 border-orange-800 bg-orange-950/30' },
                { label: 'OWASP ZAP', color: 'text-red-400 border-red-800 bg-red-950/30' },
              ].map(t => (
                <span key={t.label} className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${t.color}`}>
                  {t.label}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Phases */}
      <div className="space-y-4">
        {PHASES.map(phase => <PhaseCard key={phase.id} phase={phase} />)}
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