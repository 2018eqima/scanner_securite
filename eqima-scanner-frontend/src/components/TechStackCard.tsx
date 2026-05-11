import { AlertTriangle, CheckCircle, Server, Code2, Globe, Layers, Package, Shield, ShieldAlert } from 'lucide-react'

interface TechComp {
  name: string
  version?: string
  category: string
}

interface OutdatedComp {
  component: string
  detectedVersion: string
  minimumSafeVersion: string
  status: string
}

interface TechData {
  host: string
  headers: Record<string, string>
  server: TechComp[]
  os: TechComp[]
  languages: TechComp[]
  frameworks: TechComp[]
  cms: TechComp[]
  libraries: TechComp[]
  cdn: TechComp[]
  security: TechComp[]
  outdatedComponents: OutdatedComp[]
  missingSecurityHeaders: string[]
}

interface Props {
  techData?: string
}

function VersionBadge({ name, version, outdated }: { name: string; version?: string; outdated: boolean }) {
  return (
    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-sm ${
      outdated
        ? 'bg-red-50 border-red-200 text-red-700'
        : 'bg-gray-50 border-gray-200 text-gray-700'
    }`}>
      <span className="font-medium">{name}</span>
      {version && <span className="text-xs opacity-70 font-mono">{version}</span>}
      {outdated && <AlertTriangle size={12} className="text-red-500 shrink-0" />}
    </div>
  )
}

function Section({ icon, title, items, outdatedNames }: {
  icon: React.ReactNode
  title: string
  items: TechComp[]
  outdatedNames: Set<string>
}) {
  if (!items?.length) return null
  return (
    <div>
      <p className="flex items-center gap-1.5 text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
        {icon} {title}
      </p>
      <div className="flex flex-wrap gap-2">
        {items.map((c, i) => (
          <VersionBadge
            key={i}
            name={c.name}
            version={c.version}
            outdated={outdatedNames.has(c.name.toLowerCase())}
          />
        ))}
      </div>
    </div>
  )
}

export function TechStackCard({ techData }: Props) {
  if (!techData) return null

  let tech: TechData | null = null
  try { tech = JSON.parse(techData) } catch { return null }
  if (!tech) return null

  const outdatedNames = new Set(
    (tech.outdatedComponents || []).map(o => o.component.toLowerCase())
  )

  const hasIssues = tech.outdatedComponents?.length > 0 || tech.missingSecurityHeaders?.length > 0

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
      <div className="flex items-center justify-between mb-5">
        <h2 className="font-semibold text-gray-800 flex items-center gap-2">
          <Layers size={16} className="text-gray-400" /> Stack technique
        </h2>
        {hasIssues
          ? <span className="flex items-center gap-1 text-xs text-orange-600 font-medium bg-orange-50 px-2 py-1 rounded-full">
              <ShieldAlert size={12} /> Problèmes détectés
            </span>
          : <span className="flex items-center gap-1 text-xs text-green-600 font-medium bg-green-50 px-2 py-1 rounded-full">
              <CheckCircle size={12} /> Stack à jour
            </span>
        }
      </div>

      <div className="grid grid-cols-2 gap-5">
        <Section icon={<Server size={12} />}  title="Serveur web"  items={tech.server}     outdatedNames={outdatedNames} />
        <Section icon={<Globe size={12} />}   title="OS / Système" items={tech.os}         outdatedNames={outdatedNames} />
        <Section icon={<Code2 size={12} />}   title="Langages"    items={tech.languages}   outdatedNames={outdatedNames} />
        <Section icon={<Layers size={12} />}  title="Frameworks"  items={tech.frameworks}  outdatedNames={outdatedNames} />
        <Section icon={<Package size={12} />} title="CMS"         items={tech.cms}         outdatedNames={outdatedNames} />
        <Section icon={<Package size={12} />} title="Librairies"  items={tech.libraries}   outdatedNames={outdatedNames} />
        <Section icon={<Shield size={12} />}  title="Sécurité"    items={tech.security}    outdatedNames={outdatedNames} />
        <Section icon={<Globe size={12} />}   title="CDN / Proxy" items={tech.cdn}         outdatedNames={outdatedNames} />
      </div>

      {/* Composants obsolètes */}
      {tech.outdatedComponents?.length > 0 && (
        <div className="mt-5 border-t border-gray-100 pt-4">
          <p className="text-xs font-semibold text-red-600 uppercase tracking-wide mb-3 flex items-center gap-1.5">
            <AlertTriangle size={12} /> Composants obsolètes / à mettre à jour
          </p>
          <div className="space-y-2">
            {tech.outdatedComponents.map((c, i) => (
              <div key={i} className="flex items-center gap-3 bg-red-50 border border-red-100 rounded-lg px-3 py-2 text-sm">
                <AlertTriangle size={14} className="text-red-500 shrink-0" />
                <span className="font-medium text-red-800">{c.component}</span>
                <span className="text-red-600 font-mono text-xs">v{c.detectedVersion}</span>
                <span className="text-gray-400 text-xs">→ minimum recommandé :</span>
                <span className="text-green-700 font-mono text-xs">v{c.minimumSafeVersion}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* En-têtes de sécurité manquants */}
      {tech.missingSecurityHeaders?.length > 0 && (
        <div className="mt-4 border-t border-gray-100 pt-4">
          <p className="text-xs font-semibold text-orange-600 uppercase tracking-wide mb-3 flex items-center gap-1.5">
            <ShieldAlert size={12} /> En-têtes de sécurité manquants
          </p>
          <div className="flex flex-wrap gap-2">
            {tech.missingSecurityHeaders.map((h, i) => (
              <span key={i} className="text-xs bg-orange-50 border border-orange-200 text-orange-700 px-2.5 py-1 rounded-lg">
                {h}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* En-têtes bruts */}
      {tech.headers && Object.keys(tech.headers).length > 0 && (
        <details className="mt-4 border-t border-gray-100 pt-4">
          <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-600 font-medium">
            Voir les en-têtes HTTP bruts ({Object.keys(tech.headers).length})
          </summary>
          <div className="mt-2 bg-gray-900 rounded-lg p-3 font-mono text-xs space-y-0.5 max-h-48 overflow-y-auto">
            {Object.entries(tech.headers).map(([k, v]) => (
              <p key={k}>
                <span className="text-blue-300">{k}:</span>{' '}
                <span className="text-gray-300">{v}</span>
              </p>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}