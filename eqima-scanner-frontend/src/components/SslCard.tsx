import { SslData } from '../types'
import { ShieldCheck, ShieldAlert, ShieldX, Shield, Clock, Server, Lock, AlertTriangle } from 'lucide-react'

interface Props {
  sslGrade?: string
  sslData?: string
}

function gradeConfig(grade: string) {
  switch (grade) {
    case 'A+': return { color: 'bg-emerald-500', text: 'text-white', label: 'Excellent' }
    case 'A':  return { color: 'bg-green-500',   text: 'text-white', label: 'Très bon' }
    case 'B':  return { color: 'bg-yellow-400',  text: 'text-white', label: 'Acceptable' }
    case 'C':  return { color: 'bg-orange-400',  text: 'text-white', label: 'Faible' }
    case 'D':  return { color: 'bg-red-500',     text: 'text-white', label: 'Critique' }
    case 'F':  return { color: 'bg-red-700',     text: 'text-white', label: 'Échec' }
    case 'T':  return { color: 'bg-gray-500',    text: 'text-white', label: 'Certificat non fiable' }
    case 'M':  return { color: 'bg-gray-500',    text: 'text-white', label: 'Mismatch certificat' }
    default:   return { color: 'bg-gray-300',    text: 'text-gray-700', label: 'Inconnu' }
  }
}

function GradeIcon({ grade }: { grade: string }) {
  if (['A+', 'A'].includes(grade)) return <ShieldCheck size={22} />
  if (['B', 'C'].includes(grade))  return <Shield size={22} />
  if (['D', 'F'].includes(grade))  return <ShieldX size={22} />
  return <ShieldAlert size={22} />
}

export function SslCard({ sslGrade, sslData }: Props) {
  if (!sslGrade && !sslData) return null

  let ssl: SslData | null = null
  try {
    if (sslData) ssl = JSON.parse(sslData)
  } catch { /* ignore */ }

  const grade = sslGrade || ssl?.grade || '?'
  const cfg = gradeConfig(grade)

  const certExpiry = ssl?.certExpiry ? new Date(ssl.certExpiry) : null
  const daysLeft = certExpiry
    ? Math.floor((certExpiry.getTime() - Date.now()) / 86_400_000)
    : null

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
      <h2 className="font-semibold text-gray-800 mb-4 flex items-center gap-2">
        <Lock size={16} className="text-gray-400" /> Analyse SSL/TLS
      </h2>

      <div className="flex items-start gap-6">
        {/* Grade */}
        <div className="flex flex-col items-center shrink-0">
          <div className={`${cfg.color} ${cfg.text} w-20 h-20 rounded-2xl flex flex-col items-center justify-center shadow-sm`}>
            <GradeIcon grade={grade} />
            <span className="text-2xl font-black mt-0.5">{grade}</span>
          </div>
          <span className="text-xs text-gray-500 mt-1.5 font-medium">{cfg.label}</span>
        </div>

        {/* Détails */}
        {ssl && (
          <div className="flex-1 grid grid-cols-2 gap-4 text-sm">
            {/* Certificat */}
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1.5">Certificat</p>
              <p className="text-gray-700 font-mono text-xs truncate">{ssl.certSubject || '—'}</p>
              <p className="text-gray-500 text-xs mt-0.5">{ssl.certIssuer || '—'}</p>
              {certExpiry && (
                <p className={`text-xs mt-1 flex items-center gap-1 ${daysLeft! < 30 ? 'text-red-500 font-semibold' : 'text-gray-500'}`}>
                  <Clock size={11} />
                  Expire le {certExpiry.toLocaleDateString('fr-FR')}
                  {daysLeft !== null && ` (${daysLeft}j)`}
                </p>
              )}
            </div>

            {/* Protocoles */}
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1.5">Protocoles supportés</p>
              <div className="flex flex-wrap gap-1">
                {ssl.protocols?.map(p => (
                  <span key={p} className={`text-xs px-2 py-0.5 rounded font-mono font-medium ${
                    p.includes('1.3') ? 'bg-green-50 text-green-700' :
                    p.includes('1.2') ? 'bg-blue-50 text-blue-700' :
                    'bg-red-50 text-red-700'
                  }`}>{p.trim()}</span>
                ))}
              </div>
              {ssl.forwardSecrecy && (
                <p className="text-xs text-green-600 mt-1.5 flex items-center gap-1">
                  <ShieldCheck size={11} /> Forward Secrecy activé
                </p>
              )}
            </div>

            {/* IP */}
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1.5">Serveur</p>
              <p className="text-gray-700 font-mono text-xs flex items-center gap-1">
                <Server size={11} /> {ssl.ipAddress || '—'}
              </p>
            </div>

            {/* Vulnérabilités */}
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1.5">Vulnérabilités</p>
              {!ssl.vulnerabilities?.length ? (
                <p className="text-xs text-green-600 flex items-center gap-1">
                  <ShieldCheck size={11} /> Aucune vulnérabilité connue
                </p>
              ) : (
                <div className="flex flex-wrap gap-1">
                  {ssl.vulnerabilities.map(v => (
                    <span key={v} className="text-xs bg-red-50 text-red-700 border border-red-200 px-2 py-0.5 rounded flex items-center gap-1">
                      <AlertTriangle size={10} /> {v}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}