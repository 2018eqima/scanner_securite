import { Severity } from '../types'

const cfg: Record<Severity, { cls: string }> = {
  HIGH:          { cls: 'bg-red-100 text-red-800 border border-red-200' },
  MEDIUM:        { cls: 'bg-orange-100 text-orange-800 border border-orange-200' },
  LOW:           { cls: 'bg-yellow-100 text-yellow-800 border border-yellow-200' },
  INFORMATIONAL: { cls: 'bg-blue-100 text-blue-800 border border-blue-200' },
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${cfg[severity].cls}`}>
      {severity}
    </span>
  )
}