import { ScanStatus } from '../types'

const cfg: Record<ScanStatus, { label: string; cls: string }> = {
  PENDING:   { label: 'En attente', cls: 'bg-yellow-100 text-yellow-800' },
  RUNNING:   { label: 'En cours',   cls: 'bg-blue-100 text-blue-800 animate-pulse' },
  COMPLETED: { label: 'Terminé',    cls: 'bg-green-100 text-green-800' },
  FAILED:    { label: 'Échoué',     cls: 'bg-red-100 text-red-800' },
}

export function StatusBadge({ status }: { status: ScanStatus }) {
  const { label, cls } = cfg[status]
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${cls}`}>
      {label}
    </span>
  )
}