export function ProgressBar({ value }: { value: number }) {
  const pct = Math.min(100, Math.max(0, value))
  return (
    <div className="w-full bg-gray-200 rounded-full h-2">
      <div
        className="bg-brand-600 h-2 rounded-full transition-all duration-500"
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}