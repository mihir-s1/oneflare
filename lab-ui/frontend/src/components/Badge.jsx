export default function Badge({ type, value, size = 'sm' }) {
  const sizeClasses = size === 'sm'
    ? 'px-2 py-0.5 text-xs'
    : 'px-3 py-1 text-sm'

  if (type === 'severity') {
    const map = {
      Critical: 'bg-red-500/15 text-red-400 border border-red-500/30',
      High:     'bg-orange-500/15 text-orange-400 border border-orange-500/30',
      Medium:   'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
      Low:      'bg-blue-500/15 text-blue-400 border border-blue-500/30',
    }
    return (
      <span className={`inline-flex items-center rounded-full font-semibold font-mono tracking-wide ${sizeClasses} ${map[value] || map.Low}`}>
        {value}
      </span>
    )
  }

  if (type === 'category') {
    const map = {
      WAF:              'bg-orange-500/15 text-orange-400 border border-orange-500/30',
      Access:           'bg-purple-500/15 text-purple-400 border border-purple-500/30',
      Gateway:          'bg-blue-500/15 text-blue-400 border border-blue-500/30',
      Workers:          'bg-red-400/15 text-red-300 border border-red-400/30',
      'Bot Management': 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30',
      'AI Security':    'bg-pink-500/15 text-pink-400 border border-pink-500/30',
      Campaign:         'bg-amber-500/15 text-amber-400 border border-amber-500/30',
    }
    return (
      <span className={`inline-flex items-center rounded-full font-semibold ${sizeClasses} ${map[value] || map.WAF}`}>
        {value}
      </span>
    )
  }

  if (type === 'number') {
    return (
      <span className={`inline-flex items-center rounded font-mono font-bold bg-white/5 border border-white/10 text-slate-400 ${sizeClasses}`}>
        {value}
      </span>
    )
  }

  return (
    <span className={`inline-flex items-center rounded-full font-semibold bg-white/10 text-slate-300 ${sizeClasses}`}>
      {value}
    </span>
  )
}
