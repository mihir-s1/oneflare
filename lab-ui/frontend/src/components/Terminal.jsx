import { useState } from 'react'
import { Copy, Check, Terminal as TerminalIcon } from 'lucide-react'

// Returns a semantic modifier class; the actual color is driven by CSS vars
// (see .attack-terminal in index.css) so it adapts to light/dark theme.
function classifyLine(line) {
  if (!line) return 'is-muted'
  const l = line.toUpperCase()
  if (l.includes('403') || l.includes('BLOCKED') || l.includes('✔') || l.includes('[BLOCK]') || l.includes('PASS'))
    return 'is-block'
  if (l.includes('ERROR') || l.includes('FAILED') || l.includes('EXCEPTION'))
    return 'is-error'
  if (l.includes('200') || l.includes('ALLOWED') || l.includes('✖') || l.includes('[ALLOW]') || l.includes('BYPASS'))
    return 'is-allow'
  if (l.includes('RUNNING') || l.includes('►') || l.includes('STARTING') || l.includes('[*]') || l.includes('SENDING') || l.includes('SCENARIO'))
    return 'is-run'
  if (l.includes('WARNING') || l.includes('WARN'))
    return 'is-warn'
  if (l.startsWith('[+]') || l.startsWith('✓'))
    return 'is-block'
  if (l.startsWith('[-]') || l.startsWith('✗'))
    return 'is-error'
  if (l.trim().startsWith('—') || l.trim().startsWith('──'))
    return 'is-phase'
  return 'is-default'
}

export default function Terminal({ lines = [], isRunning = false, title = 'Terminal' }) {
  const [copied, setCopied] = useState(false)

  // Autoscroll intentionally disabled: appending a line must NOT scroll the page
  // (or the log box) to the bottom. The user scrolls the box manually.

  const handleCopy = () => {
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div
      className="attack-terminal rounded-xl overflow-hidden"
      style={{ fontFamily: '"JetBrains Mono", "Fira Code", Consolas, monospace' }}
    >
      {/* Title bar */}
      <div className="attack-terminal-bar flex items-center justify-between px-4 py-2.5">
        <div className="flex items-center gap-3">
          {/* Traffic lights */}
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/70" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
            <div className="w-3 h-3 rounded-full bg-green-500/70" />
          </div>
          <div className="attack-terminal-chrome flex items-center gap-1.5 text-xs">
            <TerminalIcon className="w-3 h-3" />
            <span>{title}</span>
          </div>
          {isRunning && (
            <div className="flex items-center gap-1 text-cyan-500 text-xs">
              <span className="inline-block w-1.5 h-1.5 bg-cyan-500 rounded-full animate-pulse" />
              running
            </div>
          )}
        </div>
        <button
          onClick={handleCopy}
          disabled={lines.length === 0}
          className="attack-terminal-chrome flex items-center gap-1.5 text-xs transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
        >
          {copied ? (
            <><Check className="w-3.5 h-3.5 text-green-500" /><span className="text-green-500">Copied</span></>
          ) : (
            <><Copy className="w-3.5 h-3.5" /><span>Copy</span></>
          )}
        </button>
      </div>

      {/* Terminal body */}
      <div
        className="attack-terminal-body terminal-scroll overflow-y-auto overflow-x-auto p-4 text-sm leading-relaxed"
        style={{ minHeight: '280px', maxHeight: '480px' }}
      >
        {lines.length === 0 ? (
          <div className="attack-terminal-line is-muted flex items-center gap-2 text-xs">
            <span className="attack-terminal-prompt">$</span>
            <span>Waiting for attack to start...</span>
            {isRunning && <span className="attack-terminal-caret inline-block w-2 h-3.5 animate-[blink_1s_step-end_infinite]" />}
          </div>
        ) : (
          <>
            {lines.map((line, i) => (
              <div
                key={i}
                className={`attack-terminal-line ${classifyLine(line)} whitespace-pre-wrap break-all text-xs leading-5`}
              >
                {line || ' '}
              </div>
            ))}
          </>
        )}
        {isRunning && lines.length > 0 && (
          <div className="flex items-center gap-1 mt-1">
            <span className="attack-terminal-prompt text-xs">$</span>
            <span
              className="attack-terminal-caret inline-block w-2 h-3.5"
              style={{ animation: 'blink 1s step-end infinite' }}
            />
          </div>
        )}
      </div>
    </div>
  )
}
