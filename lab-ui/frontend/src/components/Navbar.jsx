import { useState, useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Network,
  Settings,
  Target,
  ShieldCheck,
} from 'lucide-react'

const NAV_ITEMS = [
  { to: '/',             label: 'Dashboard',    icon: LayoutDashboard },
  { to: '/scenarios',    label: 'Scenarios',    icon: Target },
  { to: '/architecture', label: 'Architecture', icon: Network },
]

function NavItem({ to, label, icon: Icon, location }) {
  const isActive = to === '/'
    ? location.pathname === '/'
    : location.pathname.startsWith(to)
  return (
    <NavLink
      key={to}
      to={to}
      className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-200 shrink-0 ${
        isActive
          ? 'text-orange-400 bg-orange-500/10'
          : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
      }`}
    >
      <Icon className="w-3.5 h-3.5 shrink-0" />
      <span className="hidden md:inline">{label}</span>
      {isActive && (
        <span className="absolute bottom-0 left-2 right-2 h-px bg-gradient-to-r from-orange-500 to-purple-500 rounded-full" />
      )}
    </NavLink>
  )
}

export default function Navbar() {
  const location = useLocation()
  // Admin nav link is intentionally NOT a prominent, always-visible item —
  // the RBAC login gate on /admin itself is the real access control. The
  // only discoverable entry point for a logged-out user is a discreet link
  // in the Settings page footer. Here we only surface the nav link once the
  // visitor already has a valid admin-console session (GET /api/auth/me),
  // and only on an instance where admin is enabled at all.
  const [adminEnabled, setAdminEnabled] = useState(false)
  const [authed, setAuthed] = useState(false)
  useEffect(() => {
    let alive = true
    fetch('/api/config')
      .then(r => (r.ok ? r.json() : null))
      .then(cfg => { if (alive && cfg?.admin_enabled) setAdminEnabled(true) })
      .catch(() => {})
    fetch('/api/auth/me')
      .then(r => { if (alive) setAuthed(r.ok) })
      .catch(() => {})
    return () => { alive = false }
  }, [location.pathname])

  return (
    <nav className="glass-nav sticky top-0 z-50">
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 h-14 flex items-center gap-4">
        {/* Logo */}
        <NavLink to="/" className="flex items-center gap-2 shrink-0 group">
          <img
            src="/logo.png"
            alt="OneFlare"
            className="h-8 w-auto shrink-0 transition-transform group-hover:scale-105"
          />
          <span className="font-bold text-lg tracking-tight">
            <span className="gradient-text-orange">One</span>
            <span className="text-slate-100">Flare</span>
          </span>
          <span className="hidden sm:inline text-xs font-mono text-slate-600 ml-1 border border-slate-700/50 rounded px-1.5 py-0.5">
            LAB
          </span>
        </NavLink>

        {/* Nav items — scroll (never overlap) if the row is too narrow */}
        <div className="flex items-center gap-0.5 flex-1 min-w-0 overflow-x-auto no-scrollbar">
          <div className="flex items-center gap-0.5 shrink-0">
            {NAV_ITEMS.map((item) => (
              <NavItem key={item.to} {...item} location={location} />
            ))}
          </div>
        </div>

        {/* Admin — only visible once already logged in (discreet by design;
            see Settings page footer for the actual entry point) */}
        {adminEnabled && authed && (
          <NavLink
            to="/admin"
            className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-200 shrink-0 ${
              location.pathname.startsWith('/admin')
                ? 'text-orange-400 bg-orange-500/10'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
            }`}
            aria-label="Admin"
          >
            <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
            <span className="hidden md:inline">Admin</span>
            {location.pathname.startsWith('/admin') && (
              <span className="absolute bottom-0 left-2 right-2 h-px bg-gradient-to-r from-orange-500 to-purple-500 rounded-full" />
            )}
          </NavLink>
        )}

        {/* Settings — right-anchored */}
        <NavLink
          to="/settings"
          className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-200 shrink-0 ${
            location.pathname.startsWith('/settings')
              ? 'text-orange-400 bg-orange-500/10'
              : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
          }`}
          aria-label="Settings"
        >
          <Settings className="w-3.5 h-3.5 shrink-0" />
          <span className="hidden md:inline">Settings</span>
          {location.pathname.startsWith('/settings') && (
            <span className="absolute bottom-0 left-2 right-2 h-px bg-gradient-to-r from-orange-500 to-purple-500 rounded-full" />
          )}
        </NavLink>

        {/* Co-brand */}
        <div className="hidden xl:flex items-center gap-1.5 shrink-0 pl-2 border-l border-slate-700/40">
          <span className="text-xs font-semibold text-orange-400/80 tracking-widest uppercase">
            Cloudflare
          </span>
          <span className="text-slate-600 text-xs">+</span>
          <span className="text-xs font-semibold text-purple-400/80 tracking-wide">
            SentinelOne
          </span>
        </div>
      </div>
    </nav>
  )
}
