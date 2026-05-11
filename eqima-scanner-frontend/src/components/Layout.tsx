import { NavLink, Outlet } from 'react-router-dom'
import { LayoutDashboard, ScanSearch, LogOut, ShieldCheck, Crosshair, Network, Server } from 'lucide-react'
import keycloak from '../auth/keycloak'

const nav = [
  { to: '/',              icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans',         icon: ScanSearch,      label: 'Scans' },
  { to: '/attack-surface',icon: Crosshair,       label: 'Attack Surface' },
  { to: '/infra',         icon: Network,         label: 'Infra réseau' },
  { to: '/hosts-ports',   icon: Server,          label: 'Hosts & Ports' },
]

export function Layout() {
  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-60 bg-brand-900 flex flex-col shrink-0">
        {/* Logo */}
        <div className="flex items-center gap-2 px-5 py-5 border-b border-brand-700">
          <ShieldCheck className="text-brand-100" size={28} />
          <div>
            <p className="text-white font-bold leading-tight">EQIMA</p>
            <p className="text-brand-100 text-xs">Security Scanner</p>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {nav.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-brand-600 text-white'
                    : 'text-brand-100 hover:bg-brand-700 hover:text-white'
                }`
              }
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* User */}
        <div className="px-4 py-4 border-t border-brand-700">
          <p className="text-brand-100 text-xs truncate mb-2">
            {keycloak.tokenParsed?.preferred_username ?? 'Utilisateur'}
          </p>
          <button
            onClick={() => keycloak.logout()}
            className="flex items-center gap-2 text-brand-100 hover:text-white text-sm w-full"
          >
            <LogOut size={16} /> Déconnexion
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}