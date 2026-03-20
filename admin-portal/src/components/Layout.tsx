import { Outlet, NavLink } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { LogoMark } from './Logo'
import {
  LayoutDashboard,
  AppWindow,
  Shield,
  UserPlus,
  LogOut,
  ChevronRight,
  Monitor,
  Settings,
  Network,
} from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/admin', icon: LayoutDashboard },
  { name: 'Client Apps', href: '/admin/clients', icon: AppWindow },
  { name: 'Policies', href: '/admin/policies', icon: Shield },
  { name: 'Sessions', href: '/admin/sessions', icon: Monitor },
  { name: 'Invitations', href: '/admin/invitations', icon: UserPlus },
  { name: 'Federation', href: '/admin/federation', icon: Network },
  { name: 'Settings', href: '/admin/settings', icon: Settings },
]

export default function Layout() {
  const { user, logout } = useAuth()

  return (
    <div className="min-h-screen bg-navy-950 flex">
      {/* Sidebar */}
      <aside className="w-64 bg-navy-900 border-r border-navy-800 flex flex-col">
        {/* Logo */}
        <div className="h-16 flex items-center px-4 border-b border-navy-800">
          <LogoMark className="w-8 h-8" />
          <span className="ml-3 text-hex-400 font-semibold tracking-wider">HEXALGON</span>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navigation.map((item) => (
            <NavLink
              key={item.name}
              to={item.href}
              end={item.href === '/admin'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-hex-600/20 text-hex-400'
                    : 'text-navy-300 hover:bg-navy-800 hover:text-navy-100'
                }`
              }
            >
              <item.icon size={18} />
              {item.name}
              <ChevronRight size={14} className="ml-auto opacity-50" />
            </NavLink>
          ))}
        </nav>

        {/* User section */}
        <div className="p-4 border-t border-navy-800">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-9 h-9 rounded-full bg-hex-600/20 flex items-center justify-center">
              <span className="text-hex-400 text-sm font-medium">
                {user?.email?.charAt(0).toUpperCase()}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-navy-100 truncate">
                {user?.first_name || user?.email}
              </p>
              <p className="text-xs text-navy-400 truncate">{user?.role}</p>
            </div>
          </div>
          <button
            onClick={logout}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-navy-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
          >
            <LogOut size={16} />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
