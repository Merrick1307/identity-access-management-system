import { useAuth } from '../context/AuthContext'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'
import { AppWindow, Shield, UserPlus, Activity } from 'lucide-react'

export default function Dashboard() {
  const { user } = useAuth()

  const { data: clients } = useQuery({
    queryKey: ['clients'],
    queryFn: () => api.getClients(),
  })

  const { data: policies } = useQuery({
    queryKey: ['dashboard-policies-count'],
    queryFn: () => api.getTenantPoliciesPage(1, 1),
  })

  const { data: invitations } = useQuery({
    queryKey: ['invitations'],
    queryFn: () => api.getInvitations(),
  })

  const stats = [
    {
      name: 'Client Apps',
      value: clients?.data?.length || 0,
      icon: AppWindow,
      color: 'text-hex-400',
      bgColor: 'bg-hex-500/20',
    },
    {
      name: 'Active Policies',
      value: policies?.data?.pagination.total_items || 0,
      icon: Shield,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/20',
    },
    {
      name: 'Pending Invitations',
      value: invitations?.data?.filter((i) => !i.accepted_at).length || 0,
      icon: UserPlus,
      color: 'text-amber-400',
      bgColor: 'bg-amber-500/20',
    },
    {
      name: 'System Status',
      value: 'Healthy',
      icon: Activity,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/20',
    },
  ]

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-navy-50">
          Welcome back, {user?.first_name || user?.email}
        </h1>
        <p className="text-navy-400 mt-1">
          Here's an overview of your identity platform
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {stats.map((stat) => (
          <div key={stat.name} className="card">
            <div className="card-body">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-navy-400">{stat.name}</p>
                  <p className="text-2xl font-semibold text-navy-50 mt-1">
                    {stat.value}
                  </p>
                </div>
                <div className={`p-3 rounded-lg ${stat.bgColor}`}>
                  <stat.icon className={`w-6 h-6 ${stat.color}`} />
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Clients */}
        <div className="card">
          <div className="card-header flex items-center justify-between">
            <h2 className="text-lg font-medium text-navy-50">Recent Clients</h2>
            <a href="/admin/clients" className="text-sm text-hex-400 hover:text-hex-300">
              View all
            </a>
          </div>
          <div className="card-body p-0">
            {clients?.data?.slice(0, 5).map((client) => (
              <div
                key={client.client_id}
                className="flex items-center justify-between px-6 py-3 border-b border-navy-700 last:border-0"
              >
                <div>
                  <p className="text-sm font-medium text-navy-100">{client.name}</p>
                  <p className="text-xs text-navy-400 font-mono">
                    {client.client_id.substring(0, 20)}...
                  </p>
                </div>
                <span
                  className={`badge ${
                    client.is_active ? 'badge-success' : 'badge-danger'
                  }`}
                >
                  {client.is_active ? 'Active' : 'Inactive'}
                </span>
              </div>
            )) || (
              <p className="text-navy-400 text-sm px-6 py-4">No clients yet</p>
            )}
          </div>
        </div>

        {/* Pending Invitations */}
        <div className="card">
          <div className="card-header flex items-center justify-between">
            <h2 className="text-lg font-medium text-navy-50">Pending Invitations</h2>
            <a href="/admin/invitations" className="text-sm text-hex-400 hover:text-hex-300">
              View all
            </a>
          </div>
          <div className="card-body p-0">
            {invitations?.data
              ?.filter((i) => !i.accepted_at)
              .slice(0, 5)
              .map((invitation) => (
                <div
                  key={invitation.id}
                  className="flex items-center justify-between px-6 py-3 border-b border-navy-700 last:border-0"
                >
                  <div>
                    <p className="text-sm font-medium text-navy-100">
                      {invitation.email}
                    </p>
                    <p className="text-xs text-navy-400">
                      Role: {invitation.role || 'user'}
                    </p>
                  </div>
                  <span className="badge badge-warning">Pending</span>
                </div>
              )) || (
              <p className="text-navy-400 text-sm px-6 py-4">
                No pending invitations
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Tenant Info */}
      <div className="card mt-6">
        <div className="card-header">
          <h2 className="text-lg font-medium text-navy-50">Tenant Information</h2>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-navy-400">Tenant ID</p>
              <code className="text-hex-400 font-mono text-sm">{user?.tenant_id}</code>
            </div>
            <div>
              <p className="text-sm text-navy-400">Admin Email</p>
              <p className="text-navy-100">{user?.email}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
