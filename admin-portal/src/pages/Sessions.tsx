import { useState, useEffect } from 'react'
import { 
  Monitor, Smartphone, Globe, Clock, User, 
  LogOut, Trash2, RefreshCw, CheckSquare, Square,
  AlertCircle
} from 'lucide-react'
import { api } from '../services/api'
import { toast } from '../components/ui/Toast'

interface Session {
  jti: string
  user_id: string
  user_email?: string
  ip_address: string
  device_info: {
    user_agent?: string
  } | null
  created_at: string
  expires_at: string
  status: string
}

export default function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedSessions, setSelectedSessions] = useState<Set<string>>(new Set())
  const [bulkActionLoading, setBulkActionLoading] = useState(false)

  useEffect(() => {
    loadSessions()
  }, [])

  const loadSessions = async () => {
    setLoading(true)
    try {
      const response = await api.getAllSessions()
      if (response.success && response.data) {
        setSessions(response.data)
      } else {
        toast({ title: 'Failed to load sessions', description: response.error, type: 'error' })
      }
    } catch (error) {
      toast({ title: 'Error loading sessions', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const handleRevokeSession = async (jti: string) => {
    try {
      const response = await api.revokeSession(jti)
      if (response.success) {
        toast({ title: 'Session revoked', type: 'success' })
        setSessions(sessions.filter(s => s.jti !== jti))
        setSelectedSessions(prev => {
          const newSet = new Set(prev)
          newSet.delete(jti)
          return newSet
        })
      } else {
        toast({ title: 'Failed to revoke session', description: response.error, type: 'error' })
      }
    } catch (error) {
      toast({ title: 'Error revoking session', type: 'error' })
    }
  }

  const handleBulkRevoke = async () => {
    if (selectedSessions.size === 0) return
    
    setBulkActionLoading(true)
    try {
      const response = await api.bulkRevokeSessions(Array.from(selectedSessions))
      if (response.success) {
        toast({ 
          title: 'Sessions revoked', 
          description: `Revoked ${response.data?.revoked_count || selectedSessions.size} sessions`, 
          type: 'success' 
        })
        setSessions(sessions.filter(s => !selectedSessions.has(s.jti)))
        setSelectedSessions(new Set())
      } else {
        toast({ title: 'Failed to revoke sessions', description: response.error, type: 'error' })
      }
    } catch (error) {
      toast({ title: 'Error revoking sessions', type: 'error' })
    } finally {
      setBulkActionLoading(false)
    }
  }

  const toggleSelectAll = () => {
    if (selectedSessions.size === sessions.length) {
      setSelectedSessions(new Set())
    } else {
      setSelectedSessions(new Set(sessions.map(s => s.jti)))
    }
  }

  const toggleSelectSession = (jti: string) => {
    setSelectedSessions(prev => {
      const newSet = new Set(prev)
      if (newSet.has(jti)) {
        newSet.delete(jti)
      } else {
        newSet.add(jti)
      }
      return newSet
    })
  }

  const getDeviceIcon = (deviceInfo: Session['device_info']) => {
    const ua = deviceInfo?.user_agent?.toLowerCase() || ''
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
      return <Smartphone className="w-4 h-4" />
    }
    return <Monitor className="w-4 h-4" />
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString()
  }

  const getTimeAgo = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMs / 3600000)
    const diffDays = Math.floor(diffMs / 86400000)

    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    return `${diffDays}d ago`
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-navy-50">Session Management</h1>
          <p className="text-navy-400 mt-1">Manage active sessions across your organization</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadSessions}
            disabled={loading}
            className="btn-secondary flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Bulk Actions */}
      {selectedSessions.size > 0 && (
        <div className="bg-hex-600/10 border border-hex-600/30 rounded-lg p-4 flex items-center justify-between">
          <span className="text-hex-400">
            {selectedSessions.size} session{selectedSessions.size > 1 ? 's' : ''} selected
          </span>
          <button
            onClick={handleBulkRevoke}
            disabled={bulkActionLoading}
            className="btn-danger flex items-center gap-2"
          >
            {bulkActionLoading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <LogOut className="w-4 h-4" />
            )}
            Revoke Selected
          </button>
        </div>
      )}

      {/* Sessions Table */}
      <div className="card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-navy-700">
              <th className="p-4 text-left">
                <button onClick={toggleSelectAll} className="text-navy-400 hover:text-navy-200">
                  {selectedSessions.size === sessions.length && sessions.length > 0 ? (
                    <CheckSquare className="w-5 h-5" />
                  ) : (
                    <Square className="w-5 h-5" />
                  )}
                </button>
              </th>
              <th className="p-4 text-left text-sm font-medium text-navy-300">User</th>
              <th className="p-4 text-left text-sm font-medium text-navy-300">Device</th>
              <th className="p-4 text-left text-sm font-medium text-navy-300">IP Address</th>
              <th className="p-4 text-left text-sm font-medium text-navy-300">Created</th>
              <th className="p-4 text-left text-sm font-medium text-navy-300">Expires</th>
              <th className="p-4 text-left text-sm font-medium text-navy-300">Status</th>
              <th className="p-4 text-right text-sm font-medium text-navy-300">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-navy-400">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2" />
                  Loading sessions...
                </td>
              </tr>
            ) : sessions.length === 0 ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-navy-400">
                  <AlertCircle className="w-6 h-6 mx-auto mb-2" />
                  No active sessions found
                </td>
              </tr>
            ) : (
              sessions.map((session) => (
                <tr key={session.jti} className="border-b border-navy-800 hover:bg-navy-800/50">
                  <td className="p-4">
                    <button 
                      onClick={() => toggleSelectSession(session.jti)}
                      className="text-navy-400 hover:text-navy-200"
                    >
                      {selectedSessions.has(session.jti) ? (
                        <CheckSquare className="w-5 h-5 text-hex-500" />
                      ) : (
                        <Square className="w-5 h-5" />
                      )}
                    </button>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <User className="w-4 h-4 text-navy-400" />
                      <span className="text-navy-200 text-sm">
                        {session.user_email || session.user_id.slice(0, 8)}
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2 text-navy-300">
                      {getDeviceIcon(session.device_info)}
                      <span className="text-sm truncate max-w-[200px]" title={session.device_info?.user_agent}>
                        {session.device_info?.user_agent?.split(' ')[0] || 'Unknown'}
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2 text-navy-300">
                      <Globe className="w-4 h-4" />
                      <span className="text-sm font-mono">{session.ip_address || 'Unknown'}</span>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2 text-navy-300">
                      <Clock className="w-4 h-4" />
                      <span className="text-sm" title={formatDate(session.created_at)}>
                        {getTimeAgo(session.created_at)}
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <span className="text-sm text-navy-400" title={formatDate(session.expires_at)}>
                      {formatDate(session.expires_at)}
                    </span>
                  </td>
                  <td className="p-4">
                    <span className={`badge ${session.status === 'active' ? 'badge-success' : 'badge-warning'}`}>
                      {session.status}
                    </span>
                  </td>
                  <td className="p-4 text-right">
                    <button
                      onClick={() => handleRevokeSession(session.jti)}
                      className="text-red-400 hover:text-red-300 p-2 rounded hover:bg-red-500/10"
                      title="Revoke session"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        <div className="card p-4">
          <div className="text-2xl font-semibold text-navy-50">{sessions.length}</div>
          <div className="text-sm text-navy-400">Active Sessions</div>
        </div>
        <div className="card p-4">
          <div className="text-2xl font-semibold text-navy-50">
            {new Set(sessions.map(s => s.user_id)).size}
          </div>
          <div className="text-sm text-navy-400">Active Users</div>
        </div>
        <div className="card p-4">
          <div className="text-2xl font-semibold text-navy-50">
            {new Set(sessions.map(s => s.ip_address)).size}
          </div>
          <div className="text-sm text-navy-400">Unique IPs</div>
        </div>
      </div>
    </div>
  )
}
