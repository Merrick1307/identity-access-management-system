import { useState, useEffect } from 'react'
import { 
  Globe, Clock, User, LogOut, Trash2, RefreshCw,
  CheckSquare, Square, AlertCircle, ChevronLeft,
  ChevronRight, X
} from 'lucide-react'
import { api } from '../services/api'
import { toast } from '../components/ui/Toast'

interface Session {
  jti: string
  user_id: string
  user_email?: string
  ip_address: string
  has_device_info: boolean
  created_at: string
  expires_at: string
  status: string
}

interface PaginationMeta {
  page: number
  page_size: number
  total_items: number
  total_pages: number
}

const PAGE_SIZE = 20

export default function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [pagination, setPagination] = useState<PaginationMeta>({
    page: 1,
    page_size: PAGE_SIZE,
    total_items: 0,
    total_pages: 0,
  })
  const [currentPage, setCurrentPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [selectedSessions, setSelectedSessions] = useState<Set<string>>(new Set())
  const [bulkActionLoading, setBulkActionLoading] = useState(false)
  const [deviceInfoSession, setDeviceInfoSession] = useState<string | null>(null)
  const [deviceInfo, setDeviceInfo] = useState<Record<string, unknown> | null>(null)
  const [deviceInfoLoading, setDeviceInfoLoading] = useState(false)
  const [deviceInfoError, setDeviceInfoError] = useState<string | null>(null)

  useEffect(() => {
    loadSessions(currentPage)
  }, [currentPage])

  const loadSessions = async (page = currentPage) => {
    setLoading(true)
    try {
      const response = await api.getAllSessionsPage(page, PAGE_SIZE)
      if (response.success && response.data) {
        const { sessions: pageSessions, pagination: pageMeta } = response.data

        if (pageMeta.total_pages > 0 && page > pageMeta.total_pages) {
          setCurrentPage(pageMeta.total_pages)
          return
        }

        if (pageMeta.total_pages === 0 && page > 1) {
          setCurrentPage(1)
          return
        }

        setSessions(pageSessions)
        setPagination(pageMeta)
        setSelectedSessions(new Set())
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
        await loadSessions(currentPage)
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
        await loadSessions(currentPage)
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

  const openDeviceInfo = async (jti: string) => {
    setDeviceInfoSession(jti)
    setDeviceInfo(null)
    setDeviceInfoError(null)
    setDeviceInfoLoading(true)

    try {
      const response = await api.getSessionDeviceInfo(jti)
      if (response.success && response.data) {
        setDeviceInfo(response.data.device_info)
      } else {
        setDeviceInfoError(response.error || 'Unable to load device information')
      }
    } catch {
      setDeviceInfoError('Unable to load device information')
    } finally {
      setDeviceInfoLoading(false)
    }
  }

  const closeDeviceInfo = () => {
    setDeviceInfoSession(null)
    setDeviceInfo(null)
    setDeviceInfoError(null)
    setDeviceInfoLoading(false)
  }

  const visibleRangeStart = pagination.total_items === 0 ? 0 : (pagination.page - 1) * pagination.page_size + 1
  const visibleRangeEnd = pagination.total_items === 0
    ? 0
    : visibleRangeStart + sessions.length - 1

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
            onClick={() => loadSessions(currentPage)}
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
                    {session.has_device_info ? (
                      <button
                        onClick={() => openDeviceInfo(session.jti)}
                        className="text-sm text-hex-400 hover:text-hex-300 hover:underline"
                      >
                        View device info
                      </button>
                    ) : (
                      <span className="text-sm text-navy-500">Unavailable</span>
                    )}
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
        <div className="flex items-center justify-between border-t border-navy-700 px-4 py-3">
          <p className="text-sm text-navy-400">
            Showing {visibleRangeStart}-{visibleRangeEnd} of {pagination.total_items} sessions
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((prev) => Math.max(prev - 1, 1))}
              disabled={loading || currentPage <= 1}
              className="btn btn-ghost p-2 disabled:opacity-50"
              title="Previous page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-sm text-navy-300">
              Page {pagination.page} of {Math.max(pagination.total_pages, 1)}
            </span>
            <button
              onClick={() => setCurrentPage((prev) => prev + 1)}
              disabled={loading || currentPage >= pagination.total_pages}
              className="btn btn-ghost p-2 disabled:opacity-50"
              title="Next page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        <div className="card p-4">
          <div className="text-2xl font-semibold text-navy-50">{pagination.total_items}</div>
          <div className="text-sm text-navy-400">Total Active Sessions</div>
        </div>
        <div className="card p-4">
          <div className="text-2xl font-semibold text-navy-50">
            {new Set(sessions.map(s => s.user_id)).size}
          </div>
          <div className="text-sm text-navy-400">Visible Users</div>
        </div>
        <div className="card p-4">
          <div className="text-2xl font-semibold text-navy-50">
            {new Set(sessions.map(s => s.ip_address)).size}
          </div>
          <div className="text-sm text-navy-400">Visible IPs</div>
        </div>
      </div>

      {deviceInfoSession && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="card w-full max-w-2xl">
            <div className="card-header flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-navy-50">Device Information</h2>
                <p className="text-sm text-navy-400 font-mono">{deviceInfoSession}</p>
              </div>
              <button onClick={closeDeviceInfo} className="text-navy-400 hover:text-navy-200">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="card-body space-y-4">
              {deviceInfoLoading ? (
                <div className="py-8 text-center text-navy-400">
                  <RefreshCw className="mx-auto mb-2 h-6 w-6 animate-spin" />
                  Loading device information...
                </div>
              ) : deviceInfoError ? (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
                  {deviceInfoError}
                </div>
              ) : deviceInfo ? (
                <>
                  <div className="grid gap-3 md:grid-cols-2">
                    {Object.entries(deviceInfo).map(([key, value]) => (
                      <div key={key} className="rounded-lg border border-navy-700 bg-navy-900 p-3">
                        <p className="text-xs uppercase tracking-wide text-navy-500">{key.replace(/_/g, ' ')}</p>
                        <p className="mt-1 break-all text-sm text-navy-100">
                          {typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value)}
                        </p>
                      </div>
                    ))}
                  </div>
                  <div>
                    <p className="label">Raw Payload</p>
                    <pre className="overflow-x-auto rounded-lg bg-navy-950 p-4 text-xs text-navy-300">
                      {JSON.stringify(deviceInfo, null, 2)}
                    </pre>
                  </div>
                </>
              ) : (
                <p className="text-sm text-navy-400">No device information is available for this session.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
