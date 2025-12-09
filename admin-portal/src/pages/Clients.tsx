import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../services/api'
import { toast } from '../components/ui/Toast'
import { formatDate, copyToClipboard } from '../services/utils'
import {
  Plus,
  Trash2,
  RefreshCw,
  Copy,
  Eye,
  EyeOff,
  X,
  Loader2,
} from 'lucide-react'

interface NewClientSecret {
  client_id: string
  client_secret: string
}

export default function Clients() {
  const queryClient = useQueryClient()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newClientSecret, setNewClientSecret] = useState<NewClientSecret | null>(null)
  const [showSecret, setShowSecret] = useState(false)

  // Form state
  const [name, setName] = useState('')
  const [redirectUris, setRedirectUris] = useState('')
  const [scopes, setScopes] = useState('openid profile email')

  const { data: clients, isLoading } = useQuery({
    queryKey: ['clients'],
    queryFn: () => api.getClients(),
  })

  const createMutation = useMutation({
    mutationFn: (data: { name: string; redirect_uris: string[]; scopes: string[] }) =>
      api.createClient(data),
    onSuccess: (response) => {
      if (response.success && response.data) {
        setNewClientSecret({
          client_id: response.data.client_id,
          client_secret: response.data.client_secret,
        })
        queryClient.invalidateQueries({ queryKey: ['clients'] })
        toast({ title: 'Client created successfully', type: 'success' })
        resetForm()
      } else {
        toast({ title: 'Failed to create client', description: response.error, type: 'error' })
      }
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (clientId: string) => api.deleteClient(clientId),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['clients'] })
        toast({ title: 'Client deleted', type: 'success' })
      } else {
        toast({ title: 'Failed to delete client', type: 'error' })
      }
    },
  })

  const rotateMutation = useMutation({
    mutationFn: (clientId: string) => api.rotateClientSecret(clientId),
    onSuccess: (response) => {
      if (response.success && response.data) {
        setNewClientSecret({
          client_id: response.data.client_id,
          client_secret: response.data.client_secret,
        })
        toast({ title: 'Secret rotated successfully', type: 'success' })
      } else {
        toast({ title: 'Failed to rotate secret', type: 'error' })
      }
    },
  })

  const resetForm = () => {
    setName('')
    setRedirectUris('')
    setScopes('openid profile email')
    setShowCreateModal(false)
  }

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault()
    const uris = redirectUris.split('\n').map((u) => u.trim()).filter(Boolean)
    const scopeList = scopes.split(' ').filter(Boolean)
    createMutation.mutate({ name, redirect_uris: uris, scopes: scopeList })
  }

  const handleCopy = async (text: string, label: string) => {
    await copyToClipboard(text)
    toast({ title: `${label} copied to clipboard`, type: 'info' })
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-navy-50">Client Applications</h1>
          <p className="text-navy-400 mt-1">
            Manage OAuth2/OIDC client applications for your tenant
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary"
        >
          <Plus className="w-4 h-4 mr-2" />
          Register Client
        </button>
      </div>

      {/* Clients Table */}
      <div className="card">
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Client ID</th>
                <th>Redirect URIs</th>
                <th>Scopes</th>
                <th>Status</th>
                <th>Created</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="text-center py-8">
                    <Loader2 className="w-6 h-6 animate-spin mx-auto text-hex-400" />
                  </td>
                </tr>
              ) : clients?.data?.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-navy-400">
                    No clients registered yet
                  </td>
                </tr>
              ) : (
                clients?.data?.map((client) => (
                  <tr key={client.client_id}>
                    <td className="font-medium text-navy-100">{client.name}</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <code className="text-xs text-navy-300 font-mono">
                          {client.client_id.substring(0, 16)}...
                        </code>
                        <button
                          onClick={() => handleCopy(client.client_id, 'Client ID')}
                          className="text-navy-400 hover:text-hex-400"
                        >
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                    <td>
                      <div className="max-w-[200px]">
                        {client.redirect_uris.map((uri, i) => (
                          <div
                            key={i}
                            className="text-xs text-navy-400 truncate"
                            title={uri}
                          >
                            {uri}
                          </div>
                        ))}
                      </div>
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {client.scopes.map((scope) => (
                          <span key={scope} className="badge badge-info">
                            {scope}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          client.is_active ? 'badge-success' : 'badge-danger'
                        }`}
                      >
                        {client.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="text-navy-400 text-sm">
                      {formatDate(client.created_at)}
                    </td>
                    <td>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => rotateMutation.mutate(client.client_id)}
                          className="btn btn-ghost p-2"
                          title="Rotate Secret"
                        >
                          <RefreshCw className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => {
                            if (confirm('Delete this client?')) {
                              deleteMutation.mutate(client.client_id)
                            }
                          }}
                          className="btn btn-ghost p-2 text-red-400 hover:text-red-300"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Client Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-md">
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-navy-50">Register Client</h2>
              <button onClick={resetForm} className="text-navy-400 hover:text-navy-200">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleCreate}>
              <div className="card-body space-y-4">
                <div>
                  <label className="label">Application Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="input"
                    placeholder="My App"
                    required
                  />
                </div>
                <div>
                  <label className="label">Redirect URIs (one per line)</label>
                  <textarea
                    value={redirectUris}
                    onChange={(e) => setRedirectUris(e.target.value)}
                    className="input min-h-[80px]"
                    placeholder="http://localhost:3000/callback&#10;https://myapp.com/callback"
                    required
                  />
                </div>
                <div>
                  <label className="label">Scopes (space-separated)</label>
                  <input
                    type="text"
                    value={scopes}
                    onChange={(e) => setScopes(e.target.value)}
                    className="input"
                    placeholder="openid profile email"
                  />
                </div>
              </div>
              <div className="px-6 py-4 border-t border-navy-700 flex justify-end gap-3">
                <button type="button" onClick={resetForm} className="btn btn-secondary">
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="btn btn-primary"
                >
                  {createMutation.isPending && (
                    <Loader2 className="w-4 h-4 animate-spin mr-2" />
                  )}
                  Create Client
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Client Secret Modal */}
      {newClientSecret && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-md">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-navy-50">Client Credentials</h2>
              <p className="text-sm text-amber-400 mt-1">
                Save these credentials now. The secret cannot be retrieved again.
              </p>
            </div>
            <div className="card-body space-y-4">
              <div>
                <label className="label">Client ID</label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-sm text-hex-400 font-mono bg-navy-900 p-2 rounded break-all">
                    {newClientSecret.client_id}
                  </code>
                  <button
                    onClick={() => handleCopy(newClientSecret.client_id, 'Client ID')}
                    className="btn btn-ghost p-2"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
              </div>
              <div>
                <label className="label">Client Secret</label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-sm text-hex-400 font-mono bg-navy-900 p-2 rounded break-all">
                    {showSecret
                      ? newClientSecret.client_secret
                      : '••••••••••••••••••••••••••••••••'}
                  </code>
                  <button
                    onClick={() => setShowSecret(!showSecret)}
                    className="btn btn-ghost p-2"
                  >
                    {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={() => handleCopy(newClientSecret.client_secret, 'Client Secret')}
                    className="btn btn-ghost p-2"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-navy-700">
              <button
                onClick={() => {
                  setNewClientSecret(null)
                  setShowSecret(false)
                }}
                className="btn btn-primary w-full"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
