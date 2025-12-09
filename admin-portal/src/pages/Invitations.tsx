import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../services/api'
import { toast } from '../components/ui/Toast'
import { formatDate, copyToClipboard } from '../services/utils'
import { Plus, Trash2, Copy, X, Loader2, Mail, CheckCircle } from 'lucide-react'

export default function Invitations() {
  const queryClient = useQueryClient()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newInvitation, setNewInvitation] = useState<{
    invitation_link: string
    email: string
  } | null>(null)

  // Form state
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('')

  const { data: invitations, isLoading } = useQuery({
    queryKey: ['invitations'],
    queryFn: () => api.getInvitations(),
  })

  const createMutation = useMutation({
    mutationFn: (data: { email: string; role?: string }) => api.createInvitation(data),
    onSuccess: (response) => {
      if (response.success && response.data) {
        setNewInvitation({
          invitation_link: response.data.invitation_link,
          email: response.data.email,
        })
        queryClient.invalidateQueries({ queryKey: ['invitations'] })
        toast({ title: 'Invitation sent successfully', type: 'success' })
        resetForm()
      } else {
        toast({ title: 'Failed to create invitation', description: response.error, type: 'error' })
      }
    },
  })

  const revokeMutation = useMutation({
    mutationFn: (invitationId: string) => api.revokeInvitation(invitationId),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['invitations'] })
        toast({ title: 'Invitation revoked', type: 'success' })
      } else {
        toast({ title: 'Failed to revoke invitation', type: 'error' })
      }
    },
  })

  const resetForm = () => {
    setEmail('')
    setRole('')
    setShowCreateModal(false)
  }

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault()
    createMutation.mutate({ email, role: role || undefined })
  }

  const handleCopy = async (text: string, label: string) => {
    await copyToClipboard(text)
    toast({ title: `${label} copied to clipboard`, type: 'info' })
  }

  const pendingInvitations = invitations?.data?.filter((i) => !i.accepted_at) || []
  const acceptedInvitations = invitations?.data?.filter((i) => i.accepted_at) || []

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-navy-50">User Invitations</h1>
          <p className="text-navy-400 mt-1">
            Invite users to join your organization
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary"
        >
          <Plus className="w-4 h-4 mr-2" />
          Invite User
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="card">
          <div className="card-body">
            <p className="text-sm text-navy-400">Pending</p>
            <p className="text-2xl font-semibold text-amber-400">
              {pendingInvitations.length}
            </p>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <p className="text-sm text-navy-400">Accepted</p>
            <p className="text-2xl font-semibold text-emerald-400">
              {acceptedInvitations.length}
            </p>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <p className="text-sm text-navy-400">Total</p>
            <p className="text-2xl font-semibold text-navy-100">
              {invitations?.data?.length || 0}
            </p>
          </div>
        </div>
      </div>

      {/* Invitations Table */}
      <div className="card">
        <div className="card-header">
          <h2 className="text-lg font-medium text-navy-50">All Invitations</h2>
        </div>
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Expires</th>
                <th>Created</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="text-center py-8">
                    <Loader2 className="w-6 h-6 animate-spin mx-auto text-hex-400" />
                  </td>
                </tr>
              ) : invitations?.data?.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-navy-400">
                    No invitations sent yet
                  </td>
                </tr>
              ) : (
                invitations?.data?.map((invitation) => (
                  <tr key={invitation.id}>
                    <td>
                      <div className="flex items-center gap-2">
                        <Mail className="w-4 h-4 text-navy-400" />
                        <span className="text-navy-100">{invitation.email}</span>
                      </div>
                    </td>
                    <td>
                      <span className="badge badge-info">
                        {invitation.role || 'user'}
                      </span>
                    </td>
                    <td>
                      {invitation.accepted_at ? (
                        <span className="badge badge-success flex items-center gap-1 w-fit">
                          <CheckCircle className="w-3 h-3" />
                          Accepted
                        </span>
                      ) : new Date(invitation.expires_at) < new Date() ? (
                        <span className="badge badge-danger">Expired</span>
                      ) : (
                        <span className="badge badge-warning">Pending</span>
                      )}
                    </td>
                    <td className="text-navy-400 text-sm">
                      {formatDate(invitation.expires_at)}
                    </td>
                    <td className="text-navy-400 text-sm">
                      {formatDate(invitation.created_at)}
                    </td>
                    <td>
                      <div className="flex items-center justify-end gap-2">
                        {!invitation.accepted_at && (
                          <button
                            onClick={() => {
                              if (confirm('Revoke this invitation?')) {
                                revokeMutation.mutate(invitation.id)
                              }
                            }}
                            className="btn btn-ghost p-2 text-red-400 hover:text-red-300"
                            title="Revoke"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Invitation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-md">
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-navy-50">Invite User</h2>
              <button onClick={resetForm} className="text-navy-400 hover:text-navy-200">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleCreate}>
              <div className="card-body space-y-4">
                <div>
                  <label className="label">Email Address</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="input"
                    placeholder="user@example.com"
                    required
                  />
                </div>
                <div>
                  <label className="label">Role (optional)</label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="input"
                  >
                    <option value="">Default (user)</option>
                    <option value="admin">Admin</option>
                    <option value="editor">Editor</option>
                    <option value="viewer">Viewer</option>
                  </select>
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
                  Send Invitation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Invitation Link Modal */}
      {newInvitation && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-md">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-navy-50">Invitation Created</h2>
              <p className="text-sm text-navy-400 mt-1">
                Send this link to {newInvitation.email}
              </p>
            </div>
            <div className="card-body">
              <div>
                <label className="label">Invitation Link</label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-sm text-hex-400 font-mono bg-navy-900 p-2 rounded break-all">
                    {newInvitation.invitation_link}
                  </code>
                  <button
                    onClick={() => handleCopy(newInvitation.invitation_link, 'Link')}
                    className="btn btn-ghost p-2"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
                <p className="text-xs text-navy-500 mt-2">
                  This link will expire in 7 days.
                </p>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-navy-700">
              <button
                onClick={() => setNewInvitation(null)}
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
