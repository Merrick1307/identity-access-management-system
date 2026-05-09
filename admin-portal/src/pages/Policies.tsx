import { useEffect, useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../services/api'
import { toast } from '../components/ui/Toast'
import { formatDate } from '../services/utils'
import {
  Plus, Trash2, Edit2, X, Loader2, Shield, ChevronDown,
  Info, Users, FileText, UserPlus, ChevronLeft, ChevronRight
} from 'lucide-react'

interface Policy {
  user_id: string
  policy_id: string
  user_email?: string
  resource: string
  actions: string[]
  conditions?: Record<string, unknown>
  created_at: string
  last_modified?: string
}

interface PolicyTemplate {
  id: string
  tenant_id: string
  policies: {
    policy_id: string
    resource: string
    actions: string[]
    conditions?: Record<string, unknown>
  }
  roles: string[]
  created_at: string
  last_modified?: string
}

interface User {
  id: string
  email: string
  full_name: string
  role: string
}

type TabType = 'user-policies' | 'templates'

interface PaginationMeta {
  page: number
  page_size: number
  total_items: number
  total_pages: number
}

const POLICY_PAGE_SIZE = 20
const TEMPLATE_PAGE_SIZE = 10

export default function Policies() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<TabType>('user-policies')
  const [policyPage, setPolicyPage] = useState(1)
  const [templatePage, setTemplatePage] = useState(1)
  
  // User Policies State
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)
  const [showConditionsFor, setShowConditionsFor] = useState<string | null>(null)
  const [selectedUserId, setSelectedUserId] = useState('')
  const [policyId, setPolicyId] = useState('')
  const [resource, setResource] = useState('')
  const [actions, setActions] = useState('')
  const [conditionsJson, setConditionsJson] = useState('{}')
  const [conditionsError, setConditionsError] = useState('')

  // Template State
  const [showTemplateModal, setShowTemplateModal] = useState(false)
  const [editingTemplate, setEditingTemplate] = useState<PolicyTemplate | null>(null)
  const [templatePolicyId, setTemplatePolicyId] = useState('')
  const [templateResource, setTemplateResource] = useState('')
  const [templateActions, setTemplateActions] = useState('')
  const [templateRoles, setTemplateRoles] = useState('')
  const [templateConditions, setTemplateConditions] = useState('{}')
  const [templateConditionsError, setTemplateConditionsError] = useState('')
  
  // Assign Template State
  const [showAssignModal, setShowAssignModal] = useState(false)
  const [assignTemplateId, setAssignTemplateId] = useState('')
  const [assignUserId, setAssignUserId] = useState('')

  // Fetch users for dropdown
  const { data: usersData } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.getUsers(),
  })

  // Fetch all tenant policies (user-assigned)
  const { data: policiesData, isLoading: policiesLoading } = useQuery({
    queryKey: ['tenant-policies', policyPage],
    queryFn: () => api.getTenantPoliciesPage(policyPage, POLICY_PAGE_SIZE),
  })

  // Fetch policy templates
  const { data: templatesData, isLoading: templatesLoading } = useQuery({
    queryKey: ['policy-templates', templatePage],
    queryFn: () => api.getPolicyTemplatesPage(templatePage, TEMPLATE_PAGE_SIZE),
  })

  const users = useMemo(() => usersData?.data?.users || [], [usersData])
  const policies = useMemo(() => {
    return policiesData?.data?.policies || []
  }, [policiesData])
  const policiesPagination = useMemo<PaginationMeta>(() => {
    return policiesData?.data?.pagination || {
      page: policyPage,
      page_size: POLICY_PAGE_SIZE,
      total_items: 0,
      total_pages: 0,
    }
  }, [policiesData, policyPage])
  const templates = useMemo(() => {
    return templatesData?.data?.templates || []
  }, [templatesData])
  const templatesPagination = useMemo<PaginationMeta>(() => {
    return templatesData?.data?.pagination || {
      page: templatePage,
      page_size: TEMPLATE_PAGE_SIZE,
      total_items: 0,
      total_pages: 0,
    }
  }, [templatesData, templatePage])

  useEffect(() => {
    if (policiesPagination.total_pages > 0 && policyPage > policiesPagination.total_pages) {
      setPolicyPage(policiesPagination.total_pages)
    }
    if (policiesPagination.total_pages === 0 && policyPage > 1) {
      setPolicyPage(1)
    }
  }, [policyPage, policiesPagination.total_pages])

  useEffect(() => {
    if (templatesPagination.total_pages > 0 && templatePage > templatesPagination.total_pages) {
      setTemplatePage(templatesPagination.total_pages)
    }
    if (templatesPagination.total_pages === 0 && templatePage > 1) {
      setTemplatePage(1)
    }
  }, [templatePage, templatesPagination.total_pages])

  // Validate JSON
  const validateConditions = (json: string, setError: (e: string) => void): Record<string, unknown> | null => {
    try {
      if (!json.trim() || json.trim() === '{}') return {}
      const parsed = JSON.parse(json)
      if (typeof parsed !== 'object' || Array.isArray(parsed)) {
        setError('Conditions must be a JSON object')
        return null
      }
      setError('')
      return parsed
    } catch {
      setError('Invalid JSON format')
      return null
    }
  }

  // User Policy Mutations
  const createMutation = useMutation({
    mutationFn: (data: { userId: string; policy_id: string; resource: string; actions: string[]; conditions?: Record<string, unknown> }) =>
      api.createPolicy(data.userId, { policy_id: data.policy_id, resource: data.resource, actions: data.actions, conditions: data.conditions }),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['policies'] })
        queryClient.invalidateQueries({ queryKey: ['tenant-policies'] })
        queryClient.invalidateQueries({ queryKey: ['dashboard-policies-count'] })
        toast({ title: 'Policy created successfully', type: 'success' })
        resetForm()
      } else {
        toast({ title: 'Failed to create policy', description: response.error, type: 'error' })
      }
    },
  })

  const updateMutation = useMutation({
    mutationFn: (data: { userId: string; policyId: string; resource: string; actions: string[]; conditions?: Record<string, unknown> }) =>
      api.updatePolicy(data.userId, data.policyId, { resource: data.resource, actions: data.actions, conditions: data.conditions }),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['policies'] })
        queryClient.invalidateQueries({ queryKey: ['tenant-policies'] })
        queryClient.invalidateQueries({ queryKey: ['dashboard-policies-count'] })
        toast({ title: 'Policy updated successfully', type: 'success' })
        resetForm()
      } else {
        toast({ title: 'Failed to update policy', description: response.error, type: 'error' })
      }
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (data: { userId: string; policyId: string }) => api.deletePolicy(data.userId, data.policyId),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['policies'] })
        queryClient.invalidateQueries({ queryKey: ['tenant-policies'] })
        queryClient.invalidateQueries({ queryKey: ['dashboard-policies-count'] })
        toast({ title: 'Policy deleted', type: 'success' })
      } else {
        toast({ title: 'Failed to delete policy', description: response.error, type: 'error' })
      }
    },
  })

  // Template Mutations
  const createTemplateMutation = useMutation({
    mutationFn: (data: { policy_id: string; resource: string; actions: string[]; conditions?: Record<string, unknown>; roles?: string[] }) =>
      api.createPolicyTemplate(data),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['policy-templates'] })
        toast({ title: 'Template created successfully', type: 'success' })
        resetTemplateForm()
      } else {
        toast({ title: 'Failed to create template', description: response.error, type: 'error' })
      }
    },
  })

  const updateTemplateMutation = useMutation({
    mutationFn: (data: { templateId: string; resource?: string; actions?: string[]; conditions?: Record<string, unknown>; roles?: string[] }) =>
      api.updatePolicyTemplate(data.templateId, { resource: data.resource, actions: data.actions, conditions: data.conditions, roles: data.roles }),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['policy-templates'] })
        toast({ title: 'Template updated successfully', type: 'success' })
        resetTemplateForm()
      } else {
        toast({ title: 'Failed to update template', description: response.error, type: 'error' })
      }
    },
  })

  const deleteTemplateMutation = useMutation({
    mutationFn: (templateId: string) => api.deletePolicyTemplate(templateId),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['policy-templates'] })
        toast({ title: 'Template deleted', type: 'success' })
      } else {
        toast({ title: 'Failed to delete template', description: response.error, type: 'error' })
      }
    },
  })

  const assignTemplateMutation = useMutation({
    mutationFn: (data: { templateId: string; userId: string }) => api.assignTemplateToUser(data.templateId, data.userId),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['policies'] })
        queryClient.invalidateQueries({ queryKey: ['tenant-policies'] })
        queryClient.invalidateQueries({ queryKey: ['dashboard-policies-count'] })
        toast({ title: 'Template assigned to user', type: 'success' })
        setShowAssignModal(false)
        setAssignTemplateId('')
        setAssignUserId('')
      } else {
        toast({ title: 'Failed to assign template', description: response.error, type: 'error' })
      }
    },
  })

  const resetForm = () => {
    setSelectedUserId('')
    setPolicyId('')
    setResource('')
    setActions('')
    setConditionsJson('{}')
    setConditionsError('')
    setShowCreateModal(false)
    setEditingPolicy(null)
  }

  const resetTemplateForm = () => {
    setTemplatePolicyId('')
    setTemplateResource('')
    setTemplateActions('')
    setTemplateRoles('')
    setTemplateConditions('{}')
    setTemplateConditionsError('')
    setShowTemplateModal(false)
    setEditingTemplate(null)
  }

  const handleCreatePolicy = (e: React.FormEvent) => {
    e.preventDefault()
    const conditions = validateConditions(conditionsJson, setConditionsError)
    if (conditions === null) return
    const actionList = actions.split(',').map((a) => a.trim()).filter(Boolean)
    if (actionList.length === 0) {
      toast({ title: 'At least one action is required', type: 'error' })
      return
    }
    createMutation.mutate({ userId: selectedUserId, policy_id: policyId, resource, actions: actionList, conditions })
  }

  const handleUpdatePolicy = (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingPolicy) return
    const conditions = validateConditions(conditionsJson, setConditionsError)
    if (conditions === null) return
    const actionList = actions.split(',').map((a) => a.trim()).filter(Boolean)
    updateMutation.mutate({ userId: editingPolicy.user_id, policyId: editingPolicy.policy_id, resource, actions: actionList, conditions })
  }

  const handleCreateTemplate = (e: React.FormEvent) => {
    e.preventDefault()
    const conditions = validateConditions(templateConditions, setTemplateConditionsError)
    if (conditions === null) return
    const actionList = templateActions.split(',').map((a) => a.trim()).filter(Boolean)
    const roleList = templateRoles.split(',').map((r) => r.trim()).filter(Boolean)
    createTemplateMutation.mutate({ policy_id: templatePolicyId, resource: templateResource, actions: actionList, conditions, roles: roleList })
  }

  const handleUpdateTemplate = (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingTemplate) return
    const conditions = validateConditions(templateConditions, setTemplateConditionsError)
    if (conditions === null) return
    const actionList = templateActions.split(',').map((a) => a.trim()).filter(Boolean)
    const roleList = templateRoles.split(',').map((r) => r.trim()).filter(Boolean)
    updateTemplateMutation.mutate({ templateId: editingTemplate.id, resource: templateResource, actions: actionList, conditions, roles: roleList })
  }

  const openEditPolicy = (policy: Policy) => {
    setEditingPolicy(policy)
    setResource(policy.resource)
    setActions(policy.actions.join(', '))
    setConditionsJson(JSON.stringify(policy.conditions || {}, null, 2))
    setConditionsError('')
  }

  const openEditTemplate = (template: PolicyTemplate) => {
    setEditingTemplate(template)
    setTemplatePolicyId(template.policies.policy_id)
    setTemplateResource(template.policies.resource)
    setTemplateActions(template.policies.actions.join(', '))
    setTemplateRoles(template.roles.join(', '))
    setTemplateConditions(JSON.stringify(template.policies.conditions || {}, null, 2))
    setTemplateConditionsError('')
    setShowTemplateModal(true)
  }

  const openAssignModal = (templateId: string) => {
    setAssignTemplateId(templateId)
    setShowAssignModal(true)
  }

  const getUserDisplay = (userId: string, userEmail?: string) => {
    if (userEmail) return userEmail
    const user = users.find((u: User) => u.id === userId)
    return user ? user.email : userId.substring(0, 12) + '...'
  }

  const hasConditions = (obj: Record<string, unknown> | undefined) => obj && Object.keys(obj).length > 0

  const renderPagination = (
    pagination: PaginationMeta,
    onPrevious: () => void,
    onNext: () => void,
    disablePrevious: boolean,
    disableNext: boolean,
    itemLabel: string
  ) => {
    const start = pagination.total_items === 0 ? 0 : (pagination.page - 1) * pagination.page_size + 1
    const end = pagination.total_items === 0 ? 0 : start + (pagination.page_size > 0 ? Math.min(pagination.page_size, pagination.total_items - start + 1) - 1 : 0)

    return (
      <div className="flex items-center justify-between border-t border-navy-700 px-6 py-4">
        <p className="text-sm text-navy-400">
          Showing {start}-{end} of {pagination.total_items} {itemLabel}
        </p>
        <div className="flex items-center gap-2">
          <button onClick={onPrevious} disabled={disablePrevious} className="btn btn-ghost p-2 disabled:opacity-50">
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="text-sm text-navy-300">
            Page {pagination.page} of {Math.max(pagination.total_pages, 1)}
          </span>
          <button onClick={onNext} disabled={disableNext} className="btn btn-ghost p-2 disabled:opacity-50">
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-navy-50">Access Policies</h1>
          <p className="text-navy-400 mt-1">Manage user access policies and policy templates</p>
        </div>
        <button
          onClick={() => activeTab === 'user-policies' ? setShowCreateModal(true) : setShowTemplateModal(true)}
          className="btn btn-primary"
        >
          <Plus className="w-4 h-4 mr-2" />
          {activeTab === 'user-policies' ? 'Create User Policy' : 'Create Template'}
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-navy-900 p-1 rounded-lg w-fit">
        <button
          onClick={() => setActiveTab('user-policies')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md transition-colors ${
            activeTab === 'user-policies' ? 'bg-hex-500 text-white' : 'text-navy-400 hover:text-navy-200'
          }`}
        >
          <Users className="w-4 h-4" />
          User Policies
        </button>
        <button
          onClick={() => setActiveTab('templates')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md transition-colors ${
            activeTab === 'templates' ? 'bg-hex-500 text-white' : 'text-navy-400 hover:text-navy-200'
          }`}
        >
          <FileText className="w-4 h-4" />
          Policy Templates
        </button>
      </div>

      {/* User Policies Tab */}
      {activeTab === 'user-policies' && (
        <div className="card">
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Policy ID</th>
                  <th>User</th>
                  <th>Resource</th>
                  <th>Actions</th>
                  <th>Conditions</th>
                  <th>Created</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {policiesLoading ? (
                  <tr><td colSpan={7} className="text-center py-8"><Loader2 className="w-6 h-6 animate-spin mx-auto text-hex-400" /></td></tr>
                ) : policies.length === 0 ? (
                  <tr><td colSpan={7} className="text-center py-8 text-navy-400">No user policies created yet</td></tr>
                ) : (
                  policies.map((policy: Policy) => (
                    <tr key={`${policy.user_id}-${policy.policy_id}`}>
                      <td>
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4 text-hex-400" />
                          <span className="font-medium text-navy-100">{policy.policy_id}</span>
                        </div>
                      </td>
                      <td>
                        <div>
                          <p className="text-sm text-navy-100">{getUserDisplay(policy.user_id, policy.user_email)}</p>
                          <p className="text-xs text-navy-500 font-mono">{policy.user_id.substring(0, 8)}...</p>
                        </div>
                      </td>
                      <td><code className="text-sm text-navy-300 bg-navy-900 px-2 py-1 rounded">{policy.resource}</code></td>
                      <td>
                        <div className="flex flex-wrap gap-1">
                          {policy.actions.map((action) => <span key={action} className="badge badge-info">{action}</span>)}
                        </div>
                      </td>
                      <td>
                        {hasConditions(policy.conditions) ? (
                          <div className="relative">
                            <button
                              onClick={() => setShowConditionsFor(showConditionsFor === `${policy.user_id}-${policy.policy_id}` ? null : `${policy.user_id}-${policy.policy_id}`)}
                              className="flex items-center gap-1 text-xs text-hex-400 hover:text-hex-300"
                            >
                              <Info className="w-3 h-3" />View<ChevronDown className="w-3 h-3" />
                            </button>
                            {showConditionsFor === `${policy.user_id}-${policy.policy_id}` && (
                              <div className="absolute z-10 mt-1 left-0 bg-navy-900 border border-navy-700 rounded-lg p-3 min-w-[200px] shadow-lg">
                                <pre className="text-xs text-navy-300 whitespace-pre-wrap">{JSON.stringify(policy.conditions, null, 2)}</pre>
                              </div>
                            )}
                          </div>
                        ) : <span className="text-xs text-navy-500">None</span>}
                      </td>
                      <td className="text-navy-400 text-sm">{formatDate(policy.created_at)}</td>
                      <td>
                        <div className="flex items-center justify-end gap-2">
                          <button onClick={() => openEditPolicy(policy)} className="btn btn-ghost p-2" title="Edit"><Edit2 className="w-4 h-4" /></button>
                          <button
                            onClick={() => { if (confirm('Delete this policy?')) deleteMutation.mutate({ userId: policy.user_id, policyId: policy.policy_id }) }}
                            className="btn btn-ghost p-2 text-red-400 hover:text-red-300" title="Delete"
                          ><Trash2 className="w-4 h-4" /></button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {renderPagination(
            policiesPagination,
            () => setPolicyPage((prev) => Math.max(prev - 1, 1)),
            () => setPolicyPage((prev) => prev + 1),
            policiesLoading || policyPage <= 1,
            policiesLoading || policyPage >= policiesPagination.total_pages,
            'policies'
          )}
        </div>
      )}

      {/* Policy Templates Tab */}
      {activeTab === 'templates' && (
        <div className="card">
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Template ID</th>
                  <th>Policy ID</th>
                  <th>Resource</th>
                  <th>Actions</th>
                  <th>Roles</th>
                  <th>Created</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {templatesLoading ? (
                  <tr><td colSpan={7} className="text-center py-8"><Loader2 className="w-6 h-6 animate-spin mx-auto text-hex-400" /></td></tr>
                ) : templates.length === 0 ? (
                  <tr><td colSpan={7} className="text-center py-8 text-navy-400">No policy templates created yet</td></tr>
                ) : (
                  templates.map((template: PolicyTemplate) => (
                    <tr key={template.id}>
                      <td><span className="font-mono text-xs text-navy-400">{template.id.substring(0, 8)}...</span></td>
                      <td>
                        <div className="flex items-center gap-2">
                          <FileText className="w-4 h-4 text-hex-400" />
                          <span className="font-medium text-navy-100">{template.policies.policy_id}</span>
                        </div>
                      </td>
                      <td><code className="text-sm text-navy-300 bg-navy-900 px-2 py-1 rounded">{template.policies.resource}</code></td>
                      <td>
                        <div className="flex flex-wrap gap-1">
                          {template.policies.actions.map((action) => <span key={action} className="badge badge-info">{action}</span>)}
                        </div>
                      </td>
                      <td>
                        {template.roles.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {template.roles.map((role) => <span key={role} className="badge badge-success">{role}</span>)}
                          </div>
                        ) : <span className="text-xs text-navy-500">Any</span>}
                      </td>
                      <td className="text-navy-400 text-sm">{formatDate(template.created_at)}</td>
                      <td>
                        <div className="flex items-center justify-end gap-2">
                          <button onClick={() => openAssignModal(template.id)} className="btn btn-ghost p-2 text-green-400 hover:text-green-300" title="Assign to User">
                            <UserPlus className="w-4 h-4" />
                          </button>
                          <button onClick={() => openEditTemplate(template)} className="btn btn-ghost p-2" title="Edit"><Edit2 className="w-4 h-4" /></button>
                          <button
                            onClick={() => { if (confirm('Delete this template?')) deleteTemplateMutation.mutate(template.id) }}
                            className="btn btn-ghost p-2 text-red-400 hover:text-red-300" title="Delete"
                          ><Trash2 className="w-4 h-4" /></button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {renderPagination(
            templatesPagination,
            () => setTemplatePage((prev) => Math.max(prev - 1, 1)),
            () => setTemplatePage((prev) => prev + 1),
            templatesLoading || templatePage <= 1,
            templatesLoading || templatePage >= templatesPagination.total_pages,
            'templates'
          )}
        </div>
      )}

      {/* Create User Policy Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-lg">
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-navy-50">Create User Policy</h2>
              <button onClick={resetForm} className="text-navy-400 hover:text-navy-200"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleCreatePolicy}>
              <div className="card-body space-y-4">
                <div>
                  <label className="label">Assign to User</label>
                  <select value={selectedUserId} onChange={(e) => setSelectedUserId(e.target.value)} className="input" required>
                    <option value="">Select a user...</option>
                    {users.map((user: User) => <option key={user.id} value={user.id}>{user.full_name} ({user.email})</option>)}
                  </select>
                </div>
                <div>
                  <label className="label">Policy ID</label>
                  <input type="text" value={policyId} onChange={(e) => setPolicyId(e.target.value.toLowerCase().replace(/\s+/g, '_'))} className="input" placeholder="e.g., documents_read" required />
                </div>
                <div>
                  <label className="label">Resource</label>
                  <input type="text" value={resource} onChange={(e) => setResource(e.target.value)} className="input" placeholder="e.g., documents/*" required />
                </div>
                <div>
                  <label className="label">Actions (comma-separated)</label>
                  <input type="text" value={actions} onChange={(e) => setActions(e.target.value)} className="input" placeholder="read, write, delete" required />
                </div>
                <div>
                  <label className="label">Conditions (JSON)</label>
                  <textarea value={conditionsJson} onChange={(e) => { setConditionsJson(e.target.value); validateConditions(e.target.value, setConditionsError) }} className="input min-h-[80px] font-mono text-sm" placeholder="{}" />
                  {conditionsError && <p className="text-xs text-red-400 mt-1">{conditionsError}</p>}
                </div>
              </div>
              <div className="px-6 py-4 border-t border-navy-700 flex justify-end gap-3">
                <button type="button" onClick={resetForm} className="btn btn-secondary">Cancel</button>
                <button type="submit" disabled={createMutation.isPending || !!conditionsError} className="btn btn-primary">
                  {createMutation.isPending && <Loader2 className="w-4 h-4 animate-spin mr-2" />}Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit User Policy Modal */}
      {editingPolicy && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-lg">
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-navy-50">Edit Policy</h2>
              <button onClick={resetForm} className="text-navy-400 hover:text-navy-200"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleUpdatePolicy}>
              <div className="card-body space-y-4">
                <div className="bg-navy-900 rounded-lg p-3">
                  <p className="text-sm text-navy-100 font-medium">{editingPolicy.policy_id}</p>
                  <p className="text-xs text-navy-400">User: {getUserDisplay(editingPolicy.user_id, editingPolicy.user_email)}</p>
                </div>
                <div>
                  <label className="label">Resource</label>
                  <input type="text" value={resource} onChange={(e) => setResource(e.target.value)} className="input" required />
                </div>
                <div>
                  <label className="label">Actions (comma-separated)</label>
                  <input type="text" value={actions} onChange={(e) => setActions(e.target.value)} className="input" required />
                </div>
                <div>
                  <label className="label">Conditions (JSON)</label>
                  <textarea value={conditionsJson} onChange={(e) => { setConditionsJson(e.target.value); validateConditions(e.target.value, setConditionsError) }} className="input min-h-[80px] font-mono text-sm" />
                  {conditionsError && <p className="text-xs text-red-400 mt-1">{conditionsError}</p>}
                </div>
              </div>
              <div className="px-6 py-4 border-t border-navy-700 flex justify-end gap-3">
                <button type="button" onClick={resetForm} className="btn btn-secondary">Cancel</button>
                <button type="submit" disabled={updateMutation.isPending || !!conditionsError} className="btn btn-primary">
                  {updateMutation.isPending && <Loader2 className="w-4 h-4 animate-spin mr-2" />}Update
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create/Edit Template Modal */}
      {showTemplateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-lg">
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-navy-50">{editingTemplate ? 'Edit Template' : 'Create Policy Template'}</h2>
              <button onClick={resetTemplateForm} className="text-navy-400 hover:text-navy-200"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={editingTemplate ? handleUpdateTemplate : handleCreateTemplate}>
              <div className="card-body space-y-4">
                <div>
                  <label className="label">Policy ID</label>
                  <input type="text" value={templatePolicyId} onChange={(e) => setTemplatePolicyId(e.target.value.toLowerCase().replace(/\s+/g, '_'))} className="input" placeholder="e.g., editor_access" required disabled={!!editingTemplate} />
                  <p className="text-xs text-navy-500 mt-1">Unique identifier for this template</p>
                </div>
                <div>
                  <label className="label">Resource</label>
                  <input type="text" value={templateResource} onChange={(e) => setTemplateResource(e.target.value)} className="input" placeholder="e.g., documents/*" required />
                </div>
                <div>
                  <label className="label">Actions (comma-separated)</label>
                  <input type="text" value={templateActions} onChange={(e) => setTemplateActions(e.target.value)} className="input" placeholder="read, write" required />
                </div>
                <div>
                  <label className="label">Roles (comma-separated, optional)</label>
                  <input type="text" value={templateRoles} onChange={(e) => setTemplateRoles(e.target.value)} className="input" placeholder="admin, editor" />
                  <p className="text-xs text-navy-500 mt-1">Roles this template applies to (leave empty for any role)</p>
                </div>
                <div>
                  <label className="label">Conditions (JSON)</label>
                  <textarea value={templateConditions} onChange={(e) => { setTemplateConditions(e.target.value); validateConditions(e.target.value, setTemplateConditionsError) }} className="input min-h-[80px] font-mono text-sm" placeholder="{}" />
                  {templateConditionsError && <p className="text-xs text-red-400 mt-1">{templateConditionsError}</p>}
                </div>
              </div>
              <div className="px-6 py-4 border-t border-navy-700 flex justify-end gap-3">
                <button type="button" onClick={resetTemplateForm} className="btn btn-secondary">Cancel</button>
                <button type="submit" disabled={(editingTemplate ? updateTemplateMutation.isPending : createTemplateMutation.isPending) || !!templateConditionsError} className="btn btn-primary">
                  {(editingTemplate ? updateTemplateMutation.isPending : createTemplateMutation.isPending) && <Loader2 className="w-4 h-4 animate-spin mr-2" />}
                  {editingTemplate ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Assign Template Modal */}
      {showAssignModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-md">
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-navy-50">Assign Template to User</h2>
              <button onClick={() => { setShowAssignModal(false); setAssignTemplateId(''); setAssignUserId('') }} className="text-navy-400 hover:text-navy-200"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={(e) => { e.preventDefault(); assignTemplateMutation.mutate({ templateId: assignTemplateId, userId: assignUserId }) }}>
              <div className="card-body space-y-4">
                <div>
                  <label className="label">Select User</label>
                  <select value={assignUserId} onChange={(e) => setAssignUserId(e.target.value)} className="input" required>
                    <option value="">Select a user...</option>
                    {users.map((user: User) => <option key={user.id} value={user.id}>{user.full_name} ({user.email})</option>)}
                  </select>
                </div>
              </div>
              <div className="px-6 py-4 border-t border-navy-700 flex justify-end gap-3">
                <button type="button" onClick={() => { setShowAssignModal(false); setAssignTemplateId(''); setAssignUserId('') }} className="btn btn-secondary">Cancel</button>
                <button type="submit" disabled={assignTemplateMutation.isPending || !assignUserId} className="btn btn-primary">
                  {assignTemplateMutation.isPending && <Loader2 className="w-4 h-4 animate-spin mr-2" />}Assign
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
