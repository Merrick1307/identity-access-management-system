import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  RefreshCw,
  Trash2,
  Pencil,
  Link2,
  ShieldCheck,
  Network,
  X,
  Loader2,
  ExternalLink,
  ChevronRight,
} from 'lucide-react'
import { api } from '../services/api'
import { toast } from '../components/ui/Toast'
import { formatDate } from '../services/utils'

interface IdentityProvider {
  id: string
  tenant_id: string
  name: string
  protocol: string
  issuer_url: string
  client_id?: string | null
  discovery_url?: string | null
  authorization_endpoint?: string | null
  token_endpoint?: string | null
  userinfo_endpoint?: string | null
  jwks_uri?: string | null
  enabled: boolean
  auto_link: boolean
  authorization_scopes: string
  token_endpoint_auth_method: string
  claims_source: string
  link_by_email_verified_only: boolean
  default_role: string
  created_at?: string | null
  last_modified?: string | null
}

interface ProviderFormState {
  name: string
  protocol: 'oidc' | 'saml'
  issuer_url: string
  client_id: string
  client_secret: string
  discovery_url: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
  authorization_scopes: string
  token_endpoint_auth_method: string
  claims_source: string
  default_role: string
  enabled: boolean
  auto_link: boolean
  link_by_email_verified_only: boolean
}

const EMPTY_FORM: ProviderFormState = {
  name: '',
  protocol: 'oidc',
  issuer_url: '',
  client_id: '',
  client_secret: '',
  discovery_url: '',
  authorization_endpoint: '',
  token_endpoint: '',
  userinfo_endpoint: '',
  jwks_uri: '',
  authorization_scopes: 'openid profile email',
  token_endpoint_auth_method: 'client_secret_post',
  claims_source: 'auto',
  default_role: 'member',
  enabled: true,
  auto_link: true,
  link_by_email_verified_only: true,
}

function normalizeProviderToForm(provider: IdentityProvider): ProviderFormState {
  return {
    name: provider.name || '',
    protocol: (provider.protocol as 'oidc' | 'saml') || 'oidc',
    issuer_url: provider.issuer_url || '',
    client_id: provider.client_id || '',
    client_secret: '',
    discovery_url: provider.discovery_url || '',
    authorization_endpoint: provider.authorization_endpoint || '',
    token_endpoint: provider.token_endpoint || '',
    userinfo_endpoint: provider.userinfo_endpoint || '',
    jwks_uri: provider.jwks_uri || '',
    authorization_scopes: provider.authorization_scopes || 'openid profile email',
    token_endpoint_auth_method: provider.token_endpoint_auth_method || 'client_secret_post',
    claims_source: provider.claims_source || 'auto',
    default_role: provider.default_role || 'member',
    enabled: provider.enabled,
    auto_link: provider.auto_link,
    link_by_email_verified_only: provider.link_by_email_verified_only,
  }
}

export default function Federation() {
  const queryClient = useQueryClient()
  const [showProviderModal, setShowProviderModal] = useState(false)
  const [editingProvider, setEditingProvider] = useState<IdentityProvider | null>(null)
  const [selectedProvider, setSelectedProvider] = useState<IdentityProvider | null>(null)
  const [form, setForm] = useState<ProviderFormState>(EMPTY_FORM)

  const { data: providersResponse, isLoading, isFetching } = useQuery({
    queryKey: ['federation-providers'],
    queryFn: () => api.getIdentityProviders(),
  })

  const providers = providersResponse?.data || []

  const { data: linksResponse, isLoading: linksLoading } = useQuery({
    queryKey: ['federation-links', selectedProvider?.id],
    enabled: Boolean(selectedProvider?.id),
    queryFn: () => api.getFederatedLinks(selectedProvider!.id),
  })

  const links = linksResponse?.data || []

  useEffect(() => {
    if (!showProviderModal) {
      setEditingProvider(null)
      setForm(EMPTY_FORM)
    }
  }, [showProviderModal])

  const createMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.createIdentityProvider(payload),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['federation-providers'] })
        setShowProviderModal(false)
        toast({ title: 'Identity provider created', type: 'success' })
      } else {
        toast({ title: 'Failed to create provider', description: response.error, type: 'error' })
      }
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ providerId, payload }: { providerId: string; payload: Record<string, unknown> }) =>
      api.updateIdentityProvider(providerId, payload),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['federation-providers'] })
        if (selectedProvider?.id === editingProvider?.id && response.data) {
          setSelectedProvider(response.data as IdentityProvider)
        }
        setShowProviderModal(false)
        toast({ title: 'Identity provider updated', type: 'success' })
      } else {
        toast({ title: 'Failed to update provider', description: response.error, type: 'error' })
      }
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (providerId: string) => api.deleteIdentityProvider(providerId),
    onSuccess: (response, providerId) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ['federation-providers'] })
        if (selectedProvider?.id === providerId) {
          setSelectedProvider(null)
        }
        toast({ title: 'Identity provider removed', type: 'success' })
      } else {
        toast({ title: 'Failed to remove provider', description: response.error, type: 'error' })
      }
    },
  })

  const providerStats = useMemo(() => {
    const enabled = providers.filter((provider) => provider.enabled).length
    const autoLinked = providers.filter((provider) => provider.auto_link).length
    return {
      total: providers.length,
      enabled,
      autoLinked,
      strict: providers.filter((provider) => !provider.auto_link || provider.link_by_email_verified_only).length,
    }
  }, [providers])

  const openCreateModal = () => {
    setEditingProvider(null)
    setForm(EMPTY_FORM)
    setShowProviderModal(true)
  }

  const openEditModal = (provider: IdentityProvider) => {
    setEditingProvider(provider)
    setForm(normalizeProviderToForm(provider))
    setShowProviderModal(true)
  }

  const updateForm = <K extends keyof ProviderFormState>(field: K, value: ProviderFormState[K]) => {
    setForm((current) => ({ ...current, [field]: value }))
  }

  const buildPayload = (): Record<string, unknown> => {
    const payload: Record<string, unknown> = {
      name: form.name.trim(),
      protocol: form.protocol,
      issuer_url: form.issuer_url.trim(),
      client_id: form.client_id.trim() || undefined,
      discovery_url: form.discovery_url.trim() || undefined,
      authorization_endpoint: form.authorization_endpoint.trim() || undefined,
      token_endpoint: form.token_endpoint.trim() || undefined,
      userinfo_endpoint: form.userinfo_endpoint.trim() || undefined,
      jwks_uri: form.jwks_uri.trim() || undefined,
      authorization_scopes: form.authorization_scopes.trim() || 'openid profile email',
      token_endpoint_auth_method: form.token_endpoint_auth_method,
      claims_source: form.claims_source,
      default_role: form.default_role.trim() || 'member',
      enabled: form.enabled,
      auto_link: form.auto_link,
      link_by_email_verified_only: form.link_by_email_verified_only,
    }

    if (form.client_secret.trim()) {
      payload.client_secret = form.client_secret.trim()
    }

    return payload
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!form.name.trim() || !form.issuer_url.trim()) {
      toast({ title: 'Name and issuer URL are required', type: 'error' })
      return
    }

    const payload = buildPayload()

    if (editingProvider) {
      updateMutation.mutate({ providerId: editingProvider.id, payload })
    } else {
      createMutation.mutate(payload)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-navy-50">Federation</h1>
          <p className="text-navy-400 mt-1 max-w-3xl">
            Configure upstream identity providers for tenant login, manage automatic account linking,
            and inspect federated identities attached to your local IAM users.
          </p>
        </div>
        <button onClick={openCreateModal} className="btn btn-primary shrink-0">
          <Plus className="w-4 h-4 mr-2" />
          Add Provider
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard label="Configured providers" value={providerStats.total} icon={Network} />
        <StatCard label="Enabled providers" value={providerStats.enabled} icon={ShieldCheck} accent="success" />
        <StatCard label="Auto-link enabled" value={providerStats.autoLinked} icon={Link2} accent="info" />
        <StatCard label="Strict link policy" value={providerStats.strict} icon={ChevronRight} accent="warning" />
      </div>

      <div className="card">
        <div className="card-header flex items-center justify-between">
          <div>
            <h2 className="text-lg font-medium text-navy-100">Identity Providers</h2>
            <p className="text-sm text-navy-400 mt-1">
              Downstream apps still integrate with HEX IAM; provider choice only changes where authentication originates.
            </p>
          </div>
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['federation-providers'] })}
            className="btn btn-secondary"
            disabled={isFetching}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Issuer</th>
                <th>Scopes</th>
                <th>Linking</th>
                <th>Default role</th>
                <th>Status</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="text-center py-10">
                    <Loader2 className="w-6 h-6 animate-spin mx-auto text-hex-400" />
                  </td>
                </tr>
              ) : providers.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12">
                    <div className="flex flex-col items-center gap-3 text-navy-400">
                      <Network className="w-10 h-10 text-navy-500" />
                      <div>
                        <p className="text-navy-200 font-medium">No providers configured yet</p>
                        <p className="text-sm">Add Hexalgon SSO, Okta, Google Workspace, or another OIDC provider.</p>
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                providers.map((provider) => (
                  <tr key={provider.id}>
                    <td>
                      <div>
                        <div className="font-medium text-navy-100 flex items-center gap-2">
                          {provider.name}
                          <span className="badge badge-info uppercase">{provider.protocol}</span>
                        </div>
                        <div className="text-xs text-navy-400 mt-1">
                          Auth method: {provider.token_endpoint_auth_method}
                        </div>
                      </div>
                    </td>
                    <td>
                      <div className="max-w-[260px]">
                        <p className="text-sm text-navy-200 truncate" title={provider.issuer_url}>
                          {provider.issuer_url}
                        </p>
                        {provider.discovery_url && (
                          <a
                            href={provider.discovery_url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-xs text-hex-400 hover:text-hex-300 mt-1"
                          >
                            Discovery
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1 max-w-[220px]">
                        {provider.authorization_scopes.split(' ').filter(Boolean).map((scope) => (
                          <span key={scope} className="badge badge-info">
                            {scope}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <div className="space-y-1 text-sm">
                        <div className={provider.auto_link ? 'text-emerald-400' : 'text-amber-400'}>
                          {provider.auto_link ? 'Automatic link/provision' : 'Manual linking only'}
                        </div>
                        <div className="text-xs text-navy-400">
                          {provider.link_by_email_verified_only ? 'Verified email required' : 'Email verification not enforced'}
                        </div>
                      </div>
                    </td>
                    <td className="text-navy-300">{provider.default_role}</td>
                    <td>
                      <span className={`badge ${provider.enabled ? 'badge-success' : 'badge-danger'}`}>
                        {provider.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          className="btn btn-ghost p-2"
                          title="View linked identities"
                          onClick={() => setSelectedProvider(provider)}
                        >
                          <Link2 className="w-4 h-4" />
                        </button>
                        <button
                          className="btn btn-ghost p-2"
                          title="Edit provider"
                          onClick={() => openEditModal(provider)}
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          className="btn btn-ghost p-2 text-red-400 hover:text-red-300"
                          title="Delete provider"
                          onClick={() => {
                            if (confirm(`Remove provider \"${provider.name}\"?`)) {
                              deleteMutation.mutate(provider.id)
                            }
                          }}
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

      {showProviderModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-hex-lg">
            <div className="card-header flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-navy-50">
                  {editingProvider ? 'Edit Identity Provider' : 'Add Identity Provider'}
                </h3>
                <p className="text-sm text-navy-400 mt-1">
                  Configure the upstream OIDC broker that HEX IAM should use for this tenant.
                </p>
              </div>
              <button className="btn btn-ghost p-2" onClick={() => setShowProviderModal(false)}>
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="card-body space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Field label="Provider name" required>
                  <input className="input" value={form.name} onChange={(e) => updateForm('name', e.target.value)} placeholder="Okta Workforce" />
                </Field>
                <Field label="Protocol">
                  <select className="input" value={form.protocol} onChange={(e) => updateForm('protocol', e.target.value as 'oidc' | 'saml')}>
                    <option value="oidc">OIDC</option>
                    <option value="saml">SAML</option>
                  </select>
                </Field>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Field label="Issuer URL" required>
                  <input className="input" value={form.issuer_url} onChange={(e) => updateForm('issuer_url', e.target.value)} placeholder="https://example.okta.com/oauth2/default" />
                </Field>
                <Field label="Discovery URL">
                  <input className="input" value={form.discovery_url} onChange={(e) => updateForm('discovery_url', e.target.value)} placeholder="https://.../.well-known/openid-configuration" />
                </Field>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Field label="Client ID">
                  <input className="input" value={form.client_id} onChange={(e) => updateForm('client_id', e.target.value)} placeholder="oidc-client-id" />
                </Field>
                <Field label="Client Secret">
                  <input className="input" type="password" value={form.client_secret} onChange={(e) => updateForm('client_secret', e.target.value)} placeholder={editingProvider ? 'Leave blank to keep current secret' : 'Enter client secret'} />
                </Field>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Field label="Authorization endpoint">
                  <input className="input" value={form.authorization_endpoint} onChange={(e) => updateForm('authorization_endpoint', e.target.value)} placeholder="https://.../authorize" />
                </Field>
                <Field label="Token endpoint">
                  <input className="input" value={form.token_endpoint} onChange={(e) => updateForm('token_endpoint', e.target.value)} placeholder="https://.../token" />
                </Field>
                <Field label="Userinfo / JWKS URI">
                  <input className="input" value={form.userinfo_endpoint} onChange={(e) => updateForm('userinfo_endpoint', e.target.value)} placeholder="https://.../userinfo" />
                </Field>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Field label="JWKS URI">
                  <input className="input" value={form.jwks_uri} onChange={(e) => updateForm('jwks_uri', e.target.value)} placeholder="https://.../keys" />
                </Field>
                <Field label="Authorization scopes">
                  <input className="input" value={form.authorization_scopes} onChange={(e) => updateForm('authorization_scopes', e.target.value)} placeholder="openid profile email" />
                </Field>
                <Field label="Default local role">
                  <input className="input" value={form.default_role} onChange={(e) => updateForm('default_role', e.target.value)} placeholder="member" />
                </Field>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Field label="Token endpoint auth method">
                  <select className="input" value={form.token_endpoint_auth_method} onChange={(e) => updateForm('token_endpoint_auth_method', e.target.value)}>
                    <option value="client_secret_post">client_secret_post</option>
                    <option value="client_secret_basic">client_secret_basic</option>
                  </select>
                </Field>
                <Field label="Claims source">
                  <select className="input" value={form.claims_source} onChange={(e) => updateForm('claims_source', e.target.value)}>
                    <option value="auto">auto</option>
                    <option value="id_token">id_token</option>
                    <option value="userinfo">userinfo</option>
                  </select>
                </Field>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <ToggleCard
                  title="Enabled"
                  description="Allow this provider in the upstream login flow for this tenant."
                  checked={form.enabled}
                  onChange={(checked) => updateForm('enabled', checked)}
                />
                <ToggleCard
                  title="Auto-link users"
                  description="Let IAM link or provision local users when no explicit federated link exists yet."
                  checked={form.auto_link}
                  onChange={(checked) => updateForm('auto_link', checked)}
                />
                <ToggleCard
                  title="Verified email only"
                  description="Require verified email before email-based linking is allowed."
                  checked={form.link_by_email_verified_only}
                  onChange={(checked) => updateForm('link_by_email_verified_only', checked)}
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button type="button" className="btn btn-secondary" onClick={() => setShowProviderModal(false)}>
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={createMutation.isPending || updateMutation.isPending}
                >
                  {(createMutation.isPending || updateMutation.isPending) && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                  {editingProvider ? 'Save Provider' : 'Create Provider'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {selectedProvider && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex justify-end z-50">
          <div className="w-full max-w-2xl h-full bg-navy-900 border-l border-navy-800 shadow-2xl overflow-y-auto">
            <div className="px-6 py-5 border-b border-navy-800 flex items-start justify-between">
              <div>
                <h3 className="text-lg font-semibold text-navy-50">Linked identities</h3>
                <p className="text-sm text-navy-400 mt-1">
                  {selectedProvider.name} • {selectedProvider.issuer_url}
                </p>
              </div>
              <button className="btn btn-ghost p-2" onClick={() => setSelectedProvider(null)}>
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="card p-4">
                <div className="flex flex-wrap gap-2">
                  <span className={`badge ${selectedProvider.enabled ? 'badge-success' : 'badge-danger'}`}>
                    {selectedProvider.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                  <span className="badge badge-info">{selectedProvider.authorization_scopes}</span>
                  <span className="badge badge-info">claims: {selectedProvider.claims_source}</span>
                </div>
              </div>

              <div className="card">
                <div className="card-header flex items-center justify-between">
                  <div>
                    <h4 className="text-base font-medium text-navy-100">Federated identity links</h4>
                    <p className="text-sm text-navy-400 mt-1">Each record maps one external subject to a tenant-local IAM user.</p>
                  </div>
                </div>
                <div className="card-body p-0">
                  <div className="table-container rounded-none border-0">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>User ID</th>
                          <th>External subject</th>
                          <th>Email</th>
                          <th>Linked</th>
                        </tr>
                      </thead>
                      <tbody>
                        {linksLoading ? (
                          <tr>
                            <td colSpan={4} className="text-center py-8">
                              <Loader2 className="w-6 h-6 animate-spin mx-auto text-hex-400" />
                            </td>
                          </tr>
                        ) : links.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="text-center py-8 text-navy-400">
                              No linked identities for this provider yet
                            </td>
                          </tr>
                        ) : (
                          links.map((link) => (
                            <tr key={`${link.user_id}-${link.external_subject}`}>
                              <td className="font-mono text-xs text-navy-200">{link.user_id}</td>
                              <td className="font-mono text-xs text-navy-300">{link.external_subject}</td>
                              <td className="text-navy-300">{link.external_email || '—'}</td>
                              <td className="text-navy-400 text-sm">{link.created_at ? formatDate(link.created_at) : '—'}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Field({
  label,
  children,
  required = false,
}: {
  label: string
  children: React.ReactNode
  required?: boolean
}) {
  return (
    <label className="block">
      <span className="label flex items-center gap-1">
        {label}
        {required && <span className="text-red-400">*</span>}
      </span>
      {children}
    </label>
  )
}

function ToggleCard({
  title,
  description,
  checked,
  onChange,
}: {
  title: string
  description: string
  checked: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <label className="card card-body p-4 cursor-pointer hover:border-hex-700/50 transition-colors block">
      <div className="flex items-start gap-3">
        <input
          type="checkbox"
          className="mt-1 h-4 w-4 rounded border-navy-600 bg-navy-800 text-hex-500 accent-hex-500"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
        />
        <div>
          <div className="text-sm font-medium text-navy-100">{title}</div>
          <div className="text-xs text-navy-400 mt-1 leading-5">{description}</div>
        </div>
      </div>
    </label>
  )
}

function StatCard({
  label,
  value,
  icon: Icon,
  accent = 'default',
}: {
  label: string
  value: number
  icon: React.ComponentType<{ className?: string }>
  accent?: 'default' | 'success' | 'info' | 'warning'
}) {
  const accentMap = {
    default: 'text-hex-400 bg-hex-600/10',
    success: 'text-emerald-400 bg-emerald-500/10',
    info: 'text-sky-400 bg-sky-500/10',
    warning: 'text-amber-400 bg-amber-500/10',
  }

  return (
    <div className="card">
      <div className="card-body flex items-center justify-between">
        <div>
          <p className="text-sm text-navy-400">{label}</p>
          <p className="text-2xl font-semibold text-navy-50 mt-1">{value}</p>
        </div>
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${accentMap[accent]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  )
}
