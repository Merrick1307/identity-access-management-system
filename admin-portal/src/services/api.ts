const API_BASE = '/api/v1'

interface ApiResponse<T = unknown> {
  success: boolean
  data?: T
  message?: string
  error?: string
}

class ApiClient {
  private token: string | null = null
  private tenantId: string | null = null

  setAuth(token: string, tenantId: string) {
    this.token = token
    this.tenantId = tenantId
  }

  clearAuth() {
    this.token = null
    this.tenantId = null
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }
    if (this.tenantId) {
      headers['X-TENANT-ID'] = this.tenantId
    }

    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
      })

      let data: Record<string, unknown> = {}
      const contentType = response.headers.get('content-type')
      if (contentType?.includes('application/json')) {
        const text = await response.text()
        if (text) {
          data = JSON.parse(text)
        }
      }

      if (!response.ok) {
        return {
          success: false,
          error: (data.detail as string) || (data.error as string) || (data.message as string) || `Request failed with status ${response.status}`,
          message: data.message as string,
        }
      }

      return {
        success: true,
        data: data.data || data,
        message: data.message as string,
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Network error',
      }
    }
  }

  // Auth
  async login(email: string, password: string, tenantId: string) {
    this.tenantId = tenantId
    return this.request<{
      token: string
      user_id: string
      email: string
      role: string
      first_name: string
      last_name: string
    }>('/authenticate/token', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })
  }

  // Password Reset (dummy endpoint - to be replaced with real endpoint when ready)
  async requestPasswordReset(email: string, tenantId: string) {
    this.tenantId = tenantId
    return this.request('/auth/password-reset/request', {
      method: 'POST',
      body: JSON.stringify({ email }),
    })
  }

  async resetPassword(token: string, newPassword: string, tenantId: string) {
    this.tenantId = tenantId
    return this.request('/auth/password-reset/confirm', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    })
  }

  // Onboarding
  async onboardTenant(data: {
    tenant: { name: string; domain: string }
    user: { email: string; password: string; first_name: string; last_name: string; role: string }
  }) {
    return this.request('/onboarding/tenant/', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  // Clients
  async getClients() {
    return this.request<Array<{
      client_id: string
      name: string
      redirect_uris: string[]
      scopes: string[]
      is_active: boolean
      created_at: string
      last_modified: string
    }>>('/oidc/clients')
  }

  async createClient(data: { name: string; redirect_uris: string[]; scopes: string[] }) {
    return this.request<{
      client_id: string
      client_secret: string
      name: string
      redirect_uris: string[]
      scopes: string[]
    }>('/oidc/clients', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async updateClient(clientId: string, data: { name?: string; redirect_uris?: string[]; scopes?: string[] }) {
    return this.request(`/oidc/clients/${clientId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    })
  }

  async deleteClient(clientId: string) {
    return this.request(`/oidc/clients/${clientId}`, {
      method: 'DELETE',
    })
  }

  async rotateClientSecret(clientId: string) {
    return this.request<{ client_id: string; client_secret: string }>(`/oidc/clients/${clientId}/rotate-secret`, {
      method: 'POST',
    })
  }

  // Users
  async getUsers(search?: string) {
    const params = search ? `?search=${encodeURIComponent(search)}` : ''
    return this.request<{
      users: Array<{
        id: string
        email: string
        first_name: string
        last_name: string
        full_name: string
        role: string
        is_active: boolean
        created_at: string
      }>
      pagination: {
        page: number
        page_size: number
        total_items: number
        total_pages: number
      }
    }>(`/users/${params}`)
  }

  // Policies
  async getPolicies(userId?: string) {
    const endpoint = userId ? `/policies/user/${userId}` : '/policies/tenant'
    return this.request<Array<{
      policy_id: string
      user_id: string
      user_email?: string
      tenant_id: string
      resource: string
      actions: string[]
      conditions: Record<string, unknown>
      created_at: string
      last_modified: string
    }>>(endpoint)
  }

  async createPolicy(userId: string, data: {
    policy_id: string
    resource: string
    actions: string[]
    conditions?: Record<string, unknown>
  }) {
    return this.request(`/policies/user/${userId}`, {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async updatePolicy(userId: string, policyId: string, data: {
    resource?: string
    actions?: string[]
    conditions?: Record<string, unknown>
  }) {
    return this.request(`/policies/user/${userId}/${policyId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    })
  }

  async deletePolicy(userId: string, policyId: string) {
    return this.request(`/policies/user/${userId}/${policyId}`, {
      method: 'DELETE',
    })
  }

  // Policy Templates (tenant-level reusable policies)
  async getPolicyTemplates() {
    return this.request<Array<{
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
    }>>('/policies/templates')
  }

  async createPolicyTemplate(data: {
    policy_id: string
    resource: string
    actions: string[]
    conditions?: Record<string, unknown>
    roles?: string[]
  }) {
    return this.request('/policies/templates', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async updatePolicyTemplate(templateId: string, data: {
    resource?: string
    actions?: string[]
    conditions?: Record<string, unknown>
    roles?: string[]
  }) {
    return this.request(`/policies/templates/${templateId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    })
  }

  async deletePolicyTemplate(templateId: string) {
    return this.request(`/policies/templates/${templateId}`, {
      method: 'DELETE',
    })
  }

  async assignTemplateToUser(templateId: string, userId: string) {
    return this.request('/policies/templates/assign', {
      method: 'POST',
      body: JSON.stringify({ template_id: templateId, user_id: userId }),
    })
  }

  // Invitations
  async getInvitations() {
    return this.request<Array<{
      id: string
      email: string
      role: string
      invited_by: string
      expires_at: string
      created_at: string
      accepted_at: string | null
    }>>('/oidc/invitations')
  }

  async createInvitation(data: { email: string; role?: string; client_id?: string }) {
    return this.request<{
      invitation_id: string
      email: string
      expires_at: string
      invitation_link: string
    }>('/oidc/invite', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async revokeInvitation(invitationId: string) {
    return this.request(`/oidc/invitations/${invitationId}`, {
      method: 'DELETE',
    })
  }

  // Session Management
  async getAllSessions() {
    return this.request<Array<{
      jti: string
      user_id: string
      user_email?: string
      ip_address: string
      device_info: Record<string, unknown>
      created_at: string
      expires_at: string
      status: string
    }>>('/authenticate/sessions/all')
  }

  async getSessionsByUser(userId: string) {
    return this.request<Array<{
      jti: string
      ip_address: string
      device_info: Record<string, unknown>
      created_at: string
      expires_at: string
      status: string
    }>>(`/authenticate/sessions/user/${userId}`)
  }

  async revokeSession(jti: string) {
    return this.request(`/authenticate/sessions/${jti}`, {
      method: 'DELETE',
    })
  }

  async bulkRevokeSessions(jtis: string[]) {
    return this.request<{ revoked_count: number }>('/authenticate/sessions/bulk-revoke', {
      method: 'POST',
      body: JSON.stringify({ jtis }),
    })
  }

  async revokeUserSessions(userId: string) {
    return this.request<{ revoked_count: number }>(`/authenticate/sessions/user/${userId}/revoke-all`, {
      method: 'POST',
    })
  }

  // User Management
  async activateUser(userId: string) {
    return this.request(`/users/${userId}/activate`, {
      method: 'POST',
    })
  }

  async deactivateUser(userId: string) {
    return this.request(`/users/${userId}/deactivate`, {
      method: 'POST',
    })
  }

  async triggerPasswordReset(userId: string) {
    return this.request(`/users/${userId}/password-reset`, {
      method: 'POST',
    })
  }

  // Tenant Settings
  async get(endpoint: string) {
    return this.request(endpoint)
  }

  async patch(endpoint: string, data: unknown) {
    return this.request(endpoint, {
      method: 'PATCH',
      body: JSON.stringify(data),
    })
  }

  async getTenantSettings() {
    return this.request<{
      mfa: { enabled: boolean; required_for_admins: boolean; methods: string[] }
      tokens: { access_token_ttl: number; refresh_token_ttl: number; id_token_ttl: number }
      password_policy: {
        min_length: number
        require_uppercase: boolean
        require_lowercase: boolean
        require_numbers: boolean
        require_special: boolean
        max_age_days: number
        prevent_reuse_count: number
      }
      session: { max_concurrent_sessions: number; idle_timeout_minutes: number; absolute_timeout_hours: number }
      security: { lockout_threshold: number; lockout_duration_minutes: number; require_email_verification: boolean }
      branding: { logo_url: string | null; primary_color: string; company_name: string | null }
    }>('/tenants/me/settings')
  }

  async updateTenantSettings(data: Record<string, unknown>) {
    return this.request('/tenants/me/settings', {
      method: 'PATCH',
      body: JSON.stringify(data),
    })
  }
}

export const api = new ApiClient()
