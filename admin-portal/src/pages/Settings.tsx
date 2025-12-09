import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Shield, Clock, Lock, Palette, Bell, Save, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

interface MFASettings {
  enabled: boolean;
  required_for_admins: boolean;
  methods: string[];
}

interface TokenSettings {
  access_token_ttl: number;
  refresh_token_ttl: number;
  id_token_ttl: number;
}

interface PasswordPolicy {
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_numbers: boolean;
  require_special: boolean;
  max_age_days: number;
  prevent_reuse_count: number;
}

interface SessionSettings {
  max_concurrent_sessions: number;
  idle_timeout_minutes: number;
  absolute_timeout_hours: number;
}

interface SecuritySettings {
  lockout_threshold: number;
  lockout_duration_minutes: number;
  require_email_verification: boolean;
}

interface BrandingSettings {
  logo_url: string | null;
  primary_color: string;
  company_name: string | null;
}

interface TenantSettings {
  mfa: MFASettings;
  tokens: TokenSettings;
  password_policy: PasswordPolicy;
  session: SessionSettings;
  security: SecuritySettings;
  branding: BrandingSettings;
}

export default function Settings() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('mfa');
  const [settings, setSettings] = useState<TenantSettings | null>(null);
  const [hasChanges, setHasChanges] = useState(false);

  const { data, isLoading, error } = useQuery({
    queryKey: ['tenant-settings'],
    queryFn: async () => {
      const response = await api.getTenantSettings();
      if (!response.success) throw new Error(response.error);
      return response.data as TenantSettings;
    },
  });

  useEffect(() => {
    if (data) {
      setSettings(data);
    }
  }, [data]);

  const updateMutation = useMutation({
    mutationFn: async (updates: Partial<TenantSettings>) => {
      const response = await api.updateTenantSettings(updates);
      if (!response.success) throw new Error(response.error);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-settings'] });
      setHasChanges(false);
    },
  });

  const handleSave = () => {
    if (!settings) return;
    
    const updates: Partial<TenantSettings> = {};
    if (activeTab === 'mfa') updates.mfa = settings.mfa;
    if (activeTab === 'tokens') updates.tokens = settings.tokens;
    if (activeTab === 'password') updates.password_policy = settings.password_policy;
    if (activeTab === 'session') updates.session = settings.session;
    if (activeTab === 'security') updates.security = settings.security;
    if (activeTab === 'branding') updates.branding = settings.branding;
    
    updateMutation.mutate(updates);
  };

  const updateSetting = <K extends keyof TenantSettings>(
    category: K,
    field: keyof TenantSettings[K],
    value: any
  ) => {
    if (!settings) return;
    setSettings({
      ...settings,
      [category]: {
        ...settings[category],
        [field]: value,
      },
    });
    setHasChanges(true);
  };

const tabs = [
    { id: 'mfa', label: 'MFA', icon: Shield },
    { id: 'tokens', label: 'Tokens', icon: Clock },
    { id: 'password', label: 'Password Policy', icon: Lock },
    { id: 'session', label: 'Sessions', icon: Bell },
    { id: 'security', label: 'Security', icon: Lock },
    { id: 'branding', label: 'Branding', icon: Palette },
  ];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-blue-500" />
      </div>
    );
  }

  if (error || !settings) {
    return (
      <div className="p-4 bg-red-50 text-red-700 rounded-lg">
        Failed to load settings
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">Tenant Settings</h1>
          <p className="text-gray-400 text-sm mt-1">Configure security, authentication, and tenant-wide policies</p>
        </div>
        <button
          onClick={handleSave}
          disabled={!hasChanges}
          className="inline-flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 font-medium"
        >
          <Save className="h-4 w-4 mr-2" />
          Save Changes
        </button>
      </div>

      <div className="bg-gradient-to-br from-slate-900 to-slate-800 shadow-xl rounded-lg border border-slate-700">
        <div className="border-b border-slate-700 bg-slate-900/50">
          <nav className="flex overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center px-6 py-4 text-sm font-medium whitespace-nowrap border-b-2 transition-all duration-200 ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                    : 'border-transparent text-gray-400 hover:text-gray-300 hover:bg-slate-800/50'
                }`}
              >
                <tab.icon className="h-4 w-4 mr-2" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-8">
          {activeTab === 'mfa' && (
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold text-gray-100 mb-2">Multi-Factor Authentication</h3>
                <p className="text-gray-400 text-sm">Configure MFA requirements and allowed authentication methods</p>
              </div>

              <div className="space-y-6 bg-slate-800/30 rounded-lg p-6 border border-slate-700">
                <label className="flex items-center justify-between p-4 hover:bg-slate-800/50 rounded-lg transition-colors cursor-pointer group">
                  <div>
                    <span className="text-gray-200 font-medium group-hover:text-gray-100">Enable MFA</span>
                    <p className="text-gray-500 text-xs mt-1">Require multi-factor authentication for user accounts</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={settings.mfa.enabled}
                    onChange={(e) => updateSetting('mfa', 'enabled', e.target.checked)}
                    className="h-5 w-5 text-blue-600 rounded accent-blue-600"
                  />
                </label>

                <label className="flex items-center justify-between p-4 hover:bg-slate-800/50 rounded-lg transition-colors cursor-pointer group">
                  <div>
                    <span className="text-gray-200 font-medium group-hover:text-gray-100">Require MFA for Admins</span>
                    <p className="text-gray-500 text-xs mt-1">Enforce MFA for all administrator accounts</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={settings.mfa.required_for_admins}
                    onChange={(e) => updateSetting('mfa', 'required_for_admins', e.target.checked)}
                    className="h-5 w-5 text-blue-600 rounded accent-blue-600"
                  />
                </label>
              </div>

              <div>
                <label className="block text-gray-200 font-medium mb-4">Allowed Authentication Methods</label>
                <div className="grid grid-cols-3 gap-4">
                  {['totp', 'email', 'sms'].map((method) => (
                    <label key={method} className="flex items-center p-4 bg-slate-800/30 border border-slate-700 rounded-lg hover:bg-slate-800/50 hover:border-slate-600 transition-all cursor-pointer group">
                      <input
                        type="checkbox"
                        checked={settings.mfa.methods.includes(method)}
                        onChange={(e) => {
                          const methods = e.target.checked
                            ? [...settings.mfa.methods, method]
                            : settings.mfa.methods.filter((m) => m !== method);
                          updateSetting('mfa', 'methods', methods);
                        }}
                        className="h-5 w-5 text-blue-600 rounded accent-blue-600 mr-3"
                      />
                      <span className="text-gray-300 font-medium group-hover:text-gray-100">{method.toUpperCase()}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'tokens' && (
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold text-gray-100 mb-2">Token Configuration</h3>
                <p className="text-gray-400 text-sm">Set token expiration times for your authentication system</p>
              </div>

              <div className="grid gap-6">
                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Access Token TTL</label>
                  <input
                    type="number"
                    value={settings.tokens.access_token_ttl}
                    onChange={(e) => updateSetting('tokens', 'access_token_ttl', parseInt(e.target.value))}
                    min={300}
                    max={86400}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">5 minutes to 24 hours (300-86400 seconds)</p>
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Refresh Token TTL</label>
                  <input
                    type="number"
                    value={settings.tokens.refresh_token_ttl}
                    onChange={(e) => updateSetting('tokens', 'refresh_token_ttl', parseInt(e.target.value))}
                    min={3600}
                    max={2592000}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">1 hour to 30 days (3600-2592000 seconds)</p>
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">ID Token TTL</label>
                  <input
                    type="number"
                    value={settings.tokens.id_token_ttl}
                    onChange={(e) => updateSetting('tokens', 'id_token_ttl', parseInt(e.target.value))}
                    min={300}
                    max={86400}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>
            </div>
          )}

          {activeTab === 'password' && (
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold text-gray-100 mb-2">Password Policy</h3>
                <p className="text-gray-400 text-sm">Define password complexity and rotation requirements</p>
              </div>

              <div className="grid gap-6">
                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Minimum Password Length</label>
                  <input
                    type="number"
                    value={settings.password_policy.min_length}
                    onChange={(e) => updateSetting('password_policy', 'min_length', parseInt(e.target.value))}
                    min={6}
                    max={128}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-4">Complexity Requirements</label>
                  <div className="grid grid-cols-2 gap-4">
                    <label className="flex items-center p-3 hover:bg-slate-700/30 rounded-lg transition-colors cursor-pointer group">
                      <input
                        type="checkbox"
                        checked={settings.password_policy.require_uppercase}
                        onChange={(e) => updateSetting('password_policy', 'require_uppercase', e.target.checked)}
                        className="h-5 w-5 text-blue-600 rounded accent-blue-600 mr-3"
                      />
                      <span className="text-gray-300 font-medium group-hover:text-gray-100">Uppercase Letters</span>
                    </label>

                    <label className="flex items-center p-3 hover:bg-slate-700/30 rounded-lg transition-colors cursor-pointer group">
                      <input
                        type="checkbox"
                        checked={settings.password_policy.require_lowercase}
                        onChange={(e) => updateSetting('password_policy', 'require_lowercase', e.target.checked)}
                        className="h-5 w-5 text-blue-600 rounded accent-blue-600 mr-3"
                      />
                      <span className="text-gray-300 font-medium group-hover:text-gray-100">Lowercase Letters</span>
                    </label>

                    <label className="flex items-center p-3 hover:bg-slate-700/30 rounded-lg transition-colors cursor-pointer group">
                      <input
                        type="checkbox"
                        checked={settings.password_policy.require_numbers}
                        onChange={(e) => updateSetting('password_policy', 'require_numbers', e.target.checked)}
                        className="h-5 w-5 text-blue-600 rounded accent-blue-600 mr-3"
                      />
                      <span className="text-gray-300 font-medium group-hover:text-gray-100">Numbers</span>
                    </label>

                    <label className="flex items-center p-3 hover:bg-slate-700/30 rounded-lg transition-colors cursor-pointer group">
                      <input
                        type="checkbox"
                        checked={settings.password_policy.require_special}
                        onChange={(e) => updateSetting('password_policy', 'require_special', e.target.checked)}
                        className="h-5 w-5 text-blue-600 rounded accent-blue-600 mr-3"
                      />
                      <span className="text-gray-300 font-medium group-hover:text-gray-100">Special Characters</span>
                    </label>
                  </div>
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Maximum Password Age</label>
                  <input
                    type="number"
                    value={settings.password_policy.max_age_days}
                    onChange={(e) => updateSetting('password_policy', 'max_age_days', parseInt(e.target.value))}
                    min={0}
                    max={365}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">Days before password expiration (0 = never expires)</p>
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Password History</label>
                  <input
                    type="number"
                    value={settings.password_policy.prevent_reuse_count}
                    onChange={(e) => updateSetting('password_policy', 'prevent_reuse_count', parseInt(e.target.value))}
                    min={0}
                    max={24}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">Prevent reuse of previous N passwords</p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'session' && (
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold text-gray-100 mb-2">Session Management</h3>
                <p className="text-gray-400 text-sm">Control session limits and timeout behavior</p>
              </div>

              <div className="grid gap-6">
                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Maximum Concurrent Sessions</label>
                  <input
                    type="number"
                    value={settings.session.max_concurrent_sessions}
                    onChange={(e) => updateSetting('session', 'max_concurrent_sessions', parseInt(e.target.value))}
                    min={1}
                    max={100}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">Number of sessions allowed per user</p>
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Idle Timeout</label>
                  <input
                    type="number"
                    value={settings.session.idle_timeout_minutes}
                    onChange={(e) => updateSetting('session', 'idle_timeout_minutes', parseInt(e.target.value))}
                    min={5}
                    max={1440}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">Minutes of inactivity before session expires</p>
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Absolute Timeout</label>
                  <input
                    type="number"
                    value={settings.session.absolute_timeout_hours}
                    onChange={(e) => updateSetting('session', 'absolute_timeout_hours', parseInt(e.target.value))}
                    min={1}
                    max={168}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">Maximum hours a session can remain active</p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold text-gray-100 mb-2">Security Settings</h3>
                <p className="text-gray-400 text-sm">Configure account lockout and verification requirements</p>
              </div>

              <div className="grid gap-6">
                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Account Lockout Threshold</label>
                  <input
                    type="number"
                    value={settings.security.lockout_threshold}
                    onChange={(e) => updateSetting('security', 'lockout_threshold', parseInt(e.target.value))}
                    min={3}
                    max={20}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">Failed login attempts before account lockout</p>
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Lockout Duration</label>
                  <input
                    type="number"
                    value={settings.security.lockout_duration_minutes}
                    onChange={(e) => updateSetting('security', 'lockout_duration_minutes', parseInt(e.target.value))}
                    min={1}
                    max={1440}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="text-gray-500 text-xs mt-3">Minutes account remains locked</p>
                </div>

                <label className="flex items-center justify-between p-4 bg-slate-800/30 border border-slate-700 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer group">
                  <div>
                    <span className="text-gray-200 font-medium group-hover:text-gray-100">Require Email Verification</span>
                    <p className="text-gray-500 text-xs mt-1">Users must verify email addresses during signup</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={settings.security.require_email_verification}
                    onChange={(e) => updateSetting('security', 'require_email_verification', e.target.checked)}
                    className="h-5 w-5 text-blue-600 rounded accent-blue-600"
                  />
                </label>
              </div>
            </div>
          )}

          {activeTab === 'branding' && (
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold text-gray-100 mb-2">Branding</h3>
                <p className="text-gray-400 text-sm">Customize the appearance of authentication screens</p>
              </div>

              <div className="grid gap-6">
                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Company Name</label>
                  <input
                    type="text"
                    value={settings.branding.company_name || ''}
                    onChange={(e) => updateSetting('branding', 'company_name', e.target.value || null)}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="Your Company Name"
                  />
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-3">Logo URL</label>
                  <input
                    type="url"
                    value={settings.branding.logo_url || ''}
                    onChange={(e) => updateSetting('branding', 'logo_url', e.target.value || null)}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="https://example.com/logo.png"
                  />
                  <p className="text-gray-500 text-xs mt-3">Full URL to your company logo image</p>
                </div>

                <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
                  <label className="block text-gray-200 font-medium mb-4">Primary Color</label>
                  <div className="flex items-center gap-4">
                    <div className="relative">
                      <input
                        type="color"
                        value={settings.branding.primary_color}
                        onChange={(e) => updateSetting('branding', 'primary_color', e.target.value)}
                        className="h-12 w-24 rounded-lg cursor-pointer border-2 border-slate-600 hover:border-slate-500"
                      />
                    </div>
                    <input
                      type="text"
                      value={settings.branding.primary_color}
                      onChange={(e) => updateSetting('branding', 'primary_color', e.target.value)}
                      className="flex-1 px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                      placeholder="#3B82F6"
                    />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex gap-4">
        <div className="flex-1 p-4 bg-green-500/10 text-green-400 rounded-lg border border-green-500/30 hidden">
          ✓ Settings saved successfully!
        </div>
        <div className="flex-1 p-4 bg-red-500/10 text-red-400 rounded-lg border border-red-500/30 hidden">
          Failed to save settings. Please try again.
        </div>
      </div>
    </div>
  );
}
