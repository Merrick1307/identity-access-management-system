import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Logo from '../components/Logo'
import { toast } from '../components/ui/Toast'
import { api } from '../services/api'
import { Loader2, ArrowLeft, Mail } from 'lucide-react'

export default function Login() {
  const { login } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [tenantId, setTenantId] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [showForgotPassword, setShowForgotPassword] = useState(false)
  const [resetEmail, setResetEmail] = useState('')
  const [resetTenantId, setResetTenantId] = useState('')
  const [isResetting, setIsResetting] = useState(false)
  const [resetSent, setResetSent] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      await login(email, password, tenantId)
      toast({ title: 'Welcome back!', type: 'success' })
    } catch (error) {
      toast({
        title: 'Login failed',
        description: error instanceof Error ? error.message : 'Invalid credentials',
        type: 'error',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsResetting(true)

    try {
      await api.requestPasswordReset(resetEmail, resetTenantId)
      setResetSent(true)
      toast({ title: 'Reset link sent!', description: 'Check your email for instructions.', type: 'success' })
    } catch (error) {
      toast({
        title: 'Request failed',
        description: error instanceof Error ? error.message : 'Could not send reset email',
        type: 'error',
      })
    } finally {
      setIsResetting(false)
    }
  }

  // Forgot Password View
  if (showForgotPassword) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-navy-950 hex-pattern p-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <Logo className="h-12 justify-center" />
          </div>

          <div className="card">
            <div className="card-header">
              <button
                onClick={() => {
                  setShowForgotPassword(false)
                  setResetSent(false)
                  setResetEmail('')
                  setResetTenantId('')
                }}
                className="flex items-center text-navy-400 hover:text-navy-200 mb-2"
              >
                <ArrowLeft className="w-4 h-4 mr-1" />
                Back to login
              </button>
              <h1 className="text-xl font-semibold text-navy-50">Reset Password</h1>
              <p className="text-sm text-navy-400 mt-1">
                Enter your email and we'll send you a reset link
              </p>
            </div>

            <div className="card-body">
              {resetSent ? (
                <div className="text-center py-4">
                  <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center mx-auto mb-4">
                    <Mail className="w-8 h-8 text-emerald-400" />
                  </div>
                  <h2 className="text-lg font-semibold text-navy-100 mb-2">Check your email</h2>
                  <p className="text-navy-400 text-sm mb-4">
                    We've sent password reset instructions to <br />
                    <span className="text-navy-200">{resetEmail}</span>
                  </p>
                  <button
                    onClick={() => {
                      setShowForgotPassword(false)
                      setResetSent(false)
                    }}
                    className="btn btn-secondary"
                  >
                    Return to login
                  </button>
                </div>
              ) : (
                <form onSubmit={handleForgotPassword} className="space-y-4">
                  <div>
                    <label htmlFor="resetTenantId" className="label">
                      Tenant ID
                    </label>
                    <input
                      id="resetTenantId"
                      type="text"
                      value={resetTenantId}
                      onChange={(e) => setResetTenantId(e.target.value)}
                      className="input"
                      placeholder="your-tenant-id"
                      required
                    />
                  </div>

                  <div>
                    <label htmlFor="resetEmail" className="label">
                      Email Address
                    </label>
                    <input
                      id="resetEmail"
                      type="email"
                      value={resetEmail}
                      onChange={(e) => setResetEmail(e.target.value)}
                      className="input"
                      placeholder="you@example.com"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isResetting}
                    className="btn btn-primary w-full mt-6"
                  >
                    {isResetting ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : (
                      <Mail className="w-4 h-4 mr-2" />
                    )}
                    {isResetting ? 'Sending...' : 'Send Reset Link'}
                  </button>
                </form>
              )}
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-navy-950 hex-pattern p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <Logo className="h-12 justify-center" />
        </div>

        {/* Login Card */}
        <div className="card">
          <div className="card-header">
            <h1 className="text-xl font-semibold text-navy-50">Admin Login</h1>
            <p className="text-sm text-navy-400 mt-1">
              Sign in to manage your identity platform
            </p>
          </div>

          <div className="card-body">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="tenantId" className="label">
                  Tenant ID
                </label>
                <input
                  id="tenantId"
                  type="text"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  className="input"
                  placeholder="your-tenant-id"
                  required
                />
              </div>

              <div>
                <label htmlFor="email" className="label">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input"
                  placeholder="admin@example.com"
                  required
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label htmlFor="password" className="label mb-0">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowForgotPassword(true)}
                    className="text-xs text-hex-400 hover:text-hex-300"
                  >
                    Forgot password?
                  </button>
                </div>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input"
                  placeholder="••••••••"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="btn btn-primary w-full mt-6"
              >
                {isLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin mr-2" />
                ) : null}
                {isLoading ? 'Signing in...' : 'Sign In'}
              </button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-sm text-navy-400">
                Don't have an account?{' '}
                <Link
                  to="/onboarding"
                  className="text-hex-400 hover:text-hex-300 font-medium"
                >
                  Register your organization
                </Link>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
