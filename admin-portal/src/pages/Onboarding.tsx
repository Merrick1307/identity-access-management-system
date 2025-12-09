import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import Logo from '../components/Logo'
import { toast } from '../components/ui/Toast'
import { api } from '../services/api'
import { Loader2, CheckCircle, Building2, User, Mail } from 'lucide-react'

export default function Onboarding() {
  const navigate = useNavigate()
  const [step, setStep] = useState(1)
  const [isLoading, setIsLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const [result, setResult] = useState<{ tenant_id: string; user_id: string } | null>(null)

  // Organization details
  const [orgName, setOrgName] = useState('')
  const [domain, setDomain] = useState('')

  // Admin user details
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (password !== confirmPassword) {
      toast({ title: 'Passwords do not match', type: 'error' })
      return
    }

    if (password.length < 8) {
      toast({ title: 'Password must be at least 8 characters', type: 'error' })
      return
    }

    setIsLoading(true)

    try {
      const response = await api.onboardTenant({
        tenant: {
          name: orgName,
          domain: domain,
        },
        user: {
          email,
          password,
          first_name: firstName,
          last_name: lastName,
          role: 'admin',
        },
      })

      if (response.success && response.data) {
        setResult(response.data as { tenant_id: string; user_id: string })
        setSuccess(true)
        toast({ title: 'Organization registered successfully!', type: 'success' })
      } else {
        toast({
          title: 'Registration failed',
          description: response.error || 'Please try again',
          type: 'error',
        })
      }
    } catch (error) {
      toast({
        title: 'Registration failed',
        description: error instanceof Error ? error.message : 'Network error',
        type: 'error',
      })
    } finally {
      setIsLoading(false)
    }
  }

  if (success && result) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-navy-950 hex-pattern p-4">
        <div className="w-full max-w-md">
          <div className="card text-center">
            <div className="card-body py-8">
              <div className="w-16 h-16 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <CheckCircle className="w-8 h-8 text-emerald-400" />
              </div>
              <h1 className="text-2xl font-semibold text-navy-50 mb-2">
                Welcome to Hexalgon!
              </h1>
              <p className="text-navy-400 mb-6">
                Your organization has been successfully registered.
              </p>

              <div className="bg-navy-900 rounded-lg p-4 mb-6 text-left">
                <p className="text-sm text-navy-400 mb-2">Your Tenant ID:</p>
                <code className="text-hex-400 font-mono text-sm break-all">
                  {result.tenant_id}
                </code>
                <p className="text-xs text-navy-500 mt-2">
                  Save this ID - you'll need it to log in.
                </p>
              </div>

              <button
                onClick={() => navigate('/login')}
                className="btn btn-primary w-full"
              >
                Go to Login
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-navy-950 hex-pattern p-4">
      <div className="w-full max-w-lg">
        {/* Logo */}
        <div className="text-center mb-8">
          <Logo className="h-10 justify-center" />
        </div>

        {/* Onboarding Card */}
        <div className="card">
          <div className="card-header">
            <h1 className="text-xl font-semibold text-navy-50">
              Register Your Organization
            </h1>
            <p className="text-sm text-navy-400 mt-1">
              Set up your identity platform in minutes
            </p>

            {/* Progress */}
            <div className="flex items-center gap-4 mt-4">
              <div className="flex items-center gap-2">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                    step >= 1
                      ? 'bg-hex-600 text-white'
                      : 'bg-navy-700 text-navy-400'
                  }`}
                >
                  1
                </div>
                <span className="text-sm text-navy-300">Organization</span>
              </div>
              <div className="flex-1 h-px bg-navy-700"></div>
              <div className="flex items-center gap-2">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                    step >= 2
                      ? 'bg-hex-600 text-white'
                      : 'bg-navy-700 text-navy-400'
                  }`}
                >
                  2
                </div>
                <span className="text-sm text-navy-300">Admin Account</span>
              </div>
            </div>
          </div>

          <div className="card-body">
            <form onSubmit={handleSubmit}>
              {step === 1 && (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 mb-4 p-3 bg-navy-900 rounded-lg">
                    <Building2 className="w-5 h-5 text-hex-400" />
                    <span className="text-sm text-navy-300">
                      Organization Details
                    </span>
                  </div>

                  <div>
                    <label htmlFor="orgName" className="label">
                      Organization Name
                    </label>
                    <input
                      id="orgName"
                      type="text"
                      value={orgName}
                      onChange={(e) => setOrgName(e.target.value)}
                      className="input"
                      placeholder="Acme Corporation"
                      required
                    />
                  </div>

                  <div>
                    <label htmlFor="domain" className="label">
                      Domain
                    </label>
                    <input
                      id="domain"
                      type="text"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      className="input"
                      placeholder="acme.com"
                      required
                    />
                    <p className="text-xs text-navy-500 mt-1">
                      Your organization's primary domain
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => setStep(2)}
                    disabled={!orgName || !domain}
                    className="btn btn-primary w-full mt-6"
                  >
                    Continue
                  </button>
                </div>
              )}

              {step === 2 && (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 mb-4 p-3 bg-navy-900 rounded-lg">
                    <User className="w-5 h-5 text-hex-400" />
                    <span className="text-sm text-navy-300">
                      Admin Account Setup
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label htmlFor="firstName" className="label">
                        First Name
                      </label>
                      <input
                        id="firstName"
                        type="text"
                        value={firstName}
                        onChange={(e) => setFirstName(e.target.value)}
                        className="input"
                        placeholder="John"
                        required
                      />
                    </div>
                    <div>
                      <label htmlFor="lastName" className="label">
                        Last Name
                      </label>
                      <input
                        id="lastName"
                        type="text"
                        value={lastName}
                        onChange={(e) => setLastName(e.target.value)}
                        className="input"
                        placeholder="Doe"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="email" className="label">
                      <Mail className="w-4 h-4 inline mr-1" />
                      Email Address
                    </label>
                    <input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="input"
                      placeholder="john@acme.com"
                      required
                    />
                  </div>

                  <div>
                    <label htmlFor="password" className="label">
                      Password
                    </label>
                    <input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="input"
                      placeholder="••••••••"
                      required
                      minLength={8}
                    />
                    <p className="text-xs text-navy-500 mt-1">
                      Must be at least 8 characters
                    </p>
                  </div>

                  <div>
                    <label htmlFor="confirmPassword" className="label">
                      Confirm Password
                    </label>
                    <input
                      id="confirmPassword"
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="input"
                      placeholder="••••••••"
                      required
                    />
                  </div>

                  <div className="flex gap-3 mt-6">
                    <button
                      type="button"
                      onClick={() => setStep(1)}
                      className="btn btn-secondary flex-1"
                    >
                      Back
                    </button>
                    <button
                      type="submit"
                      disabled={isLoading}
                      className="btn btn-primary flex-1"
                    >
                      {isLoading ? (
                        <Loader2 className="w-4 h-4 animate-spin mr-2" />
                      ) : null}
                      {isLoading ? 'Creating...' : 'Create Organization'}
                    </button>
                  </div>
                </div>
              )}
            </form>

            <div className="mt-6 text-center">
              <p className="text-sm text-navy-400">
                Already have an account?{' '}
                <Link
                  to="/login"
                  className="text-hex-400 hover:text-hex-300 font-medium"
                >
                  Sign in
                </Link>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
