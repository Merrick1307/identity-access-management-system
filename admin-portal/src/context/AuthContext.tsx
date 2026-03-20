import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../services/api'

interface User {
  user_id: string
  email: string
  tenant_id: string
  role: string
  first_name?: string
  last_name?: string
}

interface AuthContextType {
  user: User | null
  token: string | null
  tenantId: string | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (email: string, password: string, tenantId: string) => Promise<void>
  logout: () => void
  setTenantId: (id: string) => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [tenantId, setTenantId] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    const storedToken = localStorage.getItem('hex_token')
    const storedUser = localStorage.getItem('hex_user')
    const storedTenantId = localStorage.getItem('hex_tenant_id')

    if (storedToken && storedUser && storedTenantId) {
      setToken(storedToken)
      setUser(JSON.parse(storedUser))
      setTenantId(storedTenantId)
      api.setAuth(storedToken, storedTenantId)
    }
    setIsLoading(false)
  }, [])

  const login = async (email: string, password: string, tid: string) => {
    const response = await api.login(email, password, tid)
    
    if (response.data?.token) {
      // Decode JWT payload to get user info
      const tokenPayload = JSON.parse(atob(response.data.token.split('.')[1]))
      
      const userData: User = {
        user_id: tokenPayload.user_id,
        email: tokenPayload.sub,
        tenant_id: tokenPayload.tenant_id,
        role: tokenPayload.role || 'admin',
      }

      setToken(response.data.token)
      setUser(userData)
      setTenantId(tid)

      localStorage.setItem('hex_token', response.data.token)
      localStorage.setItem('hex_user', JSON.stringify(userData))
      localStorage.setItem('hex_tenant_id', tid)

      api.setAuth(response.data.token, tid)
      navigate('/admin')
    } else {
      throw new Error(response.message || response.error || 'Login failed')
    }
  }

  const logout = () => {
    setToken(null)
    setUser(null)
    setTenantId(null)
    localStorage.removeItem('hex_token')
    localStorage.removeItem('hex_user')
    localStorage.removeItem('hex_tenant_id')
    api.clearAuth()
    navigate('/login')
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        tenantId,
        isAuthenticated: !!token,
        isLoading,
        login,
        logout,
        setTenantId,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
