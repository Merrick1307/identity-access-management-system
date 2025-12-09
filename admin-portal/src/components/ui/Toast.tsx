import { createContext, useContext, useState, useCallback, ReactNode } from 'react'
import { X } from 'lucide-react'

interface Toast {
  id: string
  title: string
  description?: string
  type: 'success' | 'error' | 'info'
}

interface ToastContextType {
  toasts: Toast[]
  addToast: (toast: Omit<Toast, 'id'>) => void
  removeToast: (id: string) => void
}

const ToastContext = createContext<ToastContextType | undefined>(undefined)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).substring(7)
    setToasts((prev) => [...prev, { ...toast, id }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 5000)
  }, [])

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ toasts, addToast, removeToast }}>
      {children}
    </ToastContext.Provider>
  )
}

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context
}

export function Toaster() {
  const [toasts, setToasts] = useState<Toast[]>([])

  // Expose addToast globally
  if (typeof window !== 'undefined') {
    (window as unknown as { __addToast?: (toast: Omit<Toast, 'id'>) => void }).__addToast = (toast) => {
      const id = Math.random().toString(36).substring(7)
      setToasts((prev) => [...prev, { ...toast, id }])
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id))
      }, 5000)
    }
  }

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`
            flex items-start gap-3 p-4 rounded-lg shadow-lg min-w-[300px] max-w-[400px]
            border backdrop-blur-sm animate-in slide-in-from-right
            ${toast.type === 'success' ? 'bg-emerald-900/90 border-emerald-700' : ''}
            ${toast.type === 'error' ? 'bg-red-900/90 border-red-700' : ''}
            ${toast.type === 'info' ? 'bg-hex-900/90 border-hex-700' : ''}
          `}
        >
          <div className="flex-1">
            <p className="font-medium text-white">{toast.title}</p>
            {toast.description && (
              <p className="text-sm text-navy-200 mt-1">{toast.description}</p>
            )}
          </div>
          <button
            onClick={() => removeToast(toast.id)}
            className="text-navy-300 hover:text-white"
          >
            <X size={16} />
          </button>
        </div>
      ))}
    </div>
  )
}

export function toast(options: Omit<Toast, 'id'>) {
  const addToast = (window as unknown as { __addToast?: (toast: Omit<Toast, 'id'>) => void }).__addToast
  if (addToast) {
    addToast(options)
  }
}
