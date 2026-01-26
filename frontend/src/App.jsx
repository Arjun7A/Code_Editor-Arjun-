import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { ThemeProvider } from '@/components/theme-provider'
import { StoreProvider } from '@/lib/store.tsx'
import { Toaster } from '@/components/ui/toaster'
import Dashboard from './pages/Dashboard'
import PRDetail from './pages/PRDetail'
import AuditLogs from './pages/AuditLogs'
import Settings from './pages/Settings'
import Submit from './pages/Submit'
import Reports from './pages/Reports'

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
      <StoreProvider>
        <Router>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/pr/:id" element={<PRDetail />} />
            <Route path="/audit-logs" element={<AuditLogs />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/submit" element={<Submit />} />
            <Route path="/reports" element={<Reports />} />
          </Routes>
          <Toaster />
        </Router>
      </StoreProvider>
    </ThemeProvider>
  )
}

export default App

