import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Layout }     from './components/Layout'
import { Dashboard }  from './pages/Dashboard'
import { Targets }    from './pages/Targets'
import { ScansList }  from './pages/ScansList'
import { NewScan }    from './pages/NewScan'
import { ScanDetail } from './pages/ScanDetail'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 10_000 },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="targets" element={<Targets />} />
            <Route path="scans">
              <Route index element={<ScansList />} />
              <Route path="new" element={<NewScan />} />
              <Route path=":id" element={<ScanDetail />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}