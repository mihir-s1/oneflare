import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Scenarios from './pages/Scenarios.jsx'
import ScenarioDetail from './pages/ScenarioDetail.jsx'
import ThreatOps from './pages/ThreatOps.jsx'
import Architecture from './pages/Architecture.jsx'
import Settings from './pages/Settings.jsx'
import Admin from './pages/Admin.jsx'
import AcceptInvite from './pages/AcceptInvite.jsx'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scenarios" element={<Scenarios />} />
        <Route path="/scenarios/:id" element={<ScenarioDetail />} />
        <Route path="/threatops" element={<ThreatOps />} />
        <Route path="/architecture" element={<Architecture />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/admin" element={<Admin />} />
        <Route path="/admin/accept-invite" element={<AcceptInvite />} />
        {/* Redirects so old bookmarks don't 404 */}
        <Route path="/detections" element={<Navigate to="/architecture" replace />} />
        <Route path="/parsers" element={<Navigate to="/architecture" replace />} />
        <Route path="/history" element={<Navigate to="/settings" replace />} />
      </Routes>
    </Layout>
  )
}
