import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import ScenarioDetail from './pages/ScenarioDetail.jsx'
import History from './pages/History.jsx'
import Detections from './pages/Detections.jsx'
import Architecture from './pages/Architecture.jsx'
import Settings from './pages/Settings.jsx'
import Parsers from './pages/Parsers.jsx'
import ThreatOps from './pages/ThreatOps.jsx'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scenarios/:id" element={<ScenarioDetail />} />
        <Route path="/history" element={<History />} />
        <Route path="/detections" element={<Detections />} />
        <Route path="/architecture" element={<Architecture />} />
        <Route path="/parsers" element={<Parsers />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/threatops" element={<ThreatOps />} />
      </Routes>
    </Layout>
  )
}
