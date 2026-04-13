import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { AppShell } from './layout/AppShell'
import { DashboardPage } from './pages/Dashboard/DashboardPage'
import { NetworkGraphPage } from './pages/NetworkGraph/NetworkGraphPage'
import { ThreatLogsPage } from './pages/ThreatLogs/ThreatLogsPage.tsx'
import { ExplainableAiPage } from './pages/ExplainableAi/ExplainableAiPage'
import { AiEngineStatusPage } from './pages/AiEngineStatus/AiEngineStatusPage'
import { SystemSettingsPage } from './pages/SystemSettings/SystemSettingsPage.tsx'

function App() {
	return (
		<BrowserRouter>
			<AppShell>
				<Routes>
					<Route path="/" element={<DashboardPage />} />
					<Route path="/network-graph" element={<NetworkGraphPage />} />
					<Route path="/threat-logs" element={<ThreatLogsPage />} />
					<Route path="/xai" element={<ExplainableAiPage />} />
					<Route path="/engine-status" element={<AiEngineStatusPage />} />
					<Route path="/settings" element={<SystemSettingsPage />} />
				</Routes>
			</AppShell>
		</BrowserRouter>
	)
}

export default App
