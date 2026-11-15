import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Header from "./components/Header";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetails from "./pages/AlertDetails";
import Incidents from "./pages/Incidents";
import IncidentDetails from "./pages/IncidentDetails";
import Login from "./pages/Login";
import LogMonitoring from "./pages/LogMonitoring";
import FileAnalysis from "./pages/FileAnalysis";
import UrlAnalysis from "./pages/UrlAnalysis";
import ThreatSearch from "./pages/ThreatSearch";
import AnalysisHistory from "./pages/AnalysisHistory";
import AnalysisDetail from "./pages/AnalysisDetail";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { HealthProvider } from "./context/HealthContext";

// Analysis, reports and settings contain private analyst data, so they need a session.
function RequireAuth({ children }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return children;
}

function App() {
  return (
    <AuthProvider>
      <HealthProvider>
        <BrowserRouter>
          <div className="app-shell">
            <Sidebar />
            <div className="app-main">
              <Header />
              <main className="app-content">
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/alerts" element={<Alerts />} />
                  <Route path="/alerts/:id" element={<AlertDetails />} />
                  <Route path="/incidents" element={<Incidents />} />
                  <Route path="/incidents/:id" element={<IncidentDetails />} />
                  <Route path="/logs" element={<RequireAuth><LogMonitoring /></RequireAuth>} />
                  <Route path="/files" element={<RequireAuth><FileAnalysis /></RequireAuth>} />
                  <Route path="/urls" element={<RequireAuth><UrlAnalysis /></RequireAuth>} />
                  <Route path="/search" element={<RequireAuth><ThreatSearch /></RequireAuth>} />
                  <Route path="/history" element={<RequireAuth><AnalysisHistory /></RequireAuth>} />
                  <Route path="/analysis/:id" element={<RequireAuth><AnalysisDetail /></RequireAuth>} />
                  <Route path="/reports" element={<RequireAuth><Reports /></RequireAuth>} />
                  <Route path="/settings" element={<RequireAuth><Settings /></RequireAuth>} />
                  <Route path="/login" element={<Login />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </main>
            </div>
          </div>
        </BrowserRouter>
      </HealthProvider>
    </AuthProvider>
  );
}

export default App;
