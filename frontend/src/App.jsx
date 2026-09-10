import { BrowserRouter, Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Header from "./components/Header";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetails from "./pages/AlertDetails";
import Incidents from "./pages/Incidents";
import IncidentDetails from "./pages/IncidentDetails";
import Login from "./pages/Login";
import { AuthProvider } from "./context/AuthContext";
import { HealthProvider } from "./context/HealthContext";

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
                  <Route path="/login" element={<Login />} />
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
