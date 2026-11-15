import axios from "axios";
import { clearSession, getToken } from "../utils/tokenStorage";

// Central Axios instance for every API call the app makes. Components and
// pages go through the functions exported here so the base URL and request
// shape stay consistent. The base URL comes from VITE_API_BASE_URL and falls
// back to the local backend. Credentials are never stored in the bundle.
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
});

// Attach the logged-in user's token to every request.
apiClient.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// A 401 on a request that carried a token means the session expired or was
// revoked: clear it and send the user to the login page. Login failures and
// anonymous 401s are handled by the calling component.
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const isLoginRequest = error.config?.url?.includes("/api/v1/auth/login");
    const hadToken = Boolean(error.config?.headers?.Authorization);

    if (!isLoginRequest && hadToken && error.response?.status === 401) {
      clearSession();
      if (window.location.pathname !== "/login") {
        window.location.assign("/login");
      }
    }

    return Promise.reject(error);
  }
);

// ---------- SOC platform (existing) ----------

export function getAlerts() {
  return apiClient.get("/api/v1/alerts").then((res) => res.data);
}

export function getAlert(id) {
  return apiClient.get(`/api/v1/alerts/${id}`).then((res) => res.data);
}

export function getIncidents() {
  return apiClient.get("/api/v1/incidents").then((res) => res.data);
}

export function getIncident(id) {
  return apiClient.get(`/api/v1/incidents/${id}`).then((res) => res.data);
}

export function updateAlertStatus(id, payload) {
  return apiClient.patch(`/api/v1/alerts/${id}/status`, payload).then((res) => res.data);
}

export function updateIncidentStatus(id, payload) {
  return apiClient.patch(`/api/v1/incidents/${id}/status`, payload).then((res) => res.data);
}

export function getAuditLogs(params) {
  return apiClient.get("/api/v1/audit-logs", { params }).then((res) => res.data);
}

export function assignAlert(id, username) {
  return apiClient.patch(`/api/v1/alerts/${id}/assignment`, { username }).then((res) => res.data);
}

export function assignIncident(id, username) {
  return apiClient.patch(`/api/v1/incidents/${id}/assignment`, { username }).then((res) => res.data);
}

export function getIncidentNotes(id) {
  return apiClient.get(`/api/v1/incidents/${id}/notes`).then((res) => res.data);
}

export function createIncidentNote(id, content) {
  return apiClient.post(`/api/v1/incidents/${id}/notes`, { content }).then((res) => res.data);
}

export function checkIpReputation(alertId) {
  return apiClient.post(`/api/v1/alerts/${alertId}/reputation`).then((res) => res.data);
}

export function getHealth() {
  return apiClient.get("/health").then((res) => res.data);
}

export function login(username, password) {
  return apiClient.post("/api/v1/auth/login", { username, password }).then((res) => res.data);
}

// ---------- Dashboard, logs, reports ----------

export function getDashboardSummary() {
  return apiClient.get("/api/v1/dashboard/summary").then((res) => res.data);
}

export function searchLogs(params) {
  return apiClient.get("/api/v1/logs/search", { params }).then((res) => res.data);
}

export function getPlatformLimits() {
  return apiClient.get("/api/v1/platform/limits").then((res) => res.data);
}

export function getProviders() {
  return apiClient.get("/api/v1/providers").then((res) => res.data);
}

/** Download a protected report. The bearer token is sent; the file is saved locally. */
export async function downloadReport(path, filename) {
  const res = await apiClient.get(path, { responseType: "blob" });
  const url = URL.createObjectURL(res.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---------- Analysis: submission ----------

export function submitFile(file, onProgress) {
  const form = new FormData();
  form.append("file", file);
  return apiClient
    .post("/api/v1/files", form, {
      onUploadProgress: (event) => {
        if (onProgress && event.total) {
          onProgress(Math.round((event.loaded * 100) / event.total));
        }
      },
    })
    .then((res) => res.data);
}

export function submitUrl(payload) {
  return apiClient.post("/api/v1/urls", payload).then((res) => res.data);
}

export function submitIndicator(query) {
  return apiClient.post("/api/v1/indicators/search", { query }).then((res) => res.data);
}

// ---------- Analysis: history and detail ----------

export function getAnalyses(params) {
  return apiClient.get("/api/v1/analyses", { params }).then((res) => res.data);
}

export function getAnalysis(id) {
  return apiClient.get(`/api/v1/analyses/${id}`).then((res) => res.data);
}

export function deleteAnalysis(id) {
  return apiClient.delete(`/api/v1/analyses/${id}`).then(() => undefined);
}

export function rerunAnalysis(id) {
  return apiClient.post(`/api/v1/analyses/${id}/rerun`).then((res) => res.data);
}

export function getAnalysisPivot(id) {
  return apiClient.get(`/api/v1/analyses/${id}/pivot`).then((res) => res.data);
}

export function getAnalysisNotes(id) {
  return apiClient.get(`/api/v1/analyses/${id}/notes`).then((res) => res.data);
}

export function addAnalysisNote(id, content) {
  return apiClient.post(`/api/v1/analyses/${id}/notes`, { content }).then((res) => res.data);
}

export function getLinkedIncidents(id) {
  return apiClient.get(`/api/v1/analyses/${id}/incidents`).then((res) => res.data);
}

/** Body: { incident_id } to attach, or { create_incident: true, title, severity } to open a new one. */
export function linkAnalysisToIncident(id, body) {
  return apiClient.post(`/api/v1/analyses/${id}/incidents`, body).then((res) => res.data);
}

/** Sends the file or URL to an external service. consent must be true; the caller shows the warning first. */
export function externalSubmission(id, provider) {
  return apiClient
    .post(`/api/v1/analyses/${id}/external-submission`, { provider, consent: true })
    .then((res) => res.data);
}
