import axios from "axios";
import { clearSession, getToken } from "../utils/tokenStorage";

// Central Axios instance for every API call the app makes. Components and
// pages should always go through the functions exported here rather than
// calling axios directly, so the base URL and request shape stay
// consistent in one place.
const apiClient = axios.create({
  baseURL: "http://localhost:8000",
});

// Attach the logged-in user's token, when present, to every request.
// Harmless on public GET endpoints; required for the protected
// status-transition and audit-log endpoints.
apiClient.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// If a request that WAS sending a bearer token comes back 401, the token
// itself is what's invalid (expired, tampered, or the user row no longer
// exists) - the server only ever 401s an authenticated request for that
// reason. Clear the stored session immediately so the rest of the app
// (isAuthenticated, derived from the same storage on next read) stops
// appearing logged in with a token that no longer works, then send the
// user back to log in again.
//
// This deliberately does NOT fire for requests sent without a token in
// the first place (e.g. an anonymous viewer hitting a protected
// endpoint) - those 401s are expected and already handled inline by the
// calling page (see AlertDetails/IncidentDetails' audit-trail handling),
// and for the login request itself (a wrong-password 401 there is a
// normal login failure, not a session expiring, and must not redirect
// away from the login form before Login.jsx can show its own error).
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
  return apiClient
    .patch(`/api/v1/alerts/${id}/status`, payload)
    .then((res) => res.data);
}

export function updateIncidentStatus(id, payload) {
  return apiClient
    .patch(`/api/v1/incidents/${id}/status`, payload)
    .then((res) => res.data);
}

export function getAuditLogs(params) {
  return apiClient
    .get("/api/v1/audit-logs", { params })
    .then((res) => res.data);
}

export function assignAlert(id, username) {
  return apiClient
    .patch(`/api/v1/alerts/${id}/assignment`, { username })
    .then((res) => res.data);
}

export function assignIncident(id, username) {
  return apiClient
    .patch(`/api/v1/incidents/${id}/assignment`, { username })
    .then((res) => res.data);
}

export function getIncidentNotes(id) {
  return apiClient
    .get(`/api/v1/incidents/${id}/notes`)
    .then((res) => res.data);
}

export function createIncidentNote(id, content) {
  return apiClient
    .post(`/api/v1/incidents/${id}/notes`, { content })
    .then((res) => res.data);
}

export function checkIpReputation(alertId) {
  return apiClient
    .post(`/api/v1/alerts/${alertId}/reputation`)
    .then((res) => res.data);
}

export function getHealth() {
  return apiClient.get("/health").then((res) => res.data);
}

export function login(username, password) {
  return apiClient
    .post("/api/v1/auth/login", { username, password })
    .then((res) => res.data);
}

export default apiClient;
