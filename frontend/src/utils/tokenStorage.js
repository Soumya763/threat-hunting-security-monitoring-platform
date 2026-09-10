// Plain localStorage-backed token/username storage, kept separate from
// AuthContext.jsx and services/api.js so neither has to import the other
// (services/api.js needs the token for its request interceptor;
// AuthContext.jsx needs services/api.js's login() call - importing this
// tiny module from both avoids a circular import between them).

const TOKEN_KEY = "thp:token";
const USERNAME_KEY = "thp:username";

function safeGet(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeSet(key, value) {
  try {
    if (value === null) {
      localStorage.removeItem(key);
    } else {
      localStorage.setItem(key, value);
    }
  } catch {
    // Ignore - auth still works for the current page load via React state.
  }
}

export function getToken() {
  return safeGet(TOKEN_KEY);
}

export function getUsername() {
  return safeGet(USERNAME_KEY);
}

export function setSession(token, username) {
  safeSet(TOKEN_KEY, token);
  safeSet(USERNAME_KEY, username);
}

export function clearSession() {
  safeSet(TOKEN_KEY, null);
  safeSet(USERNAME_KEY, null);
}
