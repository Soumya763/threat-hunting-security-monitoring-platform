import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { login as loginRequest } from "../services/api";
import { clearSession, getToken, getUsername, setSession } from "../utils/tokenStorage";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => getToken());
  const [username, setUsername] = useState(() => getUsername());

  const login = useCallback((usernameInput, password) => {
    return loginRequest(usernameInput, password).then((data) => {
      setSession(data.access_token, data.username);
      setToken(data.access_token);
      setUsername(data.username);
      return data;
    });
  }, []);

  const logout = useCallback(() => {
    clearSession();
    setToken(null);
    setUsername(null);
  }, []);

  const value = useMemo(
    () => ({
      isAuthenticated: Boolean(token),
      username,
      login,
      logout,
    }),
    [token, username, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
