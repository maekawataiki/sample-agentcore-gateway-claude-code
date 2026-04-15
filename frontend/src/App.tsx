import { useEffect, useState } from "react";
import { Routes, Route, Navigate, useSearchParams } from "react-router-dom";
import { isLoggedIn, login, handleCallback } from "./auth";
import Layout from "./components/Layout";
import Services from "./pages/Services";
import Keys from "./pages/Keys";

export default function App() {
  const [authed, setAuthed] = useState(isLoggedIn());
  const [loading, setLoading] = useState(true);
  const [searchParams] = useSearchParams();

  useEffect(() => {
    (async () => {
      const code = searchParams.get("code");
      if (code && !isLoggedIn()) {
        const ok = await handleCallback(code);
        if (ok) {
          setAuthed(true);
          window.history.replaceState({}, "", window.location.pathname);
        }
      }
      setLoading(false);
    })();
  }, [searchParams]);

  if (loading) return <div className="loading">Loading...</div>;

  if (!authed) {
    return (
      <div className="login-page">
        <div className="login-card">
          <h1>Admin Panel</h1>
          <p>MCP Gateway Control Panel</p>
          <button className="btn btn-primary" onClick={login}>
            Sign in with Cognito
          </button>
        </div>
      </div>
    );
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/services" replace />} />
        <Route path="/services" element={<Services />} />
        <Route path="/services/:name/keys" element={<Keys />} />
      </Routes>
    </Layout>
  );
}
