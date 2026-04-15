import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Mapping } from "../api";

type IdentityType = "email" | "group" | "default";

const IDENTITY_OPTIONS: { value: IdentityType; label: string; hint: string }[] = [
  { value: "email", label: "メールアドレス", hint: "特定ユーザーに割り当て (最優先)" },
  { value: "group", label: "グループ", hint: "Cognito グループ単位で割り当て" },
  { value: "default", label: "デフォルト (全員)", hint: "他にマッチしない全ユーザー向け" },
];

interface FormState {
  identityType: IdentityType;
  identityValue: string;
  apiKey: string;
  headerName: string;
  description: string;
}

const emptyForm: FormState = {
  identityType: "email",
  identityValue: "",
  apiKey: "",
  headerName: "Authorization",
  description: "",
};

function toClaim(identityType: IdentityType, identityValue: string): { claimKey: string; claimValue: string } {
  if (identityType === "email") return { claimKey: "email", claimValue: identityValue };
  if (identityType === "group") return { claimKey: "cognito:groups", claimValue: identityValue };
  return { claimKey: "*", claimValue: "*" };
}

function fromClaim(claimKey: string, claimValue: string): { label: string; type: IdentityType } {
  if (claimKey === "email") return { label: `✉ ${claimValue}`, type: "email" };
  if (claimKey === "cognito:groups") return { label: `👥 ${claimValue}`, type: "group" };
  if (claimKey === "*") return { label: "🌐 デフォルト (全員)", type: "default" };
  return { label: `${claimKey}=${claimValue}`, type: "default" };
}

export default function Keys() {
  const { name = "" } = useParams();
  const [mappings, setMappings] = useState<Mapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>({ ...emptyForm });

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await api.listMappings(name);
      setMappings(data.mappings);
    } catch (e) {
      setError((e as Error).message);
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, [name]);

  const handleSave = async () => {
    if (!form.apiKey) {
      setError("API Key is required");
      return;
    }
    if (form.identityType !== "default" && !form.identityValue) {
      setError("Identity value is required");
      return;
    }
    const { claimKey, claimValue } = toClaim(form.identityType, form.identityValue);
    try {
      await api.putMapping(name, {
        claimKey,
        claimValue,
        apiKey: form.apiKey,
        headerName: form.headerName,
        description: form.description,
      });
      setForm({ ...emptyForm });
      setShowForm(false);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const handleDelete = async (claimKey: string, claimValue: string) => {
    const { label } = fromClaim(claimKey, claimValue);
    if (!confirm(`Delete API key for ${label}?`)) return;
    try {
      await api.deleteMapping(name, claimKey, claimValue);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setForm({ ...form, [k]: v });

  return (
    <div>
      <div className="page-header">
        <div>
          <Link to="/services">← Services</Link>
          <h1>API Keys — {name}</h1>
        </div>
        <button className="btn btn-primary" onClick={() => setShowForm(true)}>+ Register API Key</button>
      </div>

      <p className="muted">
        優先順位: <strong>メールアドレス</strong> &gt; <strong>グループ</strong> &gt; <strong>デフォルト</strong>
      </p>

      {error && <div className="alert alert-error">{error}</div>}

      {showForm && (
        <div className="card form-card">
          <h3>Register API Key</h3>

          <div className="form-group">
            <label>対象 (Identity)</label>
            <div className="radio-group">
              {IDENTITY_OPTIONS.map((opt) => (
                <label key={opt.value} className="radio-option">
                  <input
                    type="radio"
                    name="identityType"
                    value={opt.value}
                    checked={form.identityType === opt.value}
                    onChange={() => set("identityType", opt.value)}
                  />
                  <span><strong>{opt.label}</strong> <span className="muted">— {opt.hint}</span></span>
                </label>
              ))}
            </div>
          </div>

          <div className="form-group">
            <label>{form.identityType === "email" ? "メールアドレス" : form.identityType === "group" ? "グループ名" : "対象"}</label>
            <input
              value={form.identityType === "default" ? "(全員)" : form.identityValue}
              onChange={(e) => set("identityValue", e.target.value)}
              placeholder={form.identityType === "email" ? "alice@example.com" : form.identityType === "group" ? "admins" : ""}
              disabled={form.identityType === "default"}
            />
          </div>

          <div className="form-group">
            <label>API Key</label>
            <input
              type="password"
              value={form.apiKey}
              onChange={(e) => set("apiKey", e.target.value)}
              placeholder="Key abc123..."
            />
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>Header Name</label>
              <input value={form.headerName} onChange={(e) => set("headerName", e.target.value)} />
            </div>
            <div className="form-group">
              <label>Description</label>
              <input value={form.description} onChange={(e) => set("description", e.target.value)} placeholder="optional" />
            </div>
          </div>

          <div className="form-actions">
            <button className="btn btn-primary" onClick={handleSave}>Save</button>
            <button className="btn btn-secondary" onClick={() => { setShowForm(false); setForm({ ...emptyForm }); }}>Cancel</button>
          </div>
        </div>
      )}

      {loading ? <p>Loading...</p> : mappings.length === 0 ? (
        <p className="muted">No API keys registered yet.</p>
      ) : (
        <table>
          <thead>
            <tr><th>Identity</th><th>Header</th><th>Description</th><th>Updated</th><th></th></tr>
          </thead>
          <tbody>
            {mappings.map((m) => {
              const { label } = fromClaim(m.claimKey, m.claimValue);
              return (
                <tr key={`${m.claimKey}#${m.claimValue}`}>
                  <td>{label}</td>
                  <td><code>{m.headerName}</code></td>
                  <td>{m.description || ""}</td>
                  <td className="muted">{m.updatedAt || ""}</td>
                  <td>
                    <button className="btn btn-danger btn-sm" onClick={() => handleDelete(m.claimKey, m.claimValue)}>Delete</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
