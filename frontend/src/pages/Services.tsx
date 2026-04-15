import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Service } from "../api";

const empty: Partial<Service> = {
  serviceName: "",
  displayName: "",
  description: "",
  defaultHeaderName: "Authorization",
  defaultHeaderPrefix: "Key ",
  targetPrefix: "",
};

// Only API-key-authenticated services belong here. GitHub / Notion use 3LO
// (OAuth) and are handled by credential providers, not by API-key injection,
// so they have no entry in this preset list.
const PRESETS: Record<string, Partial<Service>> = {
  redash: {
    serviceName: "redash",
    displayName: "Redash",
    defaultHeaderName: "Authorization",
    defaultHeaderPrefix: "Key ",
    targetPrefix: "redash-target-",
  },
};

export default function Services() {
  const [services, setServices] = useState<Service[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<Partial<Service>>({ ...empty });
  const [preset, setPreset] = useState<string>("");

  const handlePresetChange = (value: string) => {
    setPreset(value);
    if (value === "custom") {
      setForm({ ...empty });
    } else if (value && PRESETS[value]) {
      setForm({ ...empty, ...PRESETS[value] });
    } else {
      setForm({ ...empty });
    }
  };

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await api.listServices();
      setServices(data.services);
    } catch (e) {
      setError((e as Error).message);
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    if (!form.serviceName) return;
    try {
      await api.createService({
        ...form,
        targetPrefix: form.targetPrefix || `${form.serviceName}-target-`,
      });
      setForm({ ...empty });
      setPreset("");
      setShowCreate(false);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const handleDelete = async (name: string) => {
    if (!confirm(`Delete service ${name}? Mappings are not cascaded.`)) return;
    try {
      await api.deleteService(name);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const set = (key: keyof Service, val: string) => setForm({ ...form, [key]: val });

  return (
    <div>
      <div className="page-header">
        <h1>Services</h1>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ Register Service</button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {showCreate && (
        <div className="card form-card">
          <h3>Register Service</h3>
          <div className="form-group">
            <label>Preset</label>
            <select value={preset} onChange={(e) => handlePresetChange(e.target.value)}>
              <option value="">-- select a preset --</option>
              {Object.keys(PRESETS).map((k) => (
                <option key={k} value={k}>{PRESETS[k].displayName} ({k})</option>
              ))}
              <option value="custom">Custom...</option>
            </select>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Service Name</label>
              <input
                value={form.serviceName || ""}
                onChange={(e) => set("serviceName", e.target.value)}
                placeholder="redash"
                disabled={preset !== "" && preset !== "custom"}
              />
            </div>
            <div className="form-group">
              <label>Display Name</label>
              <input value={form.displayName || ""} onChange={(e) => set("displayName", e.target.value)} placeholder="Redash" />
            </div>
          </div>
          <div className="form-group">
            <label>Description</label>
            <input value={form.description || ""} onChange={(e) => set("description", e.target.value)} />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Default Header Name</label>
              <input value={form.defaultHeaderName || ""} onChange={(e) => set("defaultHeaderName", e.target.value)} />
            </div>
            <div className="form-group">
              <label>Header Prefix</label>
              <input value={form.defaultHeaderPrefix || ""} onChange={(e) => set("defaultHeaderPrefix", e.target.value)} placeholder='e.g. "Key "' />
            </div>
          </div>
          <div className="form-group">
            <label>Target Prefix</label>
            <input value={form.targetPrefix || ""} onChange={(e) => set("targetPrefix", e.target.value)} placeholder="auto: serviceName-target-" />
          </div>
          <div className="form-actions">
            <button className="btn btn-primary" onClick={handleCreate}>Register</button>
            <button className="btn btn-secondary" onClick={() => setShowCreate(false)}>Cancel</button>
          </div>
        </div>
      )}

      {loading ? <p>Loading...</p> : (
        <table>
          <thead>
            <tr><th>Service</th><th>Display Name</th><th>Target Prefix</th><th>Header</th><th>Active</th><th></th></tr>
          </thead>
          <tbody>
            {services.map((s) => (
              <tr key={s.serviceName}>
                <td>
                  <Link to={`/services/${encodeURIComponent(s.serviceName)}/keys`}>
                    <strong>{s.serviceName}</strong>
                  </Link>
                </td>
                <td>{s.displayName}</td>
                <td><code>{s.targetPrefix}</code></td>
                <td><code>{s.defaultHeaderPrefix}{s.defaultHeaderName}</code></td>
                <td><span className={`badge ${s.isActive ? "badge-ok" : "badge-warn"}`}>{s.isActive ? "Active" : "Inactive"}</span></td>
                <td>
                  <button className="btn btn-danger btn-sm" onClick={() => handleDelete(s.serviceName)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
