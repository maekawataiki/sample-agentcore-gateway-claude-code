/** Admin API client — services + claim→key mappings. */

import { getConfig, getToken } from "./auth";

export interface Service {
  serviceName: string;
  displayName?: string;
  description?: string;
  defaultHeaderName?: string;
  defaultHeaderPrefix?: string;
  targetPrefix?: string;
  isActive?: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface Mapping {
  serviceName: string;
  claimKey: string;
  claimValue: string;
  apiKey: string; // always "***" when returned by the API
  headerName: string;
  description?: string;
  updatedAt?: string;
  updatedBy?: string;
}

async function request<T = unknown>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const { adminApiUrl } = getConfig();
  const token = getToken();
  const resp = await fetch(`${adminApiUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...options.headers,
    },
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error || `HTTP ${resp.status}`);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  // Services
  listServices: () => request<{ services: Service[] }>("/services"),
  getService: (name: string) => request<Service>(`/services/${enc(name)}`),
  createService: (body: Partial<Service>) =>
    request<Service>("/services", { method: "POST", body: JSON.stringify(body) }),
  updateService: (name: string, body: Partial<Service>) =>
    request<Service>(`/services/${enc(name)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteService: (name: string) =>
    request(`/services/${enc(name)}`, { method: "DELETE" }),

  // Mappings
  listMappings: (service: string) =>
    request<{ mappings: Mapping[] }>(`/services/${enc(service)}/mappings`),
  putMapping: (service: string, body: Omit<Mapping, "serviceName" | "updatedAt" | "updatedBy">) =>
    request<Mapping>(`/services/${enc(service)}/mappings`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteMapping: (service: string, claimKey: string, claimValue: string) =>
    request(
      `/services/${enc(service)}/mappings?claimKey=${enc(claimKey)}&claimValue=${enc(claimValue)}`,
      { method: "DELETE" },
    ),
};

function enc(s: string) {
  return encodeURIComponent(s);
}
