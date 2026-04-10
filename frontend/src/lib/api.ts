import { getAuthToken } from "./stores";

type QueryValue = string | number | boolean | null | undefined;
type RequestOptions = Omit<RequestInit, "body"> & {
  body?: BodyInit | Record<string, unknown> | null;
  query?: Record<string, QueryValue>;
  auth?: boolean;
};

export class ApiError extends Error {
  status: number;
  data: unknown;

  constructor(message: string, status: number, data: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

const API_BASE = import.meta.env.VITE_API_URL ?? "/api";

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const isAbsolute = API_BASE.startsWith("http");
  const base = isAbsolute ? API_BASE : window.location.origin + API_BASE;
  const fullPath = base.replace(/\/$/, "") + (path.startsWith("/") ? path : "/" + path);
  const url = new URL(fullPath);

  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }

  return url.href;
}

function getErrorMessage(status: number, data: unknown): string {
  if (data && typeof data === "object") {
    const asRecord = data as Record<string, unknown>;
    const candidates = [asRecord.message, asRecord.error, asRecord.detail];

    for (const candidate of candidates) {
      if (typeof candidate === "string" && candidate.trim().length > 0) {
        return candidate;
      }
    }
  }

  return status >= 500 ? "Server error. Please try again." : "Request failed.";
}

function isJsonLike(body: unknown): body is Record<string, unknown> {
  if (!body || typeof body !== "object") {
    return false;
  }

  return (
    !(body instanceof FormData) &&
    !(body instanceof Blob) &&
    !(body instanceof URLSearchParams)
  );
}

export async function request<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { body, headers, query, auth = true, ...init } = options;
  const token = getAuthToken();

  const requestHeaders = new Headers(headers);
  let requestBody: BodyInit | null | undefined = null;

  if (isJsonLike(body)) {
    requestHeaders.set("Content-Type", "application/json");
    requestBody = JSON.stringify(body);
  } else if (body !== undefined) {
    requestBody = body;
  }

  if (auth && token) {
    requestHeaders.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(buildUrl(path, query), {
    ...init,
    headers: requestHeaders,
    body: requestBody,
  });

  const text = await response.text();
  let data: unknown = null;

  if (text) {
    try {
      data = JSON.parse(text) as unknown;
    } catch {
      data = text;
    }
  }

  if (!response.ok) {
    throw new ApiError(
      getErrorMessage(response.status, data),
      response.status,
      data,
    );
  }

  return data as T;
}

export const api = {
  login(email: string, password: string) {
    return request<Record<string, unknown>>("/auth/login", {
      method: "POST",
      auth: false,
      body: { email, password },
    });
  },

  // FIX: was (data: Record<string, unknown>) — Register.svelte was calling
  // api.register(email, password) with two positional args, so the full form
  // data (firstName, lastName, companyName) was never sent to the backend.
  // Signature now matches the explicit fields the form collects.
  register(data: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    companyName?: string;
  }) {
    return request<Record<string, unknown>>("/auth/register", {
      method: "POST",
      auth: false,
      body: data,
    });
  },

  getMe() {
    return request<Record<string, unknown>>("/auth/me");
  },

  getDashboardSummary() {
    return request<Record<string, unknown>>("/dashboard/summary");
  },

  getRiskScore() {
    return request<Record<string, unknown>>("/dashboard/risk-score");
  },

  getLogs(filters?: Record<string, QueryValue>) {
    return request<Array<Record<string, unknown>>>("/logs", {
      query: filters,
    });
  },

  getAlerts(filters?: Record<string, QueryValue>) {
    return request<Array<Record<string, unknown>>>("/alerts", {
      query: filters,
    });
  },

  resolveAlert(id: string) {
    return request<Record<string, unknown>>(`/alerts/${id}/resolve`, {
      method: "PATCH",
    });
  },

  getApiKeys() {
    return request<Array<Record<string, unknown>>>("/api-keys");
  },

  createApiKey(name: string) {
    return request<Record<string, unknown>>("/api-keys", {
      method: "POST",
      body: { name },
    });
  },
};
