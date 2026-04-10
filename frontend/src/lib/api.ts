import { getAuthToken } from './stores'

const BASE = '/api'

type QueryValue = string | number | boolean | null | undefined
type RequestOptions = Omit<RequestInit, 'body'> & {
  body?: BodyInit | Record<string, unknown> | null
  query?: Record<string, QueryValue>
  auth?: boolean
}

export class ApiError extends Error {
  status: number
  data: unknown

  constructor(message: string, status: number, data: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const origin = typeof window === 'undefined' ? 'http://localhost' : window.location.origin
  const url = new URL(`${BASE}${path}`, origin)

  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value))
      }
    }
  }

  return `${url.pathname}${url.search}`
}

function getErrorMessage(status: number, data: unknown): string {
  if (data && typeof data === 'object') {
    const asRecord = data as Record<string, unknown>
    const candidates = [asRecord.message, asRecord.error, asRecord.detail]

    for (const candidate of candidates) {
      if (typeof candidate === 'string' && candidate.trim().length > 0) {
        return candidate
      }
    }
  }

  return status >= 500 ? 'Server error. Please try again.' : 'Request failed.'
}

function isJsonLike(body: unknown): body is Record<string, unknown> {
  if (!body || typeof body !== 'object') {
    return false
  }

  return !(body instanceof FormData) && !(body instanceof Blob) && !(body instanceof URLSearchParams)
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, headers, query, auth = true, ...init } = options
  const token = getAuthToken()

  const requestHeaders = new Headers(headers)
  let requestBody: BodyInit | null | undefined = null

  if (isJsonLike(body)) {
    requestHeaders.set('Content-Type', 'application/json')
    requestBody = JSON.stringify(body)
  } else if (body !== undefined) {
    requestBody = body
  }

  if (auth && token) {
    requestHeaders.set('Authorization', `Bearer ${token}`)
  }

  const response = await fetch(buildUrl(path, query), {
    ...init,
    headers: requestHeaders,
    body: requestBody,
  })

  const text = await response.text()
  let data: unknown = null

  if (text) {
    try {
      data = JSON.parse(text) as unknown
    } catch {
      data = text
    }
  }

  if (!response.ok) {
    throw new ApiError(getErrorMessage(response.status, data), response.status, data)
  }

  return data as T
}

export const api = {
  login(email: string, password: string) {
    return request<Record<string, unknown>>('/auth/login', {
      method: 'POST',
      auth: false,
      body: { email, password },
    })
  },

  register(email: string, password: string) {
    return request<Record<string, unknown>>('/auth/register', {
      method: 'POST',
      auth: false,
      body: { email, password },
    })
  },

  getMe() {
    return request<Record<string, unknown>>('/users/me')
  },

  getDashboardSummary() {
    return request<Record<string, unknown>>('/dashboard/summary')
  },

  getRiskScore() {
    return request<Record<string, unknown>>('/dashboard/risk-score')
  },

  getLogs(filters?: Record<string, QueryValue>) {
    return request<Record<string, unknown> | Array<Record<string, unknown>>>('/logs', {
      query: filters,
    })
  },

  getAlerts() {
    return request<Record<string, unknown> | Array<Record<string, unknown>>>('/alerts')
  },

  resolveAlert(id: string) {
    return request<Record<string, unknown>>(`/alerts/${id}`, {
      method: 'PATCH',
    })
  },

  getApiKeys() {
    return request<Record<string, unknown> | Array<Record<string, unknown>>>('/api-keys')
  },

  createApiKey(name: string) {
    return request<Record<string, unknown>>('/api-keys', {
      method: 'POST',
      body: { name },
    })
  },

  analyzeAI(logIds: string[]) {
    return request<Record<string, unknown>>('/ai/analyze', {
      method: 'POST',
      body: { logIds },
    })
  },
}
