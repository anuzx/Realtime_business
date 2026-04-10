import { get, writable } from 'svelte/store'

const AUTH_TOKEN_KEY = 'pulseguard_token'
const AUTH_USER_KEY = 'pulseguard_user'

export type AuthUser = {
  id?: string
  email: string
  name?: string
}

export type AuthState = {
  user: AuthUser | null
  token: string | null
}

export type LogRecord = Record<string, unknown>
export type AlertRecord = Record<string, unknown>

const isBrowser = typeof window !== 'undefined'

function loadAuthState(): AuthState {
  if (!isBrowser) {
    return { user: null, token: null }
  }

  const token = window.localStorage.getItem(AUTH_TOKEN_KEY)
  const rawUser = window.localStorage.getItem(AUTH_USER_KEY)

  if (!token) {
    return { user: null, token: null }
  }

  try {
    return {
      token,
      user: rawUser ? (JSON.parse(rawUser) as AuthUser) : null,
    }
  } catch {
    return { user: null, token }
  }
}

export const authStore = writable<AuthState>(loadAuthState())
export const alertsStore = writable<AlertRecord[]>([])
export const logsStore = writable<LogRecord[]>([])

authStore.subscribe((state) => {
  if (!isBrowser) {
    return
  }

  if (state.token) {
    window.localStorage.setItem(AUTH_TOKEN_KEY, state.token)
  } else {
    window.localStorage.removeItem(AUTH_TOKEN_KEY)
  }

  if (state.user) {
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify(state.user))
  } else {
    window.localStorage.removeItem(AUTH_USER_KEY)
  }
})

export function setAuth(token: string, user: AuthUser | null): void {
  authStore.set({ token, user })
}

export function clearAuth(): void {
  authStore.set({ token: null, user: null })
}

export function getAuthToken(): string | null {
  return get(authStore).token
}
