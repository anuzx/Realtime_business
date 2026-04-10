<script lang="ts">
  import { link, push } from 'svelte-spa-router'
  import { api, ApiError } from '../api'
  import AuthCard from '../components/AuthCard.svelte'
  import Button from '../components/ui/Button.svelte'
  import Input from '../components/ui/Input.svelte'
  import { setAuth } from '../stores'
  import { asRecord } from '../normalize'

  let email = ''
  let password = ''
  let loading = false
  let error = ''

  function parseLoginResponse(payload: unknown): {
    token: string;
    user: Record<string, unknown> | null;
    apiKey: string;
  } {
    const data = asRecord(payload)
    const token = String(data.token ?? data.access_token ?? data.jwt ?? '')
    const apiKey = String(data.api_key ?? data.apiKey ?? '')

    const userRaw = data.user
    const user = userRaw && typeof userRaw === 'object' && !Array.isArray(userRaw)
      ? (userRaw as Record<string, unknown>)
      : null

    return { token, user, apiKey }
  }

  async function submit(): Promise<void> {
    error = ''
    loading = true

    try {
      const response = await api.login(email.trim(), password)
      const parsed = parseLoginResponse(response)

      if (!parsed.token) {
        throw new Error('Login succeeded but token was not returned.')
      }

      const fallbackUser = {
        email,
        name: email.split('@')[0],
      }

      const mergedUser = {
        ...(parsed.user ?? fallbackUser),
        apiKey: parsed.apiKey,
      }

      setAuth(parsed.token, mergedUser as { email: string; name?: string })
      await push('/dashboard')
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.message
      } else if (err instanceof Error) {
        error = err.message
      } else {
        error = 'Unable to login. Please try again.'
      }
    } finally {
      loading = false
    }
  }
</script>

<AuthCard title="Welcome back" subtitle="Sign in to review live AI monitoring telemetry.">
  <form on:submit|preventDefault={submit} class="form">
    <Input label="Email" type="email" bind:value={email} required placeholder="you@company.com" />
    <Input label="Password" type="password" bind:value={password} required placeholder="••••••••" />

    {#if error}
      <p class="error">{error}</p>
    {/if}

    <Button type="submit" fullWidth disabled={loading}>
      {loading ? 'Signing in...' : 'Sign in'}
    </Button>

    <p class="meta">
      Need an account? <a href="/register" use:link>Create one</a>
    </p>
  </form>
</AuthCard>

<style>
  .form {
    display: grid;
    gap: 0.8rem;
  }

  .error {
    font-size: 0.82rem;
    color: #fecaca;
    border: 1px solid rgba(239, 68, 68, 0.35);
    border-radius: 0.72rem;
    padding: 0.56rem 0.65rem;
    background: var(--danger-soft);
  }

  .meta {
    color: var(--text-muted);
    font-size: 0.82rem;
    text-align: center;
  }

  .meta a {
    color: #f4f4f5;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
</style>
