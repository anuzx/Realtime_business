<script lang="ts">
  import { link, push } from 'svelte-spa-router'
  import { api, ApiError } from '../api'
  import AuthCard from '../components/AuthCard.svelte'
  import Button from '../components/ui/Button.svelte'
  import Input from '../components/ui/Input.svelte'

  let email = ''
  let password = ''
  let confirm = ''
  let loading = false
  let error = ''
  let success = ''

  async function submit(): Promise<void> {
    error = ''
    success = ''

    if (password.length < 8) {
      error = 'Password must contain at least 8 characters.'
      return
    }

    if (password !== confirm) {
      error = 'Passwords do not match.'
      return
    }

    loading = true

    try {
      await api.register(email.trim(), password)
      success = 'Account created. Redirecting to login...'
      setTimeout(() => {
        push('/login')
      }, 900)
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.message
      } else if (err instanceof Error) {
        error = err.message
      } else {
        error = 'Unable to register. Please try again.'
      }
    } finally {
      loading = false
    }
  }
</script>

<AuthCard title="Create account" subtitle="Set up your PulseGuard operator profile.">
  <form on:submit|preventDefault={submit} class="form">
    <Input label="Email" type="email" bind:value={email} required placeholder="you@company.com" />
    <Input
      label="Password"
      type="password"
      bind:value={password}
      required
      placeholder="Minimum 8 characters"
    />
    <Input label="Confirm password" type="password" bind:value={confirm} required placeholder="Repeat password" />

    {#if error}
      <p class="error">{error}</p>
    {/if}

    {#if success}
      <p class="success">{success}</p>
    {/if}

    <Button type="submit" fullWidth disabled={loading}>
      {loading ? 'Creating...' : 'Create account'}
    </Button>

    <p class="meta">
      Already have access? <a href="/login" use:link>Sign in</a>
    </p>
  </form>
</AuthCard>

<style>
  .form {
    display: grid;
    gap: 0.8rem;
  }

  .error,
  .success {
    font-size: 0.82rem;
    border-radius: 0.72rem;
    padding: 0.56rem 0.65rem;
  }

  .error {
    color: #ffadbf;
    border: 1px solid rgba(255, 107, 135, 0.35);
    background: rgba(255, 107, 135, 0.12);
  }

  .success {
    color: #b8ffd8;
    border: 1px solid rgba(61, 219, 154, 0.35);
    background: rgba(61, 219, 154, 0.12);
  }

  .meta {
    color: var(--text-muted);
    font-size: 0.82rem;
    text-align: center;
  }

  .meta a {
    color: #d8deff;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
</style>
