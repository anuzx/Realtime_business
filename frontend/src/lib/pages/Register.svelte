<script lang="ts">
  import { link, push } from 'svelte-spa-router'
  import { api, ApiError } from '../api'
  import AuthCard from '../components/AuthCard.svelte'
  import Button from '../components/ui/Button.svelte'
  import Input from '../components/ui/Input.svelte'

  let firstName = ''
  let lastName = ''
  let email = ''
  let password = ''
  let companyName = ''
  let loading = false
  let error = ''
  let success = ''

  async function submit(): Promise<void> {
    error = ''
    success = ''

    if (!firstName || !lastName) {
      error = 'Please enter your full name.'
      return
    }

    if (password.length < 8) {
      error = 'Password must contain at least 8 characters.'
      return
    }

    loading = true

    try {
      await api.register({ firstName, lastName, email: email.trim(), password, companyName })
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
    <div class="row">
      <Input label="First name" type="text" bind:value={firstName} required placeholder="Jane" />
      <Input label="Last name" type="text" bind:value={lastName} required placeholder="Smith" />
    </div>
    <Input label="Company name" type="text" bind:value={companyName} placeholder="Acme Corp" />
    <Input label="Email" type="email" bind:value={email} required placeholder="you@company.com" />
    <Input
      label="Password"
      type="password"
      bind:value={password}
      required
      placeholder="Minimum 8 characters"
    />

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

  .row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.6rem;
  }

  .error,
  .success {
    font-size: 0.82rem;
    border-radius: 0.72rem;
    padding: 0.56rem 0.65rem;
  }

  .error {
    color: #fecaca;
    border: 1px solid rgba(239, 68, 68, 0.35);
    background: var(--danger-soft);
  }

  .success {
    color: #bbf7d0;
    border: 1px solid rgba(16, 185, 129, 0.35);
    background: var(--success-soft);
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
