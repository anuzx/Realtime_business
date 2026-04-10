<script lang="ts">
  import { link, push } from 'svelte-spa-router'
  import { api, ApiError } from '../api'
  import AuthCard from '../components/AuthCard.svelte'
  import Button from '../components/ui/Button.svelte'
  import Input from '../components/ui/Input.svelte'

  let firstName = ''
  let lastName = ''
  let companyName = ''
  let email = ''
  let password = ''
  
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
      await api.register({
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        companyName: companyName.trim(),
        email: email.trim().toLowerCase(),
        password: password
      })
      
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
      <Input label="First Name" bind:value={firstName} required placeholder="Jane" />
      <Input label="Last Name" bind:value={lastName} required placeholder="Doe" />
    </div>

    <Input label="Company Name" bind:value={companyName} placeholder="Acme Corp (Optional)" />

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