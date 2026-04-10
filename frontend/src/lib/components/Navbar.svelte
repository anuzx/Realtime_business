<script lang="ts">
  import { link, location, push } from 'svelte-spa-router'
  import { authStore, clearAuth } from '../stores'
  import Button from './ui/Button.svelte'

  function logout(): void {
    clearAuth()
    push('/login')
  }
</script>

<header class="navbar glass-soft slide-up">
  <div class="brand">
    <span class="status-dot"></span>
    <div>
      <h1>PulseGuard</h1>
      <p>Realtime AI Monitor</p>
    </div>
  </div>

  <nav>
    <a href="/dashboard" use:link class:active={$location === '/dashboard'}>Overview</a>
    <a href="/logs" use:link class:active={$location === '/logs'}>Logs</a>
    <a href="/alerts" use:link class:active={$location === '/alerts'}>Alerts</a>
    <a href="/api-keys" use:link class:active={$location === '/api-keys'}>API Keys</a>
  </nav>

  <div class="user-box">
    <div>
      <strong>{$authStore.user?.name || 'Analyst'}</strong>
      <span>{$authStore.user?.email || 'signed-in user'}</span>
    </div>
    <Button variant="ghost" size="sm" onclick={logout}>Logout</Button>
  </div>
</header>

<style>
  .navbar {
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
    padding: 0.72rem 0.9rem;
    display: grid;
    grid-template-columns: auto 1fr auto;
    align-items: center;
    gap: 0.8rem;
  }

  .brand {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
  }

  .brand .status-dot {
    background: var(--success);
    box-shadow: 0 0 0 6px rgba(61, 219, 154, 0.15);
  }

  .brand h1 {
    font-size: 0.92rem;
    font-weight: 700;
    line-height: 1.2;
  }

  .brand p {
    color: var(--text-muted);
    font-size: 0.72rem;
  }

  nav {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.38rem;
    flex-wrap: wrap;
  }

  nav a {
    color: var(--text-muted);
    font-size: 0.8rem;
    padding: 0.42rem 0.7rem;
    border-radius: 999px;
    transition: background-color 140ms ease, color 140ms ease;
  }

  nav a.active {
    color: #f5f7ff;
    background: rgba(124, 139, 255, 0.24);
  }

  nav a:hover {
    color: #f0f2ff;
  }

  .user-box {
    display: inline-flex;
    align-items: center;
    gap: 0.55rem;
  }

  .user-box strong,
  .user-box span {
    display: block;
    text-align: right;
  }

  .user-box strong {
    font-size: 0.8rem;
  }

  .user-box span {
    color: var(--text-muted);
    font-size: 0.72rem;
  }

  @media (max-width: 900px) {
    .navbar {
      grid-template-columns: 1fr;
      justify-items: stretch;
    }

    nav {
      justify-content: flex-start;
    }

    .user-box {
      justify-content: space-between;
    }

    .user-box strong,
    .user-box span {
      text-align: left;
    }
  }
</style>
