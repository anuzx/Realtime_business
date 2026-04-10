<script lang="ts">
  import { link, location } from 'svelte-spa-router'
  import {
    BellRing,
    BookOpen,
    ChevronLeft,
    ChevronRight,
    KeyRound,
    LayoutDashboard,
    ScrollText,
  } from 'lucide-svelte'

  let collapsed = false

  const items = [
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/logs', label: 'Logs', icon: ScrollText },
    { href: '/alerts', label: 'Alerts', icon: BellRing },
    { href: '/api-keys', label: 'API Keys', icon: KeyRound },
    { href: '/docs', label: 'Docs', icon: BookOpen },
  ]
</script>

<aside class="sidebar glass-soft" class:collapsed>
  <button
    type="button"
    class="toggle"
    onclick={() => {
      collapsed = !collapsed
    }}
    aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
  >
    {#if collapsed}
      <ChevronRight size={16} />
    {:else}
      <ChevronLeft size={16} />
    {/if}
  </button>

  <nav>
    {#each items as item}
      <a href={item.href} use:link class:active={$location === item.href}>
        <svelte:component this={item.icon} size={16} />
        {#if !collapsed}
          <span>{item.label}</span>
        {/if}
      </a>
    {/each}
  </nav>
</aside>

<style>
  .sidebar {
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
    padding: 0.7rem;
    min-height: 100%;
    transition: width 180ms ease;
    width: 220px;
  }

  .sidebar.collapsed {
    width: 72px;
  }

  .toggle {
    width: 100%;
    background: transparent;
    color: var(--text-muted);
    border: 1px solid var(--border);
    border-radius: 0.65rem;
    height: 34px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 0.6rem;
    cursor: pointer;
  }

  nav {
    display: flex;
    flex-direction: column;
    gap: 0.32rem;
  }

  nav a {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    border-radius: 0.68rem;
    padding: 0.55rem 0.62rem;
    color: var(--text-muted);
    font-size: 0.84rem;
    border: 1px solid transparent;
    transition: background-color 160ms ease, border-color 160ms ease, color 160ms ease;
  }

  nav a:hover {
    color: #f1f4ff;
    border-color: var(--border);
  }

  nav a.active {
    color: #ffffff;
    background: rgba(124, 139, 255, 0.25);
    border-color: rgba(124, 139, 255, 0.46);
  }

  @media (max-width: 960px) {
    .sidebar,
    .sidebar.collapsed {
      width: 100%;
      min-height: auto;
    }

    nav {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
</style>
