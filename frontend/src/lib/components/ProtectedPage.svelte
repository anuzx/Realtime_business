<script lang="ts">
  import { onMount } from 'svelte'
  import { push } from 'svelte-spa-router'
  import { get } from 'svelte/store'
  import DashboardLayout from './DashboardLayout.svelte'
  import { authStore } from '../stores'

  onMount(() => {
    if (!get(authStore).token) {
      push('/login')
    }
  })
</script>

{#if $authStore.token}
  <DashboardLayout>
    <slot />
  </DashboardLayout>
{:else}
  <section class="redirecting">
    <p>Redirecting to login...</p>
  </section>
{/if}

<style>
  .redirecting {
    width: min(420px, 100% - 1rem);
    margin: 4rem auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.2rem;
    text-align: center;
    color: var(--text-muted);
    background: var(--surface);
  }
</style>
