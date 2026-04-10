<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError } from '../api'
  import AlertItem from '../components/AlertItem.svelte'
  import ProtectedPage from '../components/ProtectedPage.svelte'
  import Button from '../components/ui/Button.svelte'
  import { extractList } from '../normalize'
  import { alertsStore } from '../stores'

  let loading = true
  let resolving = false
  let error = ''

  async function loadAlerts(): Promise<void> {
    loading = true
    error = ''

    try {
      const response = await api.getAlerts()
      alertsStore.set(extractList(response, ['alerts']))
    } catch (err) {
      alertsStore.set([])
      if (err instanceof ApiError) {
        error = err.message
      } else if (err instanceof Error) {
        error = err.message
      } else {
        error = 'Unable to load alerts.'
      }
    } finally {
      loading = false
    }
  }

  async function resolveAlert(event: CustomEvent<{ id: string }>): Promise<void> {
    if (!event.detail.id) {
      return
    }

    resolving = true
    error = ''

    try {
      await api.resolveAlert(event.detail.id)
      await loadAlerts()
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.message
      } else if (err instanceof Error) {
        error = err.message
      } else {
        error = 'Unable to resolve alert.'
      }
    } finally {
      resolving = false
    }
  }

  onMount(() => {
    loadAlerts()
  })
</script>

<ProtectedPage>
  <section class="alerts-page">
    <header>
      <div>
        <h2>Active Alerts</h2>
        <p>Respond to security incidents and keep risk within policy thresholds.</p>
      </div>
      <Button variant="ghost" onclick={loadAlerts} disabled={loading || resolving}>
        Refresh
      </Button>
    </header>

    {#if error}
      <p class="state error">{error}</p>
    {/if}

    {#if loading}
      <p class="state">Loading alerts...</p>
    {:else if $alertsStore.length === 0}
      <p class="state">No active alerts at the moment.</p>
    {:else}
      <div class="list stagger">
        {#each $alertsStore as alert}
          <AlertItem {alert} on:resolve={resolveAlert} />
        {/each}
      </div>
    {/if}
  </section>
</ProtectedPage>

<style>
  .alerts-page {
    display: grid;
    gap: 0.8rem;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.6rem;
  }

  header h2 {
    font-size: 1.25rem;
    margin-bottom: 0.2rem;
  }

  header p {
    color: var(--text-muted);
    font-size: 0.85rem;
  }

  .list {
    display: grid;
    gap: 0.6rem;
  }

  .state {
    padding: 0.75rem;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    color: var(--text-muted);
    background: var(--surface);
    font-size: 0.86rem;
  }

  .state.error {
    color: #ffb7c7;
    border-color: rgba(255, 107, 135, 0.36);
    background: rgba(255, 107, 135, 0.12);
  }

  @media (max-width: 780px) {
    header {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
