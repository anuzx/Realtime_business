<script lang="ts">
  import LogsSkeleton from '../components/LogsSkeleton.svelte';
  import { onMount } from 'svelte'
  import { api, ApiError } from '../api'
  import LogTable from '../components/LogTable.svelte'
  import ProtectedPage from '../components/ProtectedPage.svelte'
  import Button from '../components/ui/Button.svelte'
  import Input from '../components/ui/Input.svelte'
  import { extractList } from '../normalize'
  import { logsStore } from '../stores'

  let loading = true
  let error = ''

  let q = ''
  let level = ''
  let source = ''

  async function loadLogs(): Promise<void> {
    loading = true
    error = ''

    try {
      const response = await api.getLogs({ q, level, source })
      const items = extractList(response, ['logs'])
      logsStore.set(items)
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.message
      } else if (err instanceof Error) {
        error = err.message
      } else {
        error = 'Unable to load logs.'
      }
      logsStore.set([])
    } finally {
      loading = false
    }
  }

  onMount(() => {
    loadLogs()
  })
</script>

<ProtectedPage>
  <section class="logs-page">
    <header>
      <h2>Request Logs</h2>
      <p>Filter logs by source and severity before deep analysis.</p>
    </header>

    <form class="filters glass-soft" on:submit|preventDefault={loadLogs}>
      <Input label="Search" bind:value={q} placeholder="message, trace id, or actor" />
      <label>
        <span>Level</span>
        <select bind:value={level}>
          <option value="">All</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="error">Error</option>
        </select>
      </label>
      <Input label="Source" bind:value={source} placeholder="api-gateway" />
      <div class="actions">
        <Button type="submit" disabled={loading}>{loading ? 'Loading...' : 'Apply filters'}</Button>
      </div>
    </form>

    {#if error}
      <p class="state error">{error}</p>
    {/if}

    {#if loading}
      <LogsSkeleton />
    {:else if $logsStore.length === 0}
      <p class="state">No logs found for selected filters.</p>
    {:else}
      <LogTable rows={$logsStore} />
    {/if}
  </section>
</ProtectedPage>

<style>
  .logs-page {
    display: grid;
    gap: 0.8rem;
  }

  header h2 {
    font-size: 1.25rem;
    margin-bottom: 0.2rem;
  }

  header p {
    color: var(--text-muted);
    font-size: 0.85rem;
  }

  .filters {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 0.8rem;
    display: grid;
    grid-template-columns: 1.3fr 0.7fr 1fr auto;
    gap: 0.6rem;
    align-items: end;
  }

  label {
    display: grid;
    gap: 0.35rem;
  }

  label span {
    color: var(--text-muted);
    font-size: 0.82rem;
  }

  select {
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: rgba(10, 18, 35, 0.95);
    color: var(--text);
    padding: 0.64rem 0.72rem;
    outline: none;
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

  @media (max-width: 960px) {
    .filters {
      grid-template-columns: 1fr;
    }

    .actions {
      display: grid;
    }
  }
</style>
