<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError } from '../api'
  import ProtectedPage from '../components/ProtectedPage.svelte'
  import Button from '../components/ui/Button.svelte'
  import Card from '../components/ui/Card.svelte'
  import Table from '../components/ui/Table.svelte'
  import { extractList } from '../normalize'

  let loading = true
  let creating = false
  let error = ''

  let rows: Array<Record<string, unknown>> = []
  let createdSecret = ''

  const columns = [
    { key: 'id', label: 'Key ID', sortable: true },
    { key: 'key', label: 'API Key', sortable: true },
    { key: 'created_at', label: 'Created At', sortable: true },
    { key: 'status', label: 'Status', sortable: true },
  ]

  let sortKey = 'created_at'
  let sortDirection: 'asc' | 'desc' = 'desc'

  $: sortedRows = [...rows].sort((a, b) => {
    const aValue = String(a[sortKey] ?? '')
    const bValue = String(b[sortKey] ?? '')
    const result = aValue.localeCompare(bValue)
    return sortDirection === 'asc' ? result : -result
  })

  function onSort(event: CustomEvent<{ key: string; direction: 'asc' | 'desc' }>): void {
    sortKey = event.detail.key
    sortDirection = event.detail.direction
  }

  async function loadKeys(): Promise<void> {
    loading = true
    error = ''

    try {
      const response = await api.getApiKeys()
      const list = extractList(response, ['apiKeys', 'keys'])
      rows = list.map((item) => {
        const key = String(item.key ?? '')
        const id = String(item.id ?? '')
        const createdAt = String(item.created_at ?? '')
        const isActive = Boolean(item.is_active)

        return {
          id,
          key,
          created_at: createdAt,
          status: isActive ? 'active' : 'revoked',
        }
      })
    } catch (err) {
      rows = []
      if (err instanceof ApiError) {
        error = err.message
      } else if (err instanceof Error) {
        error = err.message
      } else {
        error = 'Unable to load API keys.'
      }
    } finally {
      loading = false
    }
  }

  async function createKey(): Promise<void> {
    creating = true
    error = ''
    createdSecret = ''

    try {
      const response = await api.createApiKey('generated-key')
      createdSecret = String(
        (response as Record<string, unknown>).key ??
          (response as Record<string, unknown>).secret ??
          ''
      )
      await loadKeys()
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.message
      } else if (err instanceof Error) {
        error = err.message
      } else {
        error = 'Unable to create key.'
      }
    } finally {
      creating = false
    }
  }

  onMount(() => {
    loadKeys()
  })
</script>

<ProtectedPage>
  <section class="keys-page">
    <header>
      <h2>API Keys</h2>
      <p>Create and manage machine credentials for backend integrations.</p>
    </header>

    <Card title="Create new key" subtitle="Use unique names per service and environment.">
      <form class="create" on:submit|preventDefault={createKey}>
        <Button type="submit" disabled={creating}>{creating ? 'Creating...' : 'Generate API key'}</Button>
      </form>

      {#if createdSecret}
        <p class="state success">New key: <code>{createdSecret}</code> (copy it now; it may not be shown again).</p>
      {/if}

      {#if error}
        <p class="state error">{error}</p>
      {/if}
    </Card>

    {#if loading}
      <p class="state">Loading key inventory...</p>
    {:else if rows.length === 0}
      <p class="state">No API keys found.</p>
    {:else}
      <Table columns={columns} rows={sortedRows} {sortKey} {sortDirection} on:sort={onSort} />
    {/if}
  </section>
</ProtectedPage>

<style>
  .keys-page {
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

  .create {
    display: grid;
    grid-template-columns: auto;
    gap: 0.6rem;
    align-items: center;
  }

  .state {
    margin-top: 0.35rem;
    padding: 0.75rem;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    color: var(--text-muted);
    background: var(--surface);
    font-size: 0.86rem;
  }

  .state.success {
    color: #bbf7d0;
    border-color: rgba(16, 185, 129, 0.36);
    background: var(--success-soft);
  }

  .state.error {
    color: #fecaca;
    border-color: rgba(239, 68, 68, 0.36);
    background: var(--danger-soft);
  }

  code {
    font-family: ui-monospace, Menlo, Monaco, Consolas, monospace;
  }

  @media (max-width: 700px) {
    .create {
      grid-template-columns: auto;
    }
  }
</style>
