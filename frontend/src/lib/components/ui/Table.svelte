<script lang="ts">
  import { createEventDispatcher } from 'svelte'
  import { cn } from '../../utils'

  type Column = {
    key: string
    label: string
    sortable?: boolean
  }

  export let columns: Column[] = []
  export let rows: Array<Record<string, unknown>> = []
  export let sortKey = ''
  export let sortDirection: 'asc' | 'desc' = 'asc'
  export let className = ''

  const dispatch = createEventDispatcher<{
    sort: { key: string; direction: 'asc' | 'desc' }
  }>()

  function handleSort(column: Column): void {
    if (!column.sortable) {
      return
    }

    const direction =
      sortKey === column.key && sortDirection === 'asc' ? 'desc' : 'asc'

    dispatch('sort', { key: column.key, direction })
  }

  function renderCell(value: unknown): string {
    if (value === null || value === undefined) {
      return '--'
    }

    if (typeof value === 'object') {
      return JSON.stringify(value)
    }

    return String(value)
  }

</script>

<div class={cn('table-wrap glass-soft', className)}>
  <table>
    <thead>
      <tr>
        {#each columns as column}
          <th>
            <button
              type="button"
              class:sortable={column.sortable}
              class:active={sortKey === column.key}
              onclick={() => handleSort(column)}
            >
              {column.label}
              {#if sortKey === column.key}
                <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
              {/if}
            </button>
          </th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#if rows.length === 0}
        <tr>
          <td colspan={Math.max(columns.length, 1)} class="empty">No data available</td>
        </tr>
      {:else}
        {#each rows as row}
          <tr>
            {#each columns as column}
              <td>{renderCell(row[column.key])}</td>
            {/each}
          </tr>
        {/each}
      {/if}
    </tbody>
  </table>
</div>

<style>
  .table-wrap {
    width: 100%;
    border-radius: var(--radius-lg);
    overflow: hidden;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 640px;
  }

  th,
  td {
    text-align: left;
    padding: 0.72rem 0.8rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.84rem;
  }

  th {
    color: var(--text-muted);
    font-weight: 600;
    background: rgba(18, 18, 18, 0.94);
    position: sticky;
    top: 0;
  }

  td {
    color: var(--text);
  }

  tbody tr {
    transition: background-color 120ms ease;
  }

  tbody tr:hover {
    background: rgba(255, 255, 255, 0.03);
  }

  tr:last-child td {
    border-bottom: none;
  }

  button {
    all: unset;
    cursor: default;
    display: inline-flex;
    align-items: center;
    gap: 0.28rem;
  }

  button.sortable {
    cursor: pointer;
  }

  button.active {
    color: #ffffff;
  }

  .empty {
    text-align: center;
    color: var(--text-muted);
    padding: 1rem;
  }
</style>
