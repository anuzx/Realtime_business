<script lang="ts">
  import Table from './ui/Table.svelte'

  export let rows: Array<Record<string, unknown>> = []

  let sortKey = 'received_at'
  let sortDirection: 'asc' | 'desc' = 'desc'

  const columns = [
    { key: 'received_at', label: 'Received At', sortable: true },
    { key: 'severity', label: 'Severity', sortable: true },
    { key: 'event_type', label: 'Event Type', sortable: true },
    { key: 'actor_email', label: 'Actor', sortable: true },
    { key: 'ip_address', label: 'IP Address', sortable: true },
    { key: 'endpoint', label: 'Endpoint', sortable: true },
  ]

  $: sortedRows = [...rows].sort((a, b) => {
    const aValue = String(a[sortKey] ?? '')
    const bValue = String(b[sortKey] ?? '')
    const result = aValue.localeCompare(bValue)
    return sortDirection === 'asc' ? result : -result
  })

  function handleSort(event: CustomEvent<{ key: string; direction: 'asc' | 'desc' }>): void {
    sortKey = event.detail.key
    sortDirection = event.detail.direction
  }
</script>

<Table
  {columns}
  rows={sortedRows}
  {sortKey}
  {sortDirection}
  on:sort={handleSort}
/>
