<script lang="ts">
  import Table from './ui/Table.svelte'

  export let rows: Array<Record<string, unknown>> = []

  let sortKey = 'timestamp'
  let sortDirection: 'asc' | 'desc' = 'desc'

  const columns = [
    { key: 'timestamp', label: 'Timestamp', sortable: true },
    { key: 'level', label: 'Level', sortable: true },
    { key: 'source', label: 'Source', sortable: true },
    { key: 'message', label: 'Message' },
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
