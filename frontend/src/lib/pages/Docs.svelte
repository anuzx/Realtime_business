<script lang="ts">
  import ProtectedPage from '../components/ProtectedPage.svelte'
  import Card from '../components/ui/Card.svelte'

  const endpoints = [
    { method: 'POST', path: '/api/auth/login', note: 'Authenticate and return JWT' },
    { method: 'POST', path: '/api/auth/register', note: 'Create account' },
    { method: 'GET', path: '/api/auth/me', note: 'Get current user profile' },
    { method: 'GET', path: '/api/dashboard/summary', note: 'Dashboard aggregate metrics' },
    { method: 'GET', path: '/api/dashboard/risk-score', note: 'Current risk score' },
    { method: 'GET', path: '/api/logs', note: 'Filterable log stream' },
    { method: 'GET', path: '/api/alerts', note: 'Current alert list' },
    { method: 'PATCH', path: '/api/alerts/:id/resolve', note: 'Resolve an alert' },
    { method: 'GET', path: '/api/api-keys', note: 'List API keys' },
    { method: 'POST', path: '/api/api-keys', note: 'Create API key' },
    { method: 'POST', path: '/api/logs', note: 'Ingest logs with x-api-key header' },
  ]
</script>

<ProtectedPage>
  <section class="docs-page">
    <header>
      <h2>API Reference</h2>
      <p>Quick endpoint index used by the PulseGuard frontend client.</p>
    </header>

    <Card title="Endpoint catalog" subtitle="All requests are sent via native fetch through src/lib/api.ts.">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {#each endpoints as endpoint}
              <tr>
                <td><span class={`method method--${endpoint.method.toLowerCase()}`}>{endpoint.method}</span></td>
                <td><code>{endpoint.path}</code></td>
                <td>{endpoint.note}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </Card>
  </section>
</ProtectedPage>

<style>
  .docs-page {
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

  .table-wrap {
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 680px;
  }

  th,
  td {
    text-align: left;
    padding: 0.68rem 0.72rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.83rem;
  }

  th {
    color: var(--text-muted);
  }

  tr:last-child td {
    border-bottom: none;
  }

  .method {
    display: inline-flex;
    min-width: 54px;
    justify-content: center;
    font-size: 0.7rem;
    border-radius: 999px;
    padding: 0.2rem 0.45rem;
    font-weight: 700;
    border: 1px solid transparent;
  }

  .method--get {
    color: #d2f1ff;
    background: rgba(99, 211, 255, 0.18);
    border-color: rgba(99, 211, 255, 0.32);
  }

  .method--post {
    color: #c8d1ff;
    background: rgba(124, 139, 255, 0.18);
    border-color: rgba(124, 139, 255, 0.32);
  }

  .method--patch {
    color: #ffe3bb;
    background: rgba(255, 181, 74, 0.18);
    border-color: rgba(255, 181, 74, 0.32);
  }

  code {
    font-family: ui-monospace, Menlo, Monaco, Consolas, monospace;
    color: #eef2ff;
    font-size: 0.8rem;
  }
</style>
