<script lang="ts">
  import DashboardSkeleton from '../components/DashboardSkeleton.svelte'
  import {
    Activity,
    AlertTriangle,
    CircleCheckBig,
    Database,
  } from 'lucide-svelte'
  import { onMount } from 'svelte'
  import { api, ApiError } from '../api'
  import { asRecord, extractNumber, extractText } from '../normalize'
  import BarChart from '../components/charts/BarChart.svelte'
  import DoughnutChart from '../components/charts/DoughnutChart.svelte'
  import LineChart from '../components/charts/LineChart.svelte'
  import ProtectedPage from '../components/ProtectedPage.svelte'
  import RiskGauge from '../components/RiskGauge.svelte'
  import StatCard from '../components/StatCard.svelte'
  import Card from '../components/ui/Card.svelte'

  let loading = true
  let error = ''

  let totalRequests = 0
  let errorRate = 0
  let activeAlerts = 0
  let monitoredModels = 0
  let riskScore = 0
  let highRiskCount = 0

  let requestLabels: string[] = []
  let requestValues: number[] = []

  let errorLabels: string[] = []
  let errorValues: number[] = []

  let eventLabels: string[] = []
  let eventValues: number[] = []

  async function loadDashboard(): Promise<void> {
    loading = true
    error = ''

    try {
      const [summaryRaw, riskRaw, keysRaw, logsRaw] = await Promise.all([
        api.getDashboardSummary(),
        api.getRiskScore(),
        api.getApiKeys(),
        api.getLogs({ limit: 100 }),
      ])

      const summary = asRecord(summaryRaw)
      const risk = asRecord(riskRaw)
      const keys = Array.isArray(keysRaw) ? keysRaw : []
      const logs = Array.isArray(logsRaw) ? logsRaw : []

      totalRequests = extractNumber(summary, ['total_logs', 'totalLogs'], 0)
      activeAlerts = extractNumber(summary, ['alerts'], 0)
      highRiskCount = extractNumber(summary, ['high_risk'], 0)
      riskScore = extractNumber(risk, ['risk_score', 'score', 'riskScore', 'risk'], 0)
      monitoredModels = keys.length
      errorRate = totalRequests > 0 ? Number(((highRiskCount / totalRequests) * 100).toFixed(2)) : 0

      const byEvent = new Map<string, number>()
      const bySeverity = new Map<string, number>()
      const byHour = new Map<string, number>()

      for (const log of logs) {
        const row = asRecord(log)
        const eventType = String(row.event_type ?? 'unknown')
        const severity = String(row.severity ?? 'low')
        const receivedAt = String(row.received_at ?? '')

        byEvent.set(eventType, (byEvent.get(eventType) ?? 0) + 1)
        bySeverity.set(severity, (bySeverity.get(severity) ?? 0) + 1)

        if (receivedAt) {
          const hourBucket = receivedAt.slice(0, 13).replace('T', ' ') + ':00'
          byHour.set(hourBucket, (byHour.get(hourBucket) ?? 0) + 1)
        }
      }

      const sortedHours = [...byHour.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(-10)
      requestLabels = sortedHours.map(([label]) => label)
      requestValues = sortedHours.map(([, count]) => count)

      errorLabels = [...bySeverity.keys()]
      errorValues = [...bySeverity.values()]
      eventLabels = [...byEvent.keys()]
      eventValues = [...byEvent.values()]
    } catch (err) {
      requestLabels = []
      requestValues = []
      errorLabels = []
      errorValues = []
      eventLabels = []
      eventValues = []

      if (err instanceof ApiError) {
        error = err.message
      } else if (err instanceof Error) {
        error = err.message
      } else {
        error = 'Failed to load dashboard.'
      }
    } finally {
      loading = false
    }
  }

  onMount(() => {
    loadDashboard()
  })

  $: riskText = String(riskScore)
</script>

<ProtectedPage>
  <section class="dashboard">
    <header class="dashboard__header">
      <div>
        <h2>Monitoring Overview</h2>
        <p>Live telemetry snapshot for your AI product surface.</p>
      </div>
    </header>

    {#if loading}
      <DashboardSkeleton />
    {:else if error}
      <p class="state error">{error}</p>
    {/if}

    <div class="stats stagger">
      <StatCard title="Total Logs" value={String(totalRequests)} trend="Captured from your integrations" icon={Activity} />
      <StatCard
        title="High-Risk Rate"
        value={`${errorRate}%`}
        trend={errorRate > 4 ? 'Investigate active threats' : 'Within normal range'}
        positive={errorRate <= 4}
        icon={AlertTriangle}
      />
      <StatCard title="Active Alerts" value={String(activeAlerts)} trend="Pending analyst review" positive={false} icon={CircleCheckBig} />
      <StatCard title="Active API Keys" value={String(monitoredModels)} trend="Connected developer integrations" icon={Database} />
    </div>

    <div class="main-grid">
      <Card title="Log Ingestion Volume" subtitle="Latest ingestion trend by hour">
        {#if requestLabels.length === 0}
          <p class="empty">No ingestion trend data available yet.</p>
        {:else}
          <LineChart labels={requestLabels} values={requestValues} label="Logs" />
        {/if}
      </Card>
      <RiskGauge score={riskScore} />
    </div>

    <div class="secondary-grid">
      <Card title="Severity Distribution">
        {#if errorLabels.length === 0}
          <p class="empty">No severity distribution data available.</p>
        {:else}
          <BarChart labels={errorLabels} values={errorValues} />
        {/if}
      </Card>
      <Card title="Event Type Distribution">
        {#if eventLabels.length === 0}
          <p class="empty">No event distribution data available.</p>
        {:else}
          <DoughnutChart labels={eventLabels} values={eventValues} />
        {/if}
      </Card>
    </div>

    <footer class="footnote">
      <p>Current risk score: <strong>{riskText}</strong></p>
    </footer>
  </section>
</ProtectedPage>

<style>
  .dashboard {
    display: grid;
    gap: 0.9rem;
  }

  .dashboard__header h2 {
    font-size: 1.3rem;
    margin-bottom: 0.24rem;
  }

  .dashboard__header p {
    color: var(--text-muted);
    font-size: 0.88rem;
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
    color: #fecaca;
    border-color: rgba(239, 68, 68, 0.36);
    background: var(--danger-soft);
  }

  .stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.7rem;
  }

  .main-grid {
    display: grid;
    grid-template-columns: 1.5fr 1fr;
    gap: 0.7rem;
  }

  .secondary-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.7rem;
  }

  .footnote {
    color: var(--text-muted);
    font-size: 0.82rem;
  }

  .empty {
    color: var(--text-muted);
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    padding: 1rem;
    text-align: center;
    font-size: 0.84rem;
  }

  .footnote strong {
    color: var(--text);
  }

  @media (max-width: 1080px) {
    .stats {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .main-grid,
    .secondary-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
