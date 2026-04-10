<script lang="ts">
  import {
    Activity,
    AlertTriangle,
    CircleCheckBig,
    Database,
  } from 'lucide-svelte'
  import { onMount } from 'svelte'
  import { api, ApiError } from '../api'
  import { asRecord, extractNumber, extractSeries, extractText } from '../normalize'
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
      const [summaryRaw, riskRaw] = await Promise.all([
        api.getDashboardSummary(),
        api.getRiskScore(),
      ])

      const summary = asRecord(summaryRaw)
      const risk = asRecord(riskRaw)

      totalRequests = extractNumber(summary, ['totalRequests', 'requests', 'request_count'], 0)
      errorRate = extractNumber(summary, ['errorRate', 'error_rate'], 0)
      activeAlerts = extractNumber(summary, ['activeAlerts', 'alerts', 'open_alerts'], 0)
      monitoredModels = extractNumber(summary, ['models', 'monitoredModels', 'model_count'], 0)
      riskScore = extractNumber(risk, ['score', 'riskScore', 'risk'], 0)

      const requestSeries = extractSeries(summary, ['requestSeries', 'requestVolume', 'traffic'])
      const errorSeries = extractSeries(summary, ['errorCategories', 'errorsByCategory', 'errors'])
      const eventSeries = extractSeries(summary, ['eventDistribution', 'eventTypes', 'events'])

      requestLabels = requestSeries.labels
      requestValues = requestSeries.values
      errorLabels = errorSeries.labels
      errorValues = errorSeries.values
      eventLabels = eventSeries.labels
      eventValues = eventSeries.values
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

  $: riskText = extractText({ riskScore }, ['riskScore'], '0')
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
      <p class="state">Loading dashboard metrics...</p>
    {:else if error}
      <p class="state error">{error}</p>
    {/if}

    <div class="stats stagger">
      <StatCard title="Total Requests" value={String(totalRequests)} trend="+12% today" icon={Activity} />
      <StatCard
        title="Error Rate"
        value={`${errorRate}%`}
        trend={errorRate > 4 ? 'Increased from baseline' : 'Healthy baseline'}
        positive={errorRate <= 4}
        icon={AlertTriangle}
      />
      <StatCard title="Active Alerts" value={String(activeAlerts)} trend="Needs triage" positive={false} icon={CircleCheckBig} />
      <StatCard title="Monitored Models" value={String(monitoredModels)} trend="Across all environments" icon={Database} />
    </div>

    <div class="main-grid">
      <Card title="Request Volume" subtitle="Traffic and latency trend">
        {#if requestLabels.length === 0}
          <p class="empty">No request series data available.</p>
        {:else}
          <LineChart labels={requestLabels} values={requestValues} label="Requests" />
        {/if}
      </Card>
      <RiskGauge score={riskScore} />
    </div>

    <div class="secondary-grid">
      <Card title="Errors by Category">
        {#if errorLabels.length === 0}
          <p class="empty">No error category data available.</p>
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
    color: #ffb7c7;
    border-color: rgba(255, 107, 135, 0.36);
    background: rgba(255, 107, 135, 0.12);
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
    color: #f1f5ff;
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
