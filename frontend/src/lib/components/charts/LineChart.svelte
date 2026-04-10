<script lang="ts">
  import { Line } from 'svelte-chartjs'
  import type { ChartData, ChartOptions } from 'chart.js'
  import {
    Chart as ChartJS,
    CategoryScale,
    Legend,
    LineElement,
    LinearScale,
    PointElement,
    Title,
    Tooltip,
  } from 'chart.js'

  ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend)

  export let labels: string[] = []
  export let values: number[] = []
  export let label = 'Requests'

  $: data = {
    labels,
    datasets: [
      {
        label,
        data: values,
        borderColor: 'rgba(124, 139, 255, 1)',
        backgroundColor: 'rgba(124, 139, 255, 0.2)',
        fill: true,
        tension: 0.35,
        pointRadius: 2,
      },
    ],
  } satisfies ChartData<'line'>

  const options: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#cfd8f8' },
      },
    },
    scales: {
      x: {
        ticks: { color: '#93a0c6' },
        grid: { color: 'rgba(147, 160, 198, 0.15)' },
      },
      y: {
        ticks: { color: '#93a0c6' },
        grid: { color: 'rgba(147, 160, 198, 0.15)' },
      },
    },
  }
</script>

<div class="chart-wrap">
  <Line {data} {options} />
</div>

<style>
  .chart-wrap {
    min-height: 250px;
  }
</style>
