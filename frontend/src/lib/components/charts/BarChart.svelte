<script lang="ts">
  import { Bar } from 'svelte-chartjs'
  import type { ChartData, ChartOptions } from 'chart.js'
  import {
    BarElement,
    CategoryScale,
    Chart as ChartJS,
    Legend,
    LinearScale,
    Tooltip,
  } from 'chart.js'

  ChartJS.register(CategoryScale, LinearScale, BarElement, Legend, Tooltip)

  export let labels: string[] = []
  export let values: number[] = []

  $: data = {
    labels,
    datasets: [
      {
        label: 'Errors',
        data: values,
        backgroundColor: [
          'rgba(255, 107, 135, 0.8)',
          'rgba(255, 181, 74, 0.8)',
          'rgba(99, 211, 255, 0.8)',
          'rgba(124, 139, 255, 0.8)',
        ],
        borderRadius: 10,
      },
    ],
  } satisfies ChartData<'bar'>

  const options: ChartOptions<'bar'> = {
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
  <Bar {data} {options} />
</div>

<style>
  .chart-wrap {
    min-height: 250px;
  }
</style>
