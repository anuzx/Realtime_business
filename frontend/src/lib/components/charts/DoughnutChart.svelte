<script lang="ts">
  import { Doughnut } from 'svelte-chartjs'
  import type { ChartData, ChartOptions } from 'chart.js'
  import { ArcElement, Chart as ChartJS, Legend, Tooltip } from 'chart.js'

  ChartJS.register(ArcElement, Tooltip, Legend)

  export let labels: string[] = []
  export let values: number[] = []

  $: data = {
    labels,
    datasets: [
      {
        label: 'Distribution',
        data: values,
        backgroundColor: [
          'rgba(124, 139, 255, 0.86)',
          'rgba(99, 211, 255, 0.86)',
          'rgba(255, 181, 74, 0.86)',
          'rgba(255, 107, 135, 0.86)',
          'rgba(61, 219, 154, 0.86)',
        ],
        borderWidth: 0,
      },
    ],
  } satisfies ChartData<'doughnut'>

  const options: ChartOptions<'doughnut'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#cfd8f8' },
      },
    },
  }
</script>

<div class="chart-wrap">
  <Doughnut {data} {options} />
</div>

<style>
  .chart-wrap {
    min-height: 250px;
  }
</style>
