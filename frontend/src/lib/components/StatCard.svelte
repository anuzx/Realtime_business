<script lang="ts">
  import type { ComponentType } from 'svelte'
  import Card from './ui/Card.svelte'

  export let title = ''
  export let value = '--'
  export let trend = ''
  export let positive = true
  export let icon: ComponentType | null = null
</script>

<Card className="stat-card slide-up">
  <div class="row">
    <div>
      <p class="title">{title}</p>
      <h3>{value}</h3>
    </div>
    {#if icon}
      <div class="icon-wrap">
        <svelte:component this={icon} size={16} />
      </div>
    {/if}
  </div>
  {#if trend}
    <p class:positive class:negative={!positive}>
      {trend}
    </p>
  {/if}
</Card>

<style>
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .title {
    color: var(--text-muted);
    font-size: 0.78rem;
  }

  h3 {
    font-size: 1.4rem;
    margin-top: 0.16rem;
  }

  .icon-wrap {
    width: 34px;
    height: 34px;
    border-radius: 0.7rem;
    border: 1px solid rgba(255, 255, 255, 0.24);
    background: rgba(255, 255, 255, 0.08);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: #f4f4f5;
  }

  p.positive,
  p.negative {
    font-size: 0.78rem;
    font-weight: 600;
  }

  p.positive {
    color: #b6ffd6;
  }

  p.negative {
    color: #ffb3c5;
  }
</style>
