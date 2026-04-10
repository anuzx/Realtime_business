<script lang="ts">
  import { cn } from '../../utils'

  export let title = ''
  export let subtitle = ''
  export let className = ''
</script>

<article class={cn('card glass-soft', className)}>
  {#if title || subtitle}
    <header class="card__header">
      {#if title}
        <h3>{title}</h3>
      {/if}
      {#if subtitle}
        <p>{subtitle}</p>
      {/if}
      <slot name="header" />
    </header>
  {:else}
    <slot name="header" />
  {/if}

  <div class="card__content">
    <slot />
  </div>

  {#if $$slots.footer}
    <footer class="card__footer">
      <slot name="footer" />
    </footer>
  {/if}
</article>

<style>
  .card {
    border-radius: var(--radius-lg);
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.85rem;
  }

  .card__header {
    display: flex;
    flex-direction: column;
    gap: 0.24rem;
  }

  .card__header h3 {
    font-size: 0.98rem;
    letter-spacing: 0.01em;
  }

  .card__header p {
    color: var(--text-muted);
    font-size: 0.82rem;
  }

  .card__content {
    min-height: 0;
  }

  .card__footer {
    border-top: 1px solid var(--border);
    padding-top: 0.8rem;
  }
</style>
