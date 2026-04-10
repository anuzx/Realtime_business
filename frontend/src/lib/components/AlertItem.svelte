<script lang="ts">
  import { createEventDispatcher } from 'svelte'
  import Badge from './ui/Badge.svelte'
  import Button from './ui/Button.svelte'

  export let alert: Record<string, unknown> = {}

  const dispatch = createEventDispatcher<{ resolve: { id: string } }>()

  function severityToVariant(
    severity: unknown
  ): 'success' | 'warning' | 'error' | 'info' | 'neutral' {
    const text = String(severity ?? '').toLowerCase()

    if (text.includes('critical') || text.includes('high') || text.includes('error')) {
      return 'error'
    }
    if (text.includes('medium') || text.includes('warn')) {
      return 'warning'
    }
    if (text.includes('low') || text.includes('ok')) {
      return 'success'
    }
    if (text.includes('info')) {
      return 'info'
    }

    return 'neutral'
  }
</script>

<article class="alert glass-soft">
  <div>
    <h3>{String(alert.title ?? alert.message ?? 'Untitled alert')}</h3>
    <p>{String(alert.message ?? alert.description ?? alert.details ?? 'No description provided')}</p>
  </div>
  <div class="meta">
    <Badge variant={severityToVariant(alert.severity)}>{String(alert.severity ?? 'unknown')}</Badge>
    <small>{String(alert.created_at ?? alert.timestamp ?? '')}</small>
    <Button
      variant="danger"
      size="sm"
      onclick={() => dispatch('resolve', { id: String(alert.id ?? '') })}
    >
      Resolve
    </Button>
  </div>
</article>

<style>
  .alert {
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    padding: 0.85rem;
    display: flex;
    justify-content: space-between;
    gap: 0.9rem;
    align-items: center;
  }

  h3 {
    font-size: 0.92rem;
    margin-bottom: 0.2rem;
  }

  p {
    color: var(--text-muted);
    font-size: 0.8rem;
  }

  .meta {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    justify-content: flex-end;
  }

  small {
    color: var(--text-muted);
    font-size: 0.72rem;
  }

  @media (max-width: 740px) {
    .alert {
      flex-direction: column;
      align-items: stretch;
    }

    .meta {
      justify-content: flex-start;
    }
  }
</style>
