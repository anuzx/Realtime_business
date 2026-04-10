<script lang="ts">
  import { cn } from '../../utils'

  export let variant: 'primary' | 'secondary' | 'ghost' | 'danger' = 'primary'
  export let size: 'sm' | 'md' = 'md'
  export let type: 'button' | 'submit' | 'reset' = 'button'
  export let disabled = false
  export let fullWidth = false
  export let className = ''
</script>

<button
  {type}
  {disabled}
  class={cn('btn', `btn--${variant}`, `btn--${size}`, fullWidth && 'btn--full', className)}
  {...$$restProps}
>
  <slot />
</button>

<style>
  .btn {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.58rem 1rem;
    font-size: 0.92rem;
    font-weight: 500;
    line-height: 1;
    color: var(--text);
    background: var(--surface-muted);
    cursor: pointer;
    transition: transform 160ms ease, border-color 180ms ease, background-color 180ms ease,
      box-shadow 180ms ease;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.4rem;
  }

  .btn:hover:not(:disabled) {
    transform: translateY(-1px);
  }

  .btn:focus-visible {
    outline: none;
    border-color: var(--border-strong);
    box-shadow: 0 0 0 3px var(--focus-ring);
  }

  .btn:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }

  .btn--full {
    width: 100%;
  }

  .btn--sm {
    padding: 0.45rem 0.78rem;
    font-size: 0.82rem;
  }

  .btn--primary {
    color: var(--accent-contrast);
    border-color: rgba(255, 255, 255, 0.9);
    background: linear-gradient(180deg, var(--accent-strong), var(--accent));
    box-shadow: 0 8px 20px rgba(255, 255, 255, 0.1);
  }

  .btn--primary:hover:not(:disabled) {
    box-shadow: 0 12px 24px rgba(255, 255, 255, 0.14);
  }

  .btn--secondary {
    background: rgba(255, 255, 255, 0.08);
    border-color: var(--border-strong);
  }

  .btn--ghost {
    background: transparent;
    border-color: var(--border);
  }

  .btn--ghost:hover:not(:disabled) {
    border-color: var(--border-strong);
    background: rgba(255, 255, 255, 0.05);
  }

  .btn--danger {
    background: var(--danger-soft);
    border-color: rgba(239, 68, 68, 0.45);
    color: #fecaca;
  }
</style>
