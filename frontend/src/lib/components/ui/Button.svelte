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
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    padding: 0.58rem 1rem;
    font-size: 0.92rem;
    font-weight: 600;
    color: var(--text);
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
    background: linear-gradient(135deg, var(--accent), var(--accent-strong));
    box-shadow: 0 12px 24px rgba(91, 110, 255, 0.32);
  }

  .btn--primary:hover:not(:disabled) {
    box-shadow: 0 16px 28px rgba(91, 110, 255, 0.4);
  }

  .btn--secondary {
    background: rgba(99, 211, 255, 0.14);
    border-color: rgba(99, 211, 255, 0.32);
  }

  .btn--ghost {
    background: transparent;
    border-color: var(--border);
  }

  .btn--ghost:hover:not(:disabled) {
    border-color: var(--border-strong);
    background: rgba(159, 176, 214, 0.08);
  }

  .btn--danger {
    background: rgba(255, 107, 135, 0.16);
    border-color: rgba(255, 107, 135, 0.32);
    color: #ffd8e2;
  }
</style>
