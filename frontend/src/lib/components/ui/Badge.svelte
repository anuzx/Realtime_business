<script lang="ts">
  import { cn } from '../../utils'

  export let variant: 'success' | 'warning' | 'error' | 'info' | 'neutral' = 'neutral'
  export let className = ''
</script>

<span class={cn('badge', `badge--${variant}`, className)}>
  <slot />
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    padding: 0.22rem 0.52rem;
    border: 1px solid transparent;
  }

  .badge--neutral {
    color: #d4d4d8;
    background: rgba(255, 255, 255, 0.06);
    border-color: rgba(255, 255, 255, 0.14);
  }

  .badge--success {
    color: #bbf7d0;
    background: rgba(16, 185, 129, 0.18);
    border-color: rgba(16, 185, 129, 0.34);
  }

  .badge--warning {
    color: #ffe3bb;
    background: rgba(255, 181, 74, 0.2);
    border-color: rgba(255, 181, 74, 0.32);
  }

  .badge--error {
    color: #fecaca;
    background: rgba(239, 68, 68, 0.18);
    border-color: rgba(239, 68, 68, 0.34);
  }

  .badge--info {
    color: #dbeafe;
    background: rgba(59, 130, 246, 0.18);
    border-color: rgba(59, 130, 246, 0.34);
  }
</style>
