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
    color: #c7d2f1;
    background: rgba(159, 176, 214, 0.14);
    border-color: rgba(159, 176, 214, 0.24);
  }

  .badge--success {
    color: #b9ffd8;
    background: rgba(61, 219, 154, 0.2);
    border-color: rgba(61, 219, 154, 0.32);
  }

  .badge--warning {
    color: #ffe3bb;
    background: rgba(255, 181, 74, 0.2);
    border-color: rgba(255, 181, 74, 0.32);
  }

  .badge--error {
    color: #ffc8d5;
    background: rgba(255, 107, 135, 0.2);
    border-color: rgba(255, 107, 135, 0.32);
  }

  .badge--info {
    color: #c8f0ff;
    background: rgba(99, 211, 255, 0.18);
    border-color: rgba(99, 211, 255, 0.32);
  }
</style>
