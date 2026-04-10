<script lang="ts">
  import { cn } from '../../utils'

  export let id = ''
  export let label = ''
  export let type = 'text'
  export let value = ''
  export let placeholder = ''
  export let error = ''
  export let required = false
  export let disabled = false
  export let className = ''
</script>

<label class={cn('input-wrap', className)}>
  {#if label}
    <span class="input-wrap__label">{label}</span>
  {/if}
  <input
    {id}
    {type}
    {placeholder}
    {required}
    {disabled}
    class:error={Boolean(error)}
    bind:value
    {...$$restProps}
  />
  {#if error}
    <span class="input-wrap__error">{error}</span>
  {/if}
</label>

<style>
  .input-wrap {
    display: flex;
    flex-direction: column;
    gap: 0.38rem;
    width: 100%;
  }

  .input-wrap__label {
    font-size: 0.82rem;
    color: var(--text-muted);
  }

  input {
    width: 100%;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: rgba(20, 20, 20, 0.96);
    color: var(--text);
    padding: 0.64rem 0.72rem;
    outline: none;
    transition: border-color 140ms ease, box-shadow 140ms ease, background-color 140ms ease;
  }

  input::placeholder {
    color: var(--text-subtle);
  }

  input:focus {
    border-color: var(--border-strong);
    background: rgba(26, 26, 26, 0.96);
    box-shadow: 0 0 0 3px var(--focus-ring);
  }

  input.error {
    border-color: rgba(239, 68, 68, 0.75);
    box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.2);
  }

  .input-wrap__error {
    font-size: 0.75rem;
    color: #fda4af;
  }
</style>
