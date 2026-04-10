<script lang="ts">
  import { link } from 'svelte-spa-router'
  import Button from '../components/ui/Button.svelte'
</script>

<section class="not-found glass slide-up">
  <p class="code">404</p>
  <h1>Page not found</h1>
  <p>The route you requested does not exist in PulseGuard.</p>
  <a href="/" use:link><Button>Return home</Button></a>
</section>

<style>
  .not-found {
    width: min(520px, 100% - 1.2rem);
    margin: 4rem auto;
    border-radius: 20px;
    border: 1px solid var(--border-strong);
    padding: 1.8rem;
    display: grid;
    gap: 0.5rem;
    text-align: center;
    justify-items: center;
  }

  .code {
    color: #d4d4d8;
    letter-spacing: 0.24em;
    font-size: 0.75rem;
  }

  h1 {
    font-size: 1.6rem;
  }

  p {
    color: var(--text-muted);
  }
</style>
