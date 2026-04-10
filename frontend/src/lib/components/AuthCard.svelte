<script lang="ts">
  export let title = ''
  export let subtitle = ''
</script>

<section class="auth-shell">
  <div class="auth-card glass slide-up">
    <div class="auth-card__head">
      <h1>{title}</h1>
      <p>{subtitle}</p>
    </div>
    <slot />
  </div>
</section>

<style>
  .auth-shell {
    width: min(460px, 100% - 1.2rem);
    margin: 4.2rem auto;
  }

  .auth-card {
    border-radius: 22px;
    border: 1px solid var(--border-strong);
    padding: 1.4rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .auth-card__head h1 {
    font-size: 1.35rem;
    margin-bottom: 0.28rem;
  }

  .auth-card__head p {
    color: var(--text-muted);
    font-size: 0.9rem;
  }
</style>
