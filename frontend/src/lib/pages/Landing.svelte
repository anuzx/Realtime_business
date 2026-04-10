<script lang="ts">
  import { link } from 'svelte-spa-router'
  import Button from '../components/ui/Button.svelte'
</script>

<section class="landing fade-in">
  <div class="hero glass slide-up">
    <small>AI Security Control Plane</small>
    <h1>PulseGuard monitors risk signals before incidents escalate.</h1>
    <p>
      Track anomalies, resolve alerts, and inspect API telemetry from one premium operator dashboard.
    </p>
    <div class="actions">
      <a href="/login" use:link><Button>Open Dashboard</Button></a>
      <a href="/register" use:link><Button variant="ghost">Create Account</Button></a>
    </div>
  </div>

  <div class="features stagger">
    <article class="glass-soft">
      <h2>Realtime risk score</h2>
      <p>Continuously updated threat posture with trend visibility.</p>
    </article>
    <article class="glass-soft">
      <h2>Actionable alerts</h2>
      <p>Prioritized incidents with one-click resolution workflow.</p>
    </article>
    <article class="glass-soft">
      <h2>Traceable logs</h2>
      <p>Deep log exploration with reliable filtering and analysis.</p>
    </article>
  </div>
</section>

<style>
  .landing {
    width: min(1120px, 100% - 1.4rem);
    margin: 1rem auto 2rem;
    display: grid;
    gap: 1rem;
  }

  .hero {
    border-radius: 28px;
    border: 1px solid var(--border-strong);
    padding: 2rem;
    display: grid;
    gap: 0.8rem;
  }

  .hero small {
    color: #b3beea;
    letter-spacing: 0.13em;
    text-transform: uppercase;
    font-size: 0.7rem;
  }

  .hero h1 {
    font-size: clamp(1.8rem, 4.7vw, 3.2rem);
    max-width: 16ch;
    line-height: 1.06;
  }

  .hero p {
    color: var(--text-muted);
    max-width: 64ch;
  }

  .actions {
    display: flex;
    gap: 0.6rem;
    flex-wrap: wrap;
    margin-top: 0.2rem;
  }

  .features {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.8rem;
  }

  .features article {
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
    padding: 1rem;
  }

  .features h2 {
    font-size: 1rem;
    margin-bottom: 0.35rem;
  }

  .features p {
    color: var(--text-muted);
    font-size: 0.86rem;
  }

  @media (max-width: 900px) {
    .hero {
      padding: 1.2rem;
    }

    .features {
      grid-template-columns: 1fr;
    }
  }
</style>
