<script lang="ts">
  export let score = 0

  $: clamped = Math.max(0, Math.min(100, score))
  $: angle = (clamped / 100) * 360
  $: tone =
    clamped >= 75
      ? 'var(--danger)'
      : clamped >= 45
        ? 'var(--warning)'
        : 'var(--success)'
</script>

<section class="gauge glass-soft slide-up">
  <div class="ring" style={`--angle:${angle}deg; --tone:${tone};`}>
    <div class="ring__inner">
      <span>Risk score</span>
      <strong>{clamped.toFixed(0)}</strong>
      <small>/100</small>
    </div>
  </div>
</section>

<style>
  .gauge {
    border-radius: var(--radius-lg);
    padding: 1.2rem;
    display: grid;
    place-items: center;
  }

  .ring {
    width: min(230px, 62vw);
    aspect-ratio: 1;
    border-radius: 50%;
    background:
      radial-gradient(circle at center, rgba(12, 19, 37, 1) 57%, transparent 58%),
      conic-gradient(var(--tone) var(--angle), rgba(159, 176, 214, 0.16) 0deg);
    display: grid;
    place-items: center;
    border: 1px solid var(--border);
    box-shadow: inset 0 0 30px rgba(0, 0, 0, 0.3);
  }

  .ring__inner {
    text-align: center;
    display: grid;
    gap: 0.16rem;
  }

  span {
    color: var(--text-muted);
    font-size: 0.76rem;
  }

  strong {
    font-size: 2rem;
    line-height: 1;
  }

  small {
    color: var(--text-muted);
  }
</style>
