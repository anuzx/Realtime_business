<script lang="ts">
  import Navbar from './Navbar.svelte'
  import Sidebar from './Sidebar.svelte'
</script>

<div class="layout fade-in">
  <Navbar />
  <div class="layout__body">
    <Sidebar />
    <main>
      <slot />
    </main>
  </div>
</div>

<style>
  .layout {
    width: min(1320px, 100% - 2rem);
    margin: 1rem auto;
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    padding-bottom: 1rem;
  }

  .layout__body {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.8rem;
    min-height: calc(100svh - 112px);
  }

  main {
    min-width: 0;
  }

  @media (max-width: 960px) {
    .layout {
      width: min(1320px, 100% - 1rem);
      margin-top: 0.6rem;
    }

    .layout__body {
      grid-template-columns: 1fr;
    }
  }
</style>
