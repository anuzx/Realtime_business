<script lang="ts">
  import Router from 'svelte-spa-router'
  import Landing from './lib/pages/Landing.svelte'
  import Login from './lib/pages/Login.svelte'
  import Register from './lib/pages/Register.svelte'
  import Dashboard from './lib/pages/Dashboard.svelte'
  import Logs from './lib/pages/Logs.svelte'
  import Alerts from './lib/pages/Alerts.svelte'
  import ApiKeys from './lib/pages/ApiKeys.svelte'
  import Docs from './lib/pages/Docs.svelte'
  import NotFound from './lib/pages/NotFound.svelte'

  const routes = {
    '/': Landing,
    '/login': Login,
    '/register': Register,
    '/dashboard': Dashboard,
    '/logs': Logs,
    '/alerts': Alerts,
    '/api-keys': ApiKeys,
    '/docs': Docs,
    '*': NotFound,
  }
</script>

<Router {routes} />
