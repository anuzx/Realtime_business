<script lang="ts">
  import { onDestroy } from 'svelte'
  import { link } from 'svelte-spa-router'
  import { Terminal } from 'svelte-bash'
  import Button from '../components/ui/Button.svelte'
  import Card from '../components/ui/Card.svelte'

  type Language = 'python'

  const snippets: Record<Language, { label: string; fileName: string; code: string }> = {
    python: {
      label: 'Python',
      fileName: 'fastapi_setup.py',
      code: `from fastapi import FastAPI
from securelog_sdk import instrument

app = FastAPI()

instrument(
    app,
    api_key="sk_your_key_here",
    base_url="https://securelog.pulseguard.com",
)`,
    },
  }

  const languages: Language[] = ['python']

  const terminalTheme = {
    background: '#000000',
    foreground: '#f5f5f5',
    prompt: '#ffffff',
    cursor: '#ffffff',
  }

  let activeLanguage: Language = 'python'
  let copiedLanguage: Language | null = null
  let copiedTimeout: ReturnType<typeof setTimeout> | null = null

  $: activeSnippet = snippets[activeLanguage]

  $: terminalStructure = {
    examples: {
      'fastapi_setup.py': snippets.python.code,
    },
  }

  $: terminalAutoplay = [
    { command: 'pip install securelog-sdk' },
    { command: 'cd examples' },
    { command: `cat ${activeSnippet.fileName}` },
  ]

  async function copyActiveSnippet(): Promise<void> {
    try {
      if (navigator?.clipboard) {
        await navigator.clipboard.writeText(activeSnippet.code)
      } else {
        const textArea = document.createElement('textarea')
        textArea.value = activeSnippet.code
        textArea.style.position = 'fixed'
        textArea.style.opacity = '0'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()
        document.execCommand('copy')
        document.body.removeChild(textArea)
      }

      copiedLanguage = activeLanguage

      if (copiedTimeout) {
        clearTimeout(copiedTimeout)
      }

      copiedTimeout = setTimeout(() => {
        copiedLanguage = null
      }, 1800)
    } catch {
      copiedLanguage = null
    }
  }

  onDestroy(() => {
    if (copiedTimeout) {
      clearTimeout(copiedTimeout)
    }
  })
</script>

<section class="docs-page fade-in">
  <header class="docs-header">
    <div>
      <p class="eyebrow">Developer Documentation</p>
      <h1>Python FastAPI integration guide</h1>
      <p class="subtitle">
        Install <code>securelog-sdk</code> and add one instrumentation call inside your existing
        FastAPI app.
      </p>
    </div>

    <div class="header-actions">
      <a href="/" use:link class="back-home">Back to landing</a>
      <Button variant="secondary" size="sm" onclick={copyActiveSnippet}>
        {copiedLanguage === activeLanguage ? 'Copied' : 'Copy code'}
      </Button>
    </div>
  </header>

  <div class="docs-grid">
    <Card
      title="Python snippet"
      subtitle="Run `pip install securelog-sdk`, then copy this setup block."
      className="snippet-card"
    >
      <div class="language-switch" role="tablist" aria-label="Snippet language">
        {#each languages as language}
          <button
            type="button"
            role="tab"
            class="lang-pill"
            class:active={activeLanguage === language}
            aria-selected={activeLanguage === language}
            onclick={() => {
              activeLanguage = language
            }}
          >
            {snippets[language].label}
          </button>
        {/each}
      </div>

      <div class="mac-terminal" aria-live="polite">
        <div class="terminal-bar">
          <div class="lights" aria-hidden="true">
            <span class="light red"></span>
            <span class="light yellow"></span>
            <span class="light green"></span>
          </div>
          <span>{activeSnippet.fileName}</span>
        </div>
        <pre><code>{activeSnippet.code}</code></pre>
      </div>
    </Card>

    <Card
      title="Interactive terminal"
      subtitle="Python-only walkthrough with install and FastAPI setup commands."
      className="terminal-card"
    >
      <div class="terminal-frame">
        {#key activeLanguage}
          <Terminal
            structure={terminalStructure}
            autoplay={terminalAutoplay}
            autoplayLoop={false}
            typingSpeed={25}
            user="pulseguard"
            theme={terminalTheme}
            syntaxHighlight
            ghostCompletion
            style="height: 330px;"
          />
        {/key}
      </div>
    </Card>
  </div>
</section>

<style>
  .docs-page {
    min-height: 100svh;
    width: min(1240px, 100% - 2rem);
    margin: 1rem auto 1.5rem;
    padding: 1.2rem;
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 24px;
    background:
      radial-gradient(circle at 8% 0%, rgba(255, 255, 255, 0.1), transparent 28%),
      radial-gradient(circle at 95% 12%, rgba(255, 255, 255, 0.08), transparent 24%),
      #000000;
    color: #f5f5f5;
    display: grid;
    align-content: start;
    gap: 1rem;
    font-family: 'Geist', sans-serif;
  }

  .docs-header {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    align-items: flex-end;
  }

  .eyebrow {
    font-size: 0.7rem;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: #a1a1aa;
    margin-bottom: 0.4rem;
  }

  h1 {
    font-size: clamp(1.4rem, 2.9vw, 2.5rem);
    line-height: 1.1;
    margin-bottom: 0.45rem;
  }

  .subtitle {
    color: #a1a1aa;
    max-width: 62ch;
    font-size: 0.95rem;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 0.65rem;
  }

  .back-home {
    font-size: 0.82rem;
    color: #d4d4d8;
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 999px;
    padding: 0.36rem 0.75rem;
    transition: background-color 160ms ease;
  }

  .back-home:hover {
    background: rgba(255, 255, 255, 0.08);
  }

  .docs-grid {
    display: grid;
    grid-template-columns: 1.15fr 1fr;
    gap: 1rem;
  }

  .docs-grid > :global(*) {
    min-width: 0;
  }

  :global(.snippet-card),
  :global(.terminal-card) {
    background: rgba(8, 8, 8, 0.85);
    border-color: rgba(255, 255, 255, 0.14);
  }

  .language-switch {
    display: flex;
    flex-wrap: wrap;
    gap: 0.52rem;
    margin-bottom: 0.8rem;
  }

  .lang-pill {
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: transparent;
    color: #d4d4d8;
    border-radius: 999px;
    padding: 0.32rem 0.72rem;
    font-size: 0.76rem;
    letter-spacing: 0.02em;
    cursor: pointer;
    transition: all 140ms ease;
  }

  .lang-pill:hover {
    border-color: rgba(255, 255, 255, 0.4);
    color: #ffffff;
  }

  .lang-pill.active {
    background: #f5f5f5;
    color: #000000;
    border-color: #f5f5f5;
    font-weight: 600;
  }

  .mac-terminal {
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 16px;
    overflow: hidden;
    background: #000000;
  }

  .terminal-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.55rem 0.8rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.14);
    color: #a1a1aa;
    font-size: 0.72rem;
    letter-spacing: 0.03em;
  }

  .lights {
    display: flex;
    gap: 0.35rem;
  }

  .light {
    width: 0.62rem;
    height: 0.62rem;
    border-radius: 999px;
    display: inline-block;
  }

  .light.red {
    background: #ff5f57;
  }

  .light.yellow {
    background: #febc2e;
  }

  .light.green {
    background: #28c840;
  }

  pre {
    margin: 0;
    padding: 1rem;
    max-height: 460px;
    overflow: auto;
    background: #000000;
  }

  code {
    color: #f5f5f5;
    font-family: 'Geist Mono', 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.8rem;
    line-height: 1.5;
    white-space: pre;
  }

  .terminal-frame {
    border-radius: 16px;
    overflow: hidden;
    border: 1px solid rgba(255, 255, 255, 0.14);
    background: #000;
  }

  .terminal-frame :global(.svelte-bash-terminal) {
    border-radius: 0;
    box-shadow: none;
  }

  @media (max-width: 980px) {
    .docs-grid {
      grid-template-columns: 1fr;
    }
  }

  @media (max-width: 640px) {
    .docs-page {
      width: min(1240px, 100% - 1rem);
      padding: 0.85rem;
      border-radius: 18px;
    }

    .header-actions {
      width: 100%;
      justify-content: space-between;
    }
  }
</style>
