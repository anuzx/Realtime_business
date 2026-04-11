<script lang="ts">
  import { onMount } from 'svelte';
  import { link } from 'svelte-spa-router';

  // State for the Footer Clock
  let time = '';
  let greeting = '';

  function updateTime() {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    time = `${hours}:${minutes}:${seconds}`;

    const hr = now.getHours();
    if (hr >= 5 && hr < 12) greeting = 'Good Morning';
    else if (hr >= 12 && hr < 18) greeting = 'Good Afternoon';
    else greeting = 'Good Evening';
  }

  onMount(() => {
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  });

  function scrollToFooter(event: MouseEvent): void {
    event.preventDefault();
    const footer = document.getElementById('about-footer');
    if (footer) {
      footer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

</script>

<div class="app-container">
  <!-- Fixed Floating Header Section -->
  <header class="main-header glass slide-down">
    <div class="header-inner">
      <div class="header-left">
        <div class="logo">
          <span class="logo-text">PULSEGUARD</span>
          <div class="status-dot"></div>
        </div>
        <nav class="header-nav">
          <a href="/" use:link class="nav-link">Home</a>
          <a href="/docs" use:link class="nav-link">Python Docs</a>
          <a href="#about-footer" class="nav-link" onclick={scrollToFooter}>About</a>
        </nav>
      </div>

      <div class="header-right">
        <div class="auth-actions">
          <a href="/login" use:link class="btn btn-primary btn-sm">Open Dashboard</a>
          <a href="/register" use:link class="btn btn-ghost btn-sm">Create Account</a>
        </div>
      </div>
    </div>
  </header>

  <!-- Landing Section -->
  <section class="landing fade-in">
    <div class="hero glass slide-up">
      <video
        src="/src/assets/dodo.mp4"
        autoplay
        loop
        muted
        playsinline
        class="hero-video"
      ></video>
      <div class="hero-video-overlay"></div>
      <small>AI Security Control Plane</small>
      <h1>PulseGuard monitors risk signals before incidents escalate.</h1>
      <p>
        Track anomalies, resolve alerts, and inspect API telemetry from one premium operator dashboard.
      </p>
      <div class="hero-status">
        <span class="status-badge">System Status: Optimal</span>
        <span class="latency-badge">Avg Latency: 12ms</span>
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

  <!-- Custom Integrated Footer -->
  <footer id="about-footer" class="footer-root">
    <div class="footer-content">
      
      <!-- Footer Top Row -->
      <div class="footer-grid">
        <!-- Logo Section -->
        <div class="brand-col">
          <div class="logo">
             <span class="logo-text">PULSEGUARD</span>
             <div class="status-dot"></div>
          </div>
          <p class="brand-desc">Precision monitoring for neural networks and API architectures.</p>
        </div>

        <!-- Links: Platform -->
        <div class="link-group">
          <div class="footer-label">Platform</div>
          <nav>
            <a href="#dash" class="nav-link">Dashboard</a>
            <a href="#telemetry" class="nav-link">Telemetry</a>
            <a href="#anomalies" class="nav-link">Anomalies</a>
          </nav>
        </div>

        <!-- Links: Resources -->
        <div class="link-group">
          <div class="footer-label">Resources</div>
          <nav>
            <a href="/docs" use:link class="nav-link">Python Documentation</a>
            <a href="#security" class="nav-link">Trust Center</a>
            <a href="#api" class="nav-link">API Status</a>
          </nav>
        </div>

        <!-- Links: Connect -->
        <div class="link-group">
          <div class="footer-label">Connect</div>
          <nav>
            <a href="https://linkedin.com" target="_blank" class="nav-link">LinkedIn</a>
            <a href="https://twitter.com" target="_blank" class="nav-link">Twitter</a>
            <a href="https://github.com" target="_blank" class="nav-link">GitHub</a>
          </nav>
        </div>
      </div>

      <!-- Contact Section -->
      <div class="contact-section">
        <div class="footer-label">Security Operations</div>
        <a href="mailto:ops@pulseguard.ai" class="nav-link email-link">ops@pulseguard.ai</a>
      </div>

      <!-- Bottom Row -->
      <div class="footer-bottom">
        <div class="copyright">
          <span class="muted">©2026 PulseGuard Systems</span>
        </div>

        <div class="branding-link">
          <div class="squiggly-container">
            <svg class="animate-squiggly" width="823" height="7" viewBox="0 0 823 7" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M1 3.5C5.2.2 9.4.2 13.7 3.5c4.2 3.3 8.4 3.3 12.6 0C30.6.2 34.8.2 39 3.5c4.2 3.3 8.5 3.3 12.7 0C55.9.2 60 .2 64.3 3.5c4.3 3.3 8.5 3.3 12.7 0 4.2-3.3 8.5-3.3 12.7 0 4.2 3.3 8.4 3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3 3.3 8.5 3.3 12.7 0 4.2-3.3 8.4-3.3 12.7 0 4.2 3.3 8.4 3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2 3.3 8.5 3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3 3.3 8.5 3.3 12.7 0 4.2-3.3 8.5-3.3 12.7 0 4.2 3.3 8.4 3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.2 3.3 8.5 3.3 12.7 0 4.2-3.3 8.4-3.3 12.7 0 4.2 3.3 8.4 3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2 3.3 8.4 3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.6 0 4.2-3.3 8.4-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.6 0 4.3-3.3 8.5-3.3 12.7 0 4.2-3.3 8.4-3.3 12.7 0" stroke="currentColor"></path>
            </svg>
          </div>
          <div class="footer-link-box">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12.75 4C12.75 3.58579 12.4142 3.25 12 3.25C11.5858 3.25 11.25 3.58579 11.25 4H12.75ZM11.25 10C11.25 10.4142 11.5858 10.75 12 10.75C12.4142 10.75 12.75 10.4142 12.75 10H11.25ZM11.25 4V10H12.75V4H11.25Z" fill="currentColor"></path>
              <path d="M12.5303 4.53033C12.8232 4.23744 12.8232 3.76256 12.5303 3.46967C12.2374 3.17678 11.7626 3.17678 11.4697 3.46967L12.5303 4.53033ZM3.46967 11.4697C3.17678 11.7626 3.17678 12.2374 3.46967 12.5303C3.76256 12.8232 4.23744 12.8232 4.53033 12.5303L3.46967 11.4697ZM11.4697 3.46967L3.46967 11.4697L4.53033 12.5303L12.5303 4.53033L11.4697 3.46967Z" fill="currentColor"></path>
            </svg>
            <a href="https://pulseguard.ai" class="nav-link">PulseGuard.ai</a>
          </div>
        </div>

        <div class="footer-clock">
          <span class="mono-time">{time}</span>
          <span class="greeting-text">{greeting}</span>
        </div>
      </div>
    </div>
  </footer>
</div>

<style>
  :root {
    --bg: #050505;
    --text: #f0f0f0;
    --text-muted: #a1a1aa;
    --border: #262626;
    --border-strong: #3f3f46;
    --radius-lg: 20px;
    --font-sans: 'Inter', -apple-system, sans-serif;
    --font-mono: 'JetBrains Mono', monospace;
    --header-height: 64px;
  }

  .app-container {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-sans);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    padding-top: 1.5rem; /* Space for floating header */
  }

  /* Fixed Floating Header Section */
  .main-header {
    position: fixed;
    top: 1.5rem;
    left: 50%;
    transform: translateX(-50%);
    width: min(1200px, 95%);
    height: var(--header-height);
    z-index: 100;
    border: 1px solid var(--border);
    border-radius: 100px;
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    background: rgba(15, 15, 15, 0.7);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
  }

  .header-inner {
    width: 100%;
    height: 100%;
    padding: 0 1.5rem 0 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .header-left, .header-right {
    display: flex;
    align-items: center;
    gap: 3rem;
  }

  .header-nav {
    display: flex;
    gap: 2rem;
  }

  .header-nav .nav-link {
    font-size: 0.85rem;
    color: var(--text-muted);
    font-weight: 500;
    margin-bottom: 0;
    letter-spacing: 0.01em;
  }

  .header-nav .nav-link:hover {
    color: var(--text);
  }

  .auth-actions {
    display: flex;
    gap: 0.6rem;
  }

  /* Landing Page Styles */
  .landing {
    width: min(1120px, 100% - 2.8rem);
    margin: 6rem auto 4rem;
    display: grid;
    gap: 1.5rem;
    flex: 1;
  }

  .hero {
    position: relative;
    overflow: hidden;
    border-radius: 28px;
    border: 1px solid var(--border-strong);
    padding: 3.5rem 3rem;
    display: grid;
    gap: 1.2rem;
  }

  .hero small {
    color: #d4d4d8;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .hero h1 {
    font-size: clamp(2.2rem, 5.5vw, 4rem);
    max-width: 18ch;
    line-height: 1.05;
    font-weight: 500;
    letter-spacing: -0.03em;
  }

  .hero p {
    color: var(--text-muted);
    max-width: 55ch;
    font-size: 1.2rem;
    line-height: 1.5;
  }

  .hero-status {
    display: flex;
    gap: 1rem;
    margin-top: 1rem;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    text-transform: uppercase;
  }

  .status-badge {
    color: #10b981;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .latency-badge {
    color: #737373;
  }

  .btn {
    padding: 0.8rem 1.6rem;
    border-radius: 12px;
    font-size: 0.95rem;
    font-weight: 500;
    text-decoration: none;
    transition: all 0.2s ease;
    white-space: nowrap;
  }

  .btn-sm {
    padding: 0.5rem 1.2rem;
    font-size: 0.8rem;
    border-radius: 100px;
  }

  .btn-primary {
    background: var(--text);
    color: var(--bg);
  }

  .btn-primary:hover {
    background: #fff;
    transform: translateY(-1px);
  }

  .btn-ghost {
    border: 1px solid var(--border);
    color: var(--text);
  }

  .btn-ghost:hover {
    background: rgba(255, 255, 255, 0.05);
    border-color: var(--border-strong);
  }

  .features {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
  }

  .features article {
    background: rgba(255, 255, 255, 0.02);
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
    padding: 1.5rem;
    transition: border-color 0.3s ease;
  }

  .features article:hover {
    border-color: var(--border-strong);
  }

  .features h2 {
    font-size: 1rem;
    margin-bottom: 0.5rem;
    font-weight: 500;
  }

  .features p {
    color: var(--text-muted);
    font-size: 0.9rem;
    line-height: 1.4;
  }

  /* Hero Video Background */
  .hero-video {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    object-fit: cover;
    z-index: 0;
    filter: brightness(0.65) saturate(0.6);
  }

  .hero-video-overlay {
    position: absolute;
    inset: 0;
    z-index: 1;
    background: radial-gradient(
      ellipse at 50% 100%,
      rgba(5, 5, 5, 0.6) 0%,
      rgba(5, 5, 5, 0.15) 60%,
      transparent 100%
    );
    pointer-events: none;
  }

  .hero small,
  .hero h1,
  .hero p,
  .hero-status {
    position: relative;
    z-index: 2;
  }

  /* Footer Styles */
  .footer-root {
    border-top: 1px solid var(--border);
    padding: 4rem 0 2rem;
    background: linear-gradient(to bottom, transparent, rgba(255, 255, 255, 0.02));
  }

  .footer-content {
    width: min(1200px, 100% - 3rem);
    margin: 0 auto;
  }

  .footer-grid {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr;
    gap: 3rem;
    margin-bottom: 3rem;
  }

  .footer-label {
    font-family: var(--font-mono);
    text-transform: uppercase;
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    color: #737373;
    margin-bottom: 1.5rem;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .logo-text {
    font-weight: 600;
    letter-spacing: 0.05em;
    font-size: 1.1rem;
  }

  .status-dot {
    width: 6px;
    height: 6px;
    background: #10b981;
    border-radius: 50%;
    box-shadow: 0 0 8px #10b981;
  }

  .brand-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    max-width: 25ch;
    margin-top: 1rem;
  }

  .nav-link {
    display: block;
    color: var(--text);
    text-decoration: none;
    font-size: 0.85rem;
    margin-bottom: 0.6rem;
    position: relative;
    width: fit-content;
    transition: color 0.3s;
  }

  .nav-link::after {
    content: '';
    position: absolute;
    width: 0;
    height: 1px;
    bottom: -2px;
    left: 0;
    background: currentColor;
    transition: width 0.3s;
  }

  .nav-link:hover::after {
    width: 100%;
  }

  .email-link {
    font-size: 1rem;
  }

  .contact-section {
    margin-bottom: 4rem;
  }

  .footer-bottom {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-top: 2rem;
    border-top: 1px solid var(--border);
  }

  .muted {
    color: #737373;
    font-size: 0.85rem;
  }

  .branding-link {
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }

  .squiggly-container {
    width: 60px;
    overflow: hidden;
    opacity: 0.4;
  }

  .footer-link-box {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .footer-clock {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    font-family: var(--font-mono);
  }

  .mono-time {
    font-size: 0.8rem;
  }

  .greeting-text {
    font-size: 0.6rem;
    color: #737373;
    text-transform: uppercase;
    margin-top: 0.2rem;
  }

  @keyframes squiggly {
    from { transform: translateX(0); }
    to { transform: translateX(-20px); }
  }

  .animate-squiggly {
    animation: squiggly 2s linear infinite;
  }

  /* Responsive Adjustments */
  @media (max-width: 1024px) {
    .header-left {
      gap: 1.5rem;
    }
    .header-nav {
      gap: 1.5rem;
    }
  }

  @media (max-width: 900px) {
    .header-nav {
      display: none;
    }
    
    .features {
      grid-template-columns: 1fr;
    }
    
    .footer-grid {
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
    }

    .brand-col {
      grid-column: span 2;
    }

    .hero {
      padding: 2rem;
    }

    .footer-bottom {
      flex-direction: column;
      align-items: flex-start;
      gap: 2rem;
    }

    .footer-clock {
      align-items: flex-start;
    }
  }

  @media (max-width: 600px) {
    .header-inner {
      padding: 0 1rem;
    }
    .auth-actions .btn-ghost {
      display: none;
    }
  }

  /* Entrance Animations */
  .fade-in {
    animation: fadeIn 0.8s ease-out forwards;
  }

  .slide-up {
    animation: slideUp 0.6s ease-out forwards;
  }

  .slide-down {
    animation: slideDown 0.6s ease-out forwards;
  }

  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  @keyframes slideUp {
    from { transform: translateY(20px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }

  @keyframes slideDown {
    from { transform: translate(-50%, -20px); opacity: 0; }
    to { transform: translate(-50%, 0); opacity: 1; }
  }
</style>
