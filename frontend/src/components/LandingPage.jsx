import { ArrowRight, ShieldCheck } from "lucide-react";

export default function LandingPage({ onEnter }) {
  return (
    <main className="landing-shell pixel-grid">
      <div className="landing-orbit orbit-one" />
      <div className="landing-orbit orbit-two" />
      <section className="landing-card retro-shadow">
        <div className="shield-mark">
          <ShieldCheck size={68} strokeWidth={1.5} />
        </div>
        <p className="eyebrow">PRE-DEPLOYMENT CONTROL ROOM</p>
        <h1 className="pixel-title landing-title">SPEC GUARD</h1>
        <p className="landing-tagline">AI-powered pre-deployment security auditor &amp; governance gatekeeper.</p>
        <button onClick={onEnter} className="primary-button lime-glow">
          [ ENTER WORKSPACE ] <ArrowRight size={17} />
        </button>
        <p className="landing-note">CODE · CONTRACTS · INFRASTRUCTURE</p>
      </section>
    </main>
  );
}
