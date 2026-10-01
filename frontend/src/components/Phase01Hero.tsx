import React, { useState } from 'react';
import { ShieldCheck, ChevronDown, Lock, CheckCircle2, Cpu, ArrowRight } from 'lucide-react';

interface Phase01HeroProps {
  onScrollToPhase2: () => void;
}

export const Phase01Hero: React.FC<Phase01HeroProps> = ({ onScrollToPhase2 }) => {
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 16;
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * -16;
    setTilt({ x, y });
  };

  const handleMouseLeave = () => {
    setTilt({ x: 0, y: 0 });
  };

  return (
    <section className="phase01-hero-container">
      <div 
        className="hero-center-content"
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
      >
        {/* Aesthetic 3D Holographic Security Seal */}
        <div 
          className="hero-3d-badge"
          style={{
            transform: `perspective(800px) rotateY(${tilt.x}deg) rotateX(${tilt.y}deg)`
          }}
        >
          <div className="badge-inner-glow" />
          <div className="badge-shield-wrapper">
            <ShieldCheck className="shield-icon" size={32} />
          </div>
          <span className="badge-text">AI-CHANGE ASSURANCE GATE</span>
        </div>

        {/* Big Title */}
        <h1 className="hero-main-title">
          AGENT SENTINEL
        </h1>

        {/* Subtitle in little faded manner and Italics */}
        <p className="hero-main-subtitle">
          Built for Real Impact and Execution
        </p>

        {/* Value proposition narrative */}
        <p className="hero-description">
          An AI-native security assurance gate positioned directly between an AI agent&apos;s proposed change
          and the point where that change is trusted, merged, or deployed. It intercepts and routes candidate
          modifications to <strong>CAVR</strong> (dependency trust), <strong>SABLE</strong> (Terraform boundaries),
          and <strong>SATRA</strong> (test integrity), aggregating real evidence into deterministic decisions.
        </p>

        {/* Aesthetic Mini Stats / Feature Highlights */}
        <div className="hero-feature-pills">
          <div className="feature-pill-card">
            <Cpu size={15} className="pill-icon" />
            <div>
              <strong>Three-Layer Interception</strong>
              <span>Local PEP 503 · pip shim · manifest parser</span>
            </div>
          </div>

          <div className="feature-pill-card">
            <Lock size={15} className="pill-icon" />
            <div>
              <strong>Hostile Code Sandbox</strong>
              <span>Hardened runtime · honeytokens · sys.addaudithook</span>
            </div>
          </div>

          <div className="feature-pill-card">
            <CheckCircle2 size={15} className="pill-icon" />
            <div>
              <strong>Deterministic Gates</strong>
              <span>Accept · Review · Block with honest verification</span>
            </div>
          </div>
        </div>

        {/* Interactive Scroll Down Button */}
        <div className="hero-cta-wrapper">
          <button 
            className="explore-gate-button"
            onClick={onScrollToPhase2}
            id="explore-modules-btn"
          >
            <span>Explore Assurance Modules</span>
            <ChevronDown size={18} className="bounce-arrow" />
          </button>
        </div>
      </div>
    </section>
  );
};
