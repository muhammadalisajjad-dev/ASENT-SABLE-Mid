import React, { useEffect, useRef } from 'react';

export const BackgroundGrid: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const mouseRef = useRef({ x: -1000, y: -1000, targetX: -1000, targetY: -1000 });
  const animFrameRef = useRef<number | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current.targetX = e.clientX;
      mouseRef.current.targetY = e.clientY;
      if (prefersReducedMotion) {
        mouseRef.current.x = e.clientX;
        mouseRef.current.y = e.clientY;
      }
    };
    window.addEventListener('mousemove', handleMouseMove);

    const gridSize = 24;
    const baseDotRadius = 1.2;
    const highlightRadius = 180; // Circular region around cursor

    const render = () => {
      if (!prefersReducedMotion) {
        // Eased (lerp) movement towards cursor
        mouseRef.current.x += (mouseRef.current.targetX - mouseRef.current.x) * 0.14;
        mouseRef.current.y += (mouseRef.current.targetY - mouseRef.current.y) * 0.14;
      }

      ctx.clearRect(0, 0, width, height);

      const mx = mouseRef.current.x;
      const my = mouseRef.current.y;

      // Draw dot grid
      for (let x = gridSize / 2; x < width; x += gridSize) {
        for (let y = gridSize / 2; y < height; y += gridSize) {
          const dx = x - mx;
          const dy = y - my;
          const dist = Math.sqrt(dx * dx + dy * dy);

          let alpha = 0.18; // Low transparency background grid
          let radius = baseDotRadius;
          let color = '#8899a6'; // Subtle slate

          if (dist < highlightRadius) {
            // Region around mouse in circular: grid transparency decreases (more visible), turns darker
            const factor = 1 - dist / highlightRadius;
            // Smooth ease out
            const eased = factor * factor;
            alpha = 0.18 + eased * 0.55; // Darker & more prominent
            radius = baseDotRadius + eased * 1.4;
            color = '#2c3e50'; // Darker tone
          }

          ctx.beginPath();
          ctx.arc(x, y, radius, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.globalAlpha = alpha;
          ctx.fill();
        }
      }

      // Draw faint highlight radial glow behind cursor
      if (mx > 0 && my > 0) {
        const grad = ctx.createRadialGradient(mx, my, 0, mx, my, highlightRadius);
        grad.addColorStop(0, 'rgba(44, 62, 80, 0.04)');
        grad.addColorStop(1, 'rgba(44, 62, 80, 0)');
        ctx.fillStyle = grad;
        ctx.globalAlpha = 1;
        ctx.beginPath();
        ctx.arc(mx, my, highlightRadius, 0, Math.PI * 2);
        ctx.fill();
      }

      animFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
      }
    };
  }, []);

  return (
    <div className="network-background-layer" aria-hidden="true">
      {/* Lowest background canvas dot grid */}
      <canvas ref={canvasRef} className="dot-grid-canvas" />

      {/* Network circuit lines overlay matching screenshot with 1-second delay animation */}
      <svg className="network-lines-svg" viewBox="0 0 1600 900" preserveAspectRatio="none">
        <defs>
          <linearGradient id="netGradLeft" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#94a3b8" stopOpacity="0.8" />
            <stop offset="70%" stopColor="#94a3b8" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#cbd5e1" stopOpacity="0.3" />
          </linearGradient>
          <linearGradient id="netGradRight" x1="100%" y1="0%" x2="0%" y2="0%">
            <stop offset="0%" stopColor="#94a3b8" stopOpacity="0.8" />
            <stop offset="70%" stopColor="#94a3b8" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#cbd5e1" stopOpacity="0.3" />
          </linearGradient>
          <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="1.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* LEFT SIDE NETWORK LINES: Moving from left to right */}
        <g className="network-group-left">
          {/* Main top trace */}
          <path
            className="circuit-path path-left-1"
            d="M 0 110 L 260 110 L 330 180 L 520 180"
            fill="none"
            stroke="url(#netGradLeft)"
            strokeWidth="1.6"
          />
          <circle cx="260" cy="110" r="4" className="circuit-node node-left-1" />
          <circle cx="330" cy="180" r="3.5" className="circuit-node node-left-2" />
          <circle cx="520" cy="180" r="4.5" className="circuit-node node-left-3" />

          {/* Upper middle trace */}
          <path
            className="circuit-path path-left-2"
            d="M 0 230 L 140 230 L 210 300 L 460 300"
            fill="none"
            stroke="url(#netGradLeft)"
            strokeWidth="1.6"
          />
          <circle cx="140" cy="230" r="3.5" className="circuit-node node-left-4" />
          <circle cx="210" cy="300" r="4" className="circuit-node node-left-5" />
          <circle cx="460" cy="300" r="4.5" className="circuit-node node-left-6" />

          {/* Lower middle branch */}
          <path
            className="circuit-path path-left-3"
            d="M 0 380 L 80 380 L 150 450 L 390 450 L 440 500 L 580 500"
            fill="none"
            stroke="url(#netGradLeft)"
            strokeWidth="1.6"
          />
          <circle cx="80" cy="380" r="3" className="circuit-node node-left-7" />
          <circle cx="150" cy="450" r="3.5" className="circuit-node node-left-8" />
          <circle cx="390" cy="450" r="4" className="circuit-node node-left-9" />
          <circle cx="580" cy="500" r="4.5" className="circuit-node node-left-10" />

          {/* Bottom left trace */}
          <path
            className="circuit-path path-left-4"
            d="M 0 760 L 220 760 L 300 840 L 480 840"
            fill="none"
            stroke="url(#netGradLeft)"
            strokeWidth="1.6"
          />
          <circle cx="220" cy="760" r="4" className="circuit-node node-left-11" />
          <circle cx="300" cy="840" r="3.5" className="circuit-node node-left-12" />
          <circle cx="480" cy="840" r="4.5" className="circuit-node node-left-13" />
        </g>

        {/* RIGHT SIDE NETWORK LINES: Moving from right to left */}
        <g className="network-group-right">
          {/* Main top right trace */}
          <path
            className="circuit-path path-right-1"
            d="M 1600 110 L 1340 110 L 1270 180 L 1070 180"
            fill="none"
            stroke="url(#netGradRight)"
            strokeWidth="1.6"
          />
          <circle cx="1340" cy="110" r="4" className="circuit-node node-right-1" />
          <circle cx="1270" cy="180" r="3.5" className="circuit-node node-right-2" />
          <circle cx="1070" cy="180" r="4.5" className="circuit-node node-right-3" />

          {/* Upper middle right trace */}
          <path
            className="circuit-path path-right-2"
            d="M 1600 240 L 1450 240 L 1380 310 L 1120 310"
            fill="none"
            stroke="url(#netGradRight)"
            strokeWidth="1.6"
          />
          <circle cx="1450" cy="240" r="3.5" className="circuit-node node-right-4" />
          <circle cx="1380" cy="310" r="4" className="circuit-node node-right-5" />
          <circle cx="1120" cy="310" r="4.5" className="circuit-node node-right-6" />

          {/* Lower middle right branch */}
          <path
            className="circuit-path path-right-3"
            d="M 1600 390 L 1510 390 L 1440 460 L 1190 460 L 1140 510 L 1010 510"
            fill="none"
            stroke="url(#netGradRight)"
            strokeWidth="1.6"
          />
          <circle cx="1510" cy="390" r="3" className="circuit-node node-right-7" />
          <circle cx="1440" cy="460" r="3.5" className="circuit-node node-right-8" />
          <circle cx="1190" cy="460" r="4" className="circuit-node node-right-9" />
          <circle cx="1010" cy="510" r="4.5" className="circuit-node node-right-10" />

          {/* Bottom right trace & star accent */}
          <path
            className="circuit-path path-right-4"
            d="M 1600 760 L 1380 760 L 1300 840 L 1100 840"
            fill="none"
            stroke="url(#netGradRight)"
            strokeWidth="1.6"
          />
          <circle cx="1380" cy="760" r="4" className="circuit-node node-right-11" />
          <circle cx="1300" cy="840" r="3.5" className="circuit-node node-right-12" />
          <circle cx="1100" cy="840" r="4.5" className="circuit-node node-right-13" />

          {/* Geometric 4-point accent star from screenshot */}
          <g transform="translate(1420, 740)" className="accent-star">
            <path
              d="M 0 -14 L 3 -3 L 14 0 L 3 3 L 0 14 L -3 3 L -14 0 L -3 -3 Z"
              fill="#64748b"
              opacity="0.75"
            />
          </g>
        </g>
      </svg>
    </div>
  );
};
