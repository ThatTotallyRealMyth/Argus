import React, { useEffect, useRef } from "react";

export default function NetworkCanvas({ compact = false }) {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    const context = canvas.getContext("2d");
    let frame;
    let width = 0;
    let height = 0;
    let pointer = { x: -9999, y: -9999 };
    let nodes = [];
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    function resize() {
      const rect = canvas.getBoundingClientRect();
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width; height = rect.height;
      canvas.width = Math.max(1, Math.floor(width * ratio)); canvas.height = Math.max(1, Math.floor(height * ratio));
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      const count = compact ? Math.max(20, Math.floor(width / 24)) : Math.max(36, Math.floor((width * height) / 15000));
      nodes = Array.from({ length: count }, (_, index) => ({ x: ((index * 97) % 101) / 101 * width, y: ((index * 53) % 89) / 89 * height, vx: ((index % 5) - 2) * 0.045, vy: (((index * 3) % 5) - 2) * 0.035, size: index % 11 === 0 ? 2.6 : 1.2 }));
    }
    function draw(time) {
      context.clearRect(0, 0, width, height);
      nodes.forEach((node) => { if (!reducedMotion) { node.x += node.vx; node.y += node.vy; if (node.x < 0 || node.x > width) node.vx *= -1; if (node.y < 0 || node.y > height) node.vy *= -1; } const dx = node.x - pointer.x; const dy = node.y - pointer.y; if (dx * dx + dy * dy < 9000) { node.x += dx * 0.002; node.y += dy * 0.002; } });
      for (let i = 0; i < nodes.length; i += 1) for (let j = i + 1; j < nodes.length; j += 1) { const dx = nodes[i].x - nodes[j].x; const dy = nodes[i].y - nodes[j].y; const distance = Math.hypot(dx, dy); if (distance < 132) { context.strokeStyle = `rgba(57,245,208,${(1 - distance / 132) * 0.22})`; context.lineWidth = 0.7; context.beginPath(); context.moveTo(nodes[i].x, nodes[i].y); context.lineTo(nodes[j].x, nodes[j].y); context.stroke(); } }
      nodes.forEach((node, index) => { context.fillStyle = index % 11 === 0 ? "rgba(184,255,61,.95)" : "rgba(57,245,208,.5)"; context.fillRect(node.x - node.size / 2, node.y - node.size / 2, node.size, node.size); });
      if (!reducedMotion) { const radius = (time * 0.04) % Math.max(width, height); context.strokeStyle = `rgba(184,255,61,${Math.max(0, 0.18 - radius / Math.max(width, height) * 0.18)})`; context.beginPath(); context.arc(width * 0.62, height * 0.48, radius, 0, Math.PI * 2); context.stroke(); }
      if (document.visibilityState !== "hidden") frame = requestAnimationFrame(draw);
    }
    const observer = new ResizeObserver(resize);
    const move = (event) => { const rect = canvas.getBoundingClientRect(); pointer = { x: event.clientX - rect.left, y: event.clientY - rect.top }; };
    const visibility = () => { if (document.visibilityState !== "hidden") frame = requestAnimationFrame(draw); else cancelAnimationFrame(frame); };
    observer.observe(canvas); canvas.addEventListener("pointermove", move); document.addEventListener("visibilitychange", visibility); resize(); frame = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(frame); observer.disconnect(); canvas.removeEventListener("pointermove", move); document.removeEventListener("visibilitychange", visibility); };
  }, [compact]);
  return <canvas ref={ref} className="network-canvas" aria-hidden="true" />;
}
