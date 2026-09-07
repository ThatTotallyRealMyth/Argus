import React, { useEffect } from "react";

export default function CustomCursor() {
  useEffect(() => {
    const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
    if (!finePointer.matches) return undefined;
    const root = document.documentElement;
    const down = (event) => {
      root.classList.toggle("cursor-primary-down", event.button === 0);
      root.classList.toggle("cursor-secondary-down", event.button === 2);
    };
    const up = () => root.classList.remove("cursor-primary-down", "cursor-secondary-down");

    window.addEventListener("pointerdown", down, true);
    window.addEventListener("pointerup", up, true);
    window.addEventListener("pointercancel", up, true);
    window.addEventListener("blur", up);
    return () => {
      window.removeEventListener("pointerdown", down, true);
      window.removeEventListener("pointerup", up, true);
      window.removeEventListener("pointercancel", up, true);
      window.removeEventListener("blur", up);
      up();
    };
  }, []);

  return null;
}
