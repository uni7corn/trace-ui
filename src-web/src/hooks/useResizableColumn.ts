import { useState, useCallback, useRef } from "react";

/**
 * @param initialWidth 初始宽度
 * @param direction "left" = 向左拖增大（Changes 列），"right" = 向右拖增大（Seq/Address 列）
 * @param minWidth 最小宽度
 */
export function useResizableColumn(initialWidth: number, direction: "left" | "right" = "left", minWidth = 40) {
  const [width, setWidth] = useState(initialWidth);
  const dragging = useRef(false);
  const startX = useRef(0);
  const startW = useRef(0);

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    dragging.current = true;
    startX.current = e.clientX;
    startW.current = width;
    const onMove = (ev: MouseEvent) => {
      if (!dragging.current) return;
      const delta = direction === "left"
        ? startX.current - ev.clientX
        : ev.clientX - startX.current;
      setWidth(Math.max(minWidth, startW.current + delta));
    };
    const onUp = () => {
      dragging.current = false;
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [width, direction, minWidth]);

  return { width, onMouseDown };
}
