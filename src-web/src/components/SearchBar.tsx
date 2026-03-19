import React, { useState, useCallback, useRef } from "react";

export interface SearchOptions {
  caseSensitive: boolean;
  wholeWord: boolean;
  useRegex: boolean;
}

interface SearchBarProps {
  query: string;
  onQueryChange: (q: string) => void;
  onSearch: (query: string, options: SearchOptions) => void;
  onPrevMatch: () => void;
  onNextMatch: () => void;
  matchInfo?: string;
  inputRef?: React.RefObject<HTMLInputElement | null>;
  /** 初始 toggle 状态（浮窗打开时从主窗口继承） */
  initialOptions?: SearchOptions;
  /** toggle 状态变化时回调（用于同步状态） */
  onOptionsChange?: (options: SearchOptions) => void;
}

// VSCode 风格 toggle 按钮
function ToggleButton({
  active, onClick, title, children,
}: {
  active: boolean; onClick: () => void; title: string; children: React.ReactNode;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <button
      onClick={onClick}
      title={title}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        width: 22, height: 22,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: active ? "rgba(255,255,255,0.12)" : hovered ? "rgba(255,255,255,0.06)" : "transparent",
        color: active ? "var(--text-primary)" : "var(--text-secondary)",
        border: "none", borderRadius: 3, cursor: "pointer",
        padding: 0, position: "relative",
        fontSize: 12, fontFamily: "var(--font-mono)",
      }}
    >
      {children}
      {active && (
        <span style={{
          position: "absolute", bottom: 0, left: 3, right: 3, height: 2,
          background: "var(--btn-primary)", borderRadius: 1,
        }} />
      )}
    </button>
  );
}

// 小型图标按钮（上下导航、选项）
function IconButton({
  onClick, title, disabled, children,
}: {
  onClick: () => void; title: string; disabled?: boolean; children: React.ReactNode;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <button
      onClick={onClick}
      title={title}
      disabled={disabled}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        width: 22, height: 22,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: hovered && !disabled ? "rgba(255,255,255,0.08)" : "transparent",
        color: disabled ? "var(--text-disabled, #555)" : "var(--text-secondary)",
        border: "none", borderRadius: 3,
        cursor: disabled ? "default" : "pointer", padding: 0,
      }}
    >
      {children}
    </button>
  );
}

export default function SearchBar({
  query, onQueryChange, onSearch, onPrevMatch, onNextMatch, matchInfo,
  inputRef: externalRef, initialOptions, onOptionsChange,
}: SearchBarProps) {
  const [caseSensitive, setCaseSensitive] = useState(initialOptions?.caseSensitive ?? false);
  const [wholeWord, setWholeWord] = useState(initialOptions?.wholeWord ?? false);
  const [useRegex, setUseRegex] = useState(initialOptions?.useRegex ?? false);
  const internalRef = useRef<HTMLInputElement>(null);
  const ref = externalRef || internalRef;

  const getOptions = useCallback((): SearchOptions => ({
    caseSensitive, wholeWord, useRegex,
  }), [caseSensitive, wholeWord, useRegex]);

  // toggle 变化时通知父组件
  const toggleCaseSensitive = useCallback(() => {
    setCaseSensitive(v => {
      const next = !v;
      onOptionsChange?.({ caseSensitive: next, wholeWord, useRegex });
      return next;
    });
  }, [wholeWord, useRegex, onOptionsChange]);

  const toggleWholeWord = useCallback(() => {
    setWholeWord(v => {
      const next = !v;
      onOptionsChange?.({ caseSensitive, wholeWord: next, useRegex });
      return next;
    });
  }, [caseSensitive, useRegex, onOptionsChange]);

  const toggleUseRegex = useCallback(() => {
    setUseRegex(v => {
      const next = !v;
      onOptionsChange?.({ caseSensitive, wholeWord, useRegex: next });
      return next;
    });
  }, [caseSensitive, wholeWord, onOptionsChange]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      if (e.shiftKey) {
        onPrevMatch();
      } else {
        onSearch(query, getOptions());
        onNextMatch();
      }
    }
  }, [query, onSearch, onPrevMatch, onNextMatch, getOptions]);

  return (
    <div style={{
      display: "flex", gap: 2, padding: "6px 8px",
      borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      alignItems: "center",
    }}>
      {/* 搜索输入框 + 内嵌 toggle */}
      <div style={{
        flex: 1, display: "flex", alignItems: "center",
        background: "var(--bg-input)", border: "1px solid var(--border-color)",
        borderRadius: 3, overflow: "hidden",
      }}>
        <input
          ref={ref}
          type="text"
          placeholder="Search text or /regex/"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          onKeyDown={handleKeyDown}
          style={{
            flex: 1, padding: "3px 8px",
            background: "transparent", color: "var(--text-primary)",
            border: "none", outline: "none",
            fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)",
            minWidth: 0,
          }}
        />
        <div style={{ display: "flex", gap: 1, paddingRight: 4, flexShrink: 0 }}>
          <ToggleButton
            active={caseSensitive}
            onClick={toggleCaseSensitive}
            title="Match Case (Alt+C)"
          >
            <span style={{ fontSize: 13, fontFamily: "serif", fontWeight: 600 }}>Aa</span>
          </ToggleButton>
          <ToggleButton
            active={wholeWord}
            onClick={toggleWholeWord}
            title="Match Whole Word (Alt+W)"
          >
            <span style={{
              fontSize: 10, fontWeight: 700,
              border: "1.2px solid currentColor", borderRadius: 2,
              padding: "0 2px", lineHeight: "14px",
            }}>ab</span>
          </ToggleButton>
          <ToggleButton
            active={useRegex}
            onClick={toggleUseRegex}
            title="Use Regular Expression (Alt+R)"
          >
            <span style={{ fontSize: 12 }}>.*</span>
          </ToggleButton>
        </div>
      </div>

      {/* matchInfo 显示 */}
      {matchInfo && (
        <span style={{
          fontSize: 11, color: "var(--text-secondary)",
          whiteSpace: "nowrap", padding: "0 4px", flexShrink: 0,
        }}>
          {matchInfo}
        </span>
      )}

      {/* 上下导航 + 选项 */}
      <div style={{ display: "flex", gap: 1, alignItems: "center", flexShrink: 0 }}>
        <IconButton onClick={onPrevMatch} title="Previous Match (Shift+Enter)">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 3.5L3 8.5h3v4h4v-4h3L8 3.5z" />
          </svg>
        </IconButton>
        <IconButton onClick={onNextMatch} title="Next Match (Enter)">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 12.5L13 7.5h-3v-4H6v4H3L8 12.5z" />
          </svg>
        </IconButton>
        <IconButton onClick={() => {}} title="Search Options" disabled>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M1 3h14v1H1zm2 3h10v1H3zm2 3h6v1H5zm2 3h2v1H7z" />
          </svg>
        </IconButton>
      </div>
    </div>
  );
}