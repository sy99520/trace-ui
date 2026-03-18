/**
 * 主题颜色定义
 * 所有主题的颜色集中在此文件管理，包括 CSS 变量和 Canvas 颜色。
 */

export type ThemeId = "dark" | "light" | "dim";

export interface ThemeColors {
  /* ── CSS 变量映射 ── */
  bgPrimary: string;
  bgSecondary: string;
  bgRowEven: string;
  bgRowOdd: string;
  bgFuncEntry: string;
  bgSelected: string;
  bgTainted: string;
  bgInput: string;
  bgDialog: string;

  textPrimary: string;
  textSecondary: string;
  textAddress: string;
  textChanges: string;
  textAsciiPrintable: string;
  textAsciiNonprint: string;
  textHexZero: string;
  textHexHighlight: string;

  btnPrimary: string;
  btnTaint: string;

  regChanged: string;
  regRead: string;
  regPc: string;

  asmMnemonic: string;
  asmRegister: string;
  asmMemory: string;
  asmImmediate: string;
  asmShift: string;

  borderColor: string;

  scrollbarThumb: string;
  scrollbarThumbHover: string;

  /* ── Canvas 特有颜色 ── */
  // TraceTable
  arrowAnchor: string;
  arrowDef: string;
  arrowUse: string;
  bgHover: string;
  arrowAnchorBg: string;
  arrowDefBg: string;
  arrowUseBg: string;
  bgMultiSelect: string;
  strikethroughLine: string;
  commentGutter: string;
  commentInline: string;
  callInfoNormal: string;
  callInfoJni: string;

  // Minimap
  minimapSelected: string;
  minimapViewportBg: string;
  minimapViewportHover: string;
  minimapViewportDrag: string;
  minimapViewportBorder: string;
}

export interface ThemeMeta {
  id: ThemeId;
  label: string;
  colors: ThemeColors;
}

/* ═══════════════════════════════════════════════════════════
   Dark — One Dark Trace (current default)
   ═══════════════════════════════════════════════════════════ */
const dark: ThemeColors = {
  bgPrimary: "#1e1f22",
  bgSecondary: "#27282c",
  bgRowEven: "#1e1f22",
  bgRowOdd: "#222327",
  bgFuncEntry: "#1e2a38",
  bgSelected: "#2c3e5c",
  bgTainted: "#3a1e32",
  bgInput: "#2c2d31",
  bgDialog: "#1a1b1e",

  textPrimary: "#abb2bf",
  textSecondary: "#636d83",
  textAddress: "#61afef",
  textChanges: "#e5c07b",
  textAsciiPrintable: "#98c379",
  textAsciiNonprint: "#3e4150",
  textHexZero: "#3e4150",
  textHexHighlight: "#e5c07b",

  btnPrimary: "#528bff",
  btnTaint: "#d19a66",

  regChanged: "#e06c75",
  regRead: "#61afef",
  regPc: "#61afef",

  asmMnemonic: "#c678dd",
  asmRegister: "#56b6c2",
  asmMemory: "#e5c07b",
  asmImmediate: "#d19a66",
  asmShift: "#98c379",

  borderColor: "#3e4150",

  scrollbarThumb: "#3e4150",
  scrollbarThumbHover: "#525769",

  arrowAnchor: "#e05050",
  arrowDef: "#4caf50",
  arrowUse: "#5c9fd6",
  bgHover: "rgba(255,255,255,0.04)",
  arrowAnchorBg: "rgba(255,255,255,0.08)",
  arrowDefBg: "rgba(76,175,80,0.12)",
  arrowUseBg: "rgba(92,159,214,0.12)",
  bgMultiSelect: "rgba(80,200,120,0.18)",
  strikethroughLine: "#888888",
  commentGutter: "rgba(230,160,50,0.8)",
  commentInline: "#8b95a7",
  callInfoNormal: "#e06c75",
  callInfoJni: "#d16d9e",

  minimapSelected: "rgba(44, 62, 92, 0.6)",
  minimapViewportBg: "rgba(255,255,255,0.08)",
  minimapViewportHover: "rgba(255,255,255,0.15)",
  minimapViewportDrag: "rgba(255,255,255,0.20)",
  minimapViewportBorder: "rgba(255,255,255,0.2)",
};

/* ═══════════════════════════════════════════════════════════
   Light — 浅白色主题
   ═══════════════════════════════════════════════════════════ */
const light: ThemeColors = {
  bgPrimary: "#f5f5f5",
  bgSecondary: "#eaeaeb",
  bgRowEven: "#f5f5f5",
  bgRowOdd: "#efefef",
  bgFuncEntry: "#dce8f5",
  bgSelected: "#c4d7f2",
  bgTainted: "#f5dce8",
  bgInput: "#ffffff",
  bgDialog: "#f0f0f0",

  textPrimary: "#383a42",
  textSecondary: "#8c919a",
  textAddress: "#4078f2",
  textChanges: "#c18401",
  textAsciiPrintable: "#50a14f",
  textAsciiNonprint: "#c8cad0",
  textHexZero: "#c8cad0",
  textHexHighlight: "#c18401",

  btnPrimary: "#4078f2",
  btnTaint: "#c18401",

  regChanged: "#e45649",
  regRead: "#4078f2",
  regPc: "#4078f2",

  asmMnemonic: "#a626a4",
  asmRegister: "#0184bc",
  asmMemory: "#c18401",
  asmImmediate: "#986801",
  asmShift: "#50a14f",

  borderColor: "#d0d0d0",

  scrollbarThumb: "#c0c0c0",
  scrollbarThumbHover: "#a0a0a0",

  arrowAnchor: "#e03030",
  arrowDef: "#3d9140",
  arrowUse: "#4078f2",
  bgHover: "rgba(0,0,0,0.04)",
  arrowAnchorBg: "rgba(224,48,48,0.08)",
  arrowDefBg: "rgba(61,145,64,0.10)",
  arrowUseBg: "rgba(64,120,242,0.10)",
  bgMultiSelect: "rgba(80,200,120,0.15)",
  strikethroughLine: "#999999",
  commentGutter: "rgba(193,132,1,0.7)",
  commentInline: "#6a6f78",
  callInfoNormal: "#e45649",
  callInfoJni: "#a626a4",

  minimapSelected: "rgba(196, 215, 242, 0.6)",
  minimapViewportBg: "rgba(0,0,0,0.06)",
  minimapViewportHover: "rgba(0,0,0,0.12)",
  minimapViewportDrag: "rgba(0,0,0,0.18)",
  minimapViewportBorder: "rgba(0,0,0,0.2)",
};

/* ═══════════════════════════════════════════════════════════
   Dim — 柔和深色（比 Dark 更低对比度，护眼）
   ═══════════════════════════════════════════════════════════ */
const dim: ThemeColors = {
  bgPrimary: "#282c34",
  bgSecondary: "#2e323b",
  bgRowEven: "#282c34",
  bgRowOdd: "#2b3039",
  bgFuncEntry: "#253345",
  bgSelected: "#35485e",
  bgTainted: "#3d2637",
  bgInput: "#333842",
  bgDialog: "#242830",

  textPrimary: "#9da5b4",
  textSecondary: "#5c6370",
  textAddress: "#5cacee",
  textChanges: "#d4a955",
  textAsciiPrintable: "#8fbc6f",
  textAsciiNonprint: "#3e4452",
  textHexZero: "#3e4452",
  textHexHighlight: "#d4a955",

  btnPrimary: "#4d78cc",
  btnTaint: "#c49060",

  regChanged: "#d46a6a",
  regRead: "#5cacee",
  regPc: "#5cacee",

  asmMnemonic: "#b07cd8",
  asmRegister: "#4db8b0",
  asmMemory: "#d4a955",
  asmImmediate: "#c49060",
  asmShift: "#8fbc6f",

  borderColor: "#3e4452",

  scrollbarThumb: "#3e4452",
  scrollbarThumbHover: "#4b5263",

  arrowAnchor: "#d46a6a",
  arrowDef: "#4caf50",
  arrowUse: "#5cacee",
  bgHover: "rgba(255,255,255,0.03)",
  arrowAnchorBg: "rgba(255,255,255,0.06)",
  arrowDefBg: "rgba(76,175,80,0.10)",
  arrowUseBg: "rgba(92,159,214,0.10)",
  bgMultiSelect: "rgba(80,200,120,0.14)",
  strikethroughLine: "#777777",
  commentGutter: "rgba(210,150,50,0.7)",
  commentInline: "#7a8494",
  callInfoNormal: "#d46a6a",
  callInfoJni: "#b07cd8",

  minimapSelected: "rgba(53, 72, 94, 0.6)",
  minimapViewportBg: "rgba(255,255,255,0.06)",
  minimapViewportHover: "rgba(255,255,255,0.12)",
  minimapViewportDrag: "rgba(255,255,255,0.18)",
  minimapViewportBorder: "rgba(255,255,255,0.2)",
};

/* ═══════════════════════════════════════════════════════════ */

export const THEMES: ThemeMeta[] = [
  { id: "dark", label: "Dark", colors: dark },
  { id: "light", label: "Light", colors: light },
  { id: "dim", label: "Dim", colors: dim },
];

export function getTheme(id: ThemeId): ThemeColors {
  return THEMES.find(t => t.id === id)?.colors ?? dark;
}
