export const tokens = {
  color: {
    bg: "#0B1017", sidebar: "#101722", workspace: "#111923",
    panel: "#172230", raised: "#1D2A3A", border: "#263344",
    borderStrong: "#35465A", text: "#E8EEF5", secondary: "#9AA9B9",
    disabled: "#6F7F92", accent: "#4C8DCE", accentHover: "#5D9CDA",
    teal: "#43B5A0", danger: "#D96868", warning: "#D9A441",
    high: "#E08A5B", info: "#7E8FA3",
  },
  font: { ui: "Inter", technical: "IBM Plex Mono" },
  spacing: [4, 8, 12, 16, 20, 24, 32],
  radius: [4, 6, 8],
  duration: [90, 160, 240, 400],
  motion: "cubic-bezier(0.2, 0, 0, 1)",
  density: { compact: 28, default: 32, comfortable: 40 },
  evidence: {
    exact: { color: "#43B5A0", shape: "circle", line: "solid" },
    temporal: { color: "#4C8DCE", shape: "square", line: "dashed" },
    heuristic: { color: "#D9A441", shape: "triangle", line: "dotted" },
    reference: { color: "#D96868", shape: "diamond", line: "solid" },
    prediction: { color: "#B8C4D2", shape: "circle-outline", line: "long-dash" },
  },
} as const;

export type Density = keyof typeof tokens.density;
export type EvidenceType = keyof typeof tokens.evidence;
