export { runScan } from "./engine/scanner.js";
export { connect } from "./transports/factory.js";
export { inventory } from "./engine/inventory.js";
export { loadConfig, defaultConfig } from "./config/loader.js";
export { computeScore } from "./report/score.js";
export { renderJson } from "./report/json.js";
export { renderSarif } from "./report/sarif.js";
export { renderTerminal } from "./report/terminal.js";
export type * from "./types.js";

export { createBaseline, applyBaseline, loadBaseline, createSnapshot, compareSnapshot, loadSnapshot } from "./policy.js";
export type { Baseline, ToolSnapshot } from "./policy.js";
