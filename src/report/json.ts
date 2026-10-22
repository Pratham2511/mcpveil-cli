// src/report/json.ts
import type { ScanReport } from "../types.js";
import { redactValue } from "../utils/redact.js";

export function renderJson(report: ScanReport): string {
  return JSON.stringify(redactValue(report), null, 2);
}
