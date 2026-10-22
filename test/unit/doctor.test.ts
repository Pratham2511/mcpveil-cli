import { it, expect } from "vitest";
import { doctor } from "../../src/doctor.js";
it("diagnoses setup and environment availability without revealing values", () => {
  process.env.MCPVEIL_TEST_DOCTOR = "synthetic-sensitive-diagnostic-value";
  try {
    const report = doctor(undefined, ["MCPVEIL_TEST_DOCTOR", "MCPVEIL_TEST_MISSING"]);
    expect(report.status).toBe("needs-attention");
    expect(report.missingEnv).toEqual(["MCPVEIL_TEST_MISSING"]);
    expect(JSON.stringify(report)).not.toContain(process.env.MCPVEIL_TEST_DOCTOR);
    expect(doctor().status).toBe("ready");
  } finally { delete process.env.MCPVEIL_TEST_DOCTOR; }
});
