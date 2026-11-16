import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { BACKEND_CAPABILITIES } from "../src/capabilities.ts";

// The browser holdout test (src/guided/vendorHoldout20261116.test.ts) decides which formats the automatic journey
// may choose from a copy of the capabilities this backend serves. The copy must be what the backend serves.
test("the capabilities copy of the vendor holdout test is what this backend serves", () => {
  const copy = JSON.parse(readFileSync(new URL("../../tests/fixtures/vendor-holdout-capabilities-20261116.json", import.meta.url), "utf8"));
  assert.deepEqual(copy, JSON.parse(JSON.stringify(BACKEND_CAPABILITIES)));
});
