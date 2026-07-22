import assert from "node:assert/strict";
import test from "node:test";

import { shouldAutoConfigureLocalPreviewCommunity } from "./localPreviewCommunity.ts";

test("only an explicitly enabled development preview bypasses hosted onboarding", () => {
  assert.equal(shouldAutoConfigureLocalPreviewCommunity(true, "1"), true);
  assert.equal(
    shouldAutoConfigureLocalPreviewCommunity(true, undefined),
    false,
  );
  assert.equal(shouldAutoConfigureLocalPreviewCommunity(true, "0"), false);
  assert.equal(shouldAutoConfigureLocalPreviewCommunity(false, "1"), false);
});
