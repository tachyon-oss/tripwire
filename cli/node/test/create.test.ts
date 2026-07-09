import { describe, expect, it } from "vitest";

import { ApiError } from "../src/api/errors.js";
import { createErrorMessage } from "../src/commands/create.js";

describe("create error mapping", () => {
  it("explains a still-provisioning orphan (429 canary_pending)", () => {
    const message = createErrorMessage(new ApiError(429, "canary_pending"));
    expect(message).toContain("still being prepared");
    expect(message).toContain("tripwire canary delete");
  });

  it("explains a hard provisioning failure (502 provisioning_failed)", () => {
    const message = createErrorMessage(new ApiError(502, "provisioning_failed"));
    expect(message).toContain("nothing was issued");
  });

  it("falls through (null) for other errors", () => {
    expect(createErrorMessage(new ApiError(429, "create_rate_limited"))).toBeNull();
    expect(createErrorMessage(new ApiError(400, "bad"))).toBeNull();
    expect(createErrorMessage(new ApiError(401, "unauthorized"))).toBeNull();
  });
});
