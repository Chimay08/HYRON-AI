import { describe, expect, it } from "vitest";
import { errorMessage } from "./api.js";

describe("API error handling", () => {
  it("explains an unreachable backend without inventing success", () => {
    expect(errorMessage({ code: "ERR_NETWORK" })).toMatch(/Cannot reach/);
  });

  it("reports request timeouts distinctly", () => {
    expect(errorMessage({ code: "ECONNABORTED" })).toMatch(/timed out/);
  });

  it("preserves structured backend validation details", () => {
    const error = {
      response: {
        status: 422,
        data: { detail: { message: "No dependencies found", issues: [
          { file: "package.json", level: "error", message: "empty manifest" },
        ] } },
      },
    };
    expect(errorMessage(error)).toBe("No dependencies found - package.json: empty manifest");
  });

  it("surfaces FastAPI field validation errors", () => {
    const error = { response: { status: 422, data: { detail: [{ msg: "Field required" }] } } };
    expect(errorMessage(error)).toBe("Field required");
  });
});
