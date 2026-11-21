import { describe, expect, it } from "vitest";
import { correlationFromRequest, withRequestCorrelation } from "../request-correlation";
import { createCaptureSink, setTelemetrySink } from "../telemetry";

describe("request correlation", () => {
  it("preserves a valid incoming ID through worker submission", () => {
    const ctx = correlationFromRequest(new Request("https://example.test", { headers: { "x-correlation-id": "trace-123" } }));
    expect(ctx.correlationId).toBe("trace-123");
    expect(ctx.job({ operation: "work", params: {} }).correlationId).toBe("trace-123");
  });

  it("rejects malformed and oversized IDs without reflecting untrusted text", () => {
    for (const value of ["unsafe\\nheader", "a".repeat(129), "two words"]) {
      const ctx = correlationFromRequest(new Request("https://example.test", { headers: { "x-correlation-id": value } }));
      expect(ctx.correlationId).not.toBe(value);
      expect(ctx.correlationId.length).toBeGreaterThan(0);
    }
  });

  it("preserves correlation in failing responses and telemetry", async () => {
    const sink = createCaptureSink();
    const before = setTelemetrySink(sink);
    try {
      const req = new Request("https://example.test", { headers: { "x-correlation-id": "route-error" } });
      const response = await withRequestCorrelation(req, "api.test", () => Response.json({ code: "denied" }, { status: 403 }));
      expect(response.status).toBe(403);
      expect(response.headers.get("x-correlation-id")).toBe("route-error");
      expect(sink.latest()).toMatchObject({ op: "api.test", result: "failure", correlationId: "route-error", errorCode: "http_403" });
      const thrown = await withRequestCorrelation(req, "api.test", () => { throw new Error("secret"); });
      expect(thrown.status).toBe(500);
      expect(thrown.headers.get("x-correlation-id")).toBe("route-error");
      expect(await thrown.json()).toEqual({ error: "internal_error" });
    } finally {
      setTelemetrySink(before);
    }
  });
});
