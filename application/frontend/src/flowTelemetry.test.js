import assert from "node:assert/strict";
import test from "node:test";

import { getFlowEndpointLabel, requestFlowSnapshot } from "./flowTelemetry.js";

test("flow snapshots use the existing capture-session header", async () => {
  let request;
  const flow = { flow_id: 7, protocol: "TCP", packets: 3 };
  const client = {
    async get(url, config) {
      request = { url, config };
      return { data: { flows: [flow] } };
    },
  };

  const result = await requestFlowSnapshot(client, "/api/capture/flows", "session-secret");

  assert.equal(request.url, "/api/capture/flows");
  assert.deepEqual(request.config.headers, { "X-Capture-Token": "session-secret" });
  assert.deepEqual(result, { stopped: false, flows: [flow] });
});

test("HTTP 409 is represented as a normal stopped capture", async () => {
  const client = {
    async get() {
      const error = new Error("capture stopped");
      error.response = { status: 409 };
      throw error;
    },
  };

  assert.deepEqual(await requestFlowSnapshot(client, "/flows", "token"), {
    stopped: true,
    flows: [],
  });
});

test("other flow request failures remain errors", async () => {
  const failure = new Error("forbidden");
  failure.response = { status: 403 };
  const client = { async get() { throw failure; } };

  await assert.rejects(requestFlowSnapshot(client, "/flows", "token"), failure);
});

test("endpoint labels render available address and port safely", () => {
  assert.equal(getFlowEndpointLabel({ ip: "192.0.2.4", port: 443 }), "192.0.2.4:443");
  assert.equal(getFlowEndpointLabel({ ip: "2001:db8::1", port: 53 }), "[2001:db8::1]:53");
  assert.equal(getFlowEndpointLabel({ ip: "192.0.2.4" }), "192.0.2.4");
  assert.equal(getFlowEndpointLabel(null), "—");
});
