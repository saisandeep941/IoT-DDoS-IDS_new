export function getFlowEndpointLabel(endpoint) {
  if (!endpoint || typeof endpoint !== "object") return "—";
  const address = typeof endpoint.ip === "string" ? endpoint.ip : "";
  const port = Number.isInteger(endpoint.port) ? endpoint.port : null;
  if (!address) return "—";
  const host = address.includes(":") ? `[${address}]` : address;
  return port === null ? host : `${host}:${port}`;
}

export async function requestFlowSnapshot(client, url, token) {
  try {
    const response = await client.get(url, {
      headers: { "X-Capture-Token": token },
    });
    return {
      stopped: false,
      flows: Array.isArray(response.data?.flows) ? response.data.flows : [],
    };
  } catch (error) {
    if (error.response?.status === 409) return { stopped: true, flows: [] };
    throw error;
  }
}
