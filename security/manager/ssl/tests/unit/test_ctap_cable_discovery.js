/* Any copyright is dedicated to the Public Domain.
https://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

let gCtapCableDiscoveryService = Cc[
  "@mozilla.org/security/ctapcablediscoveryservice;1"
].createInstance(Ci.nsICtapCableDiscoveryService);

function newDiscoveryParams() {
  return Cc["@mozilla.org/security/ctapcablediscoveryparams;1"].createInstance(
    Ci.nsICtapCableDiscoveryParams
  );
}

add_task(async function test_cable_discovery_param_defaults() {
  let params = newDiscoveryParams();
  equal(
    params.knownDomainCount,
    0,
    "known domain count should be zero by default"
  );
  equal(params.timestamp, 0, "timestamp should be zero by default");
  ok(
    !params.supportsStateAssistedTransactions,
    "should not support state-assisted transactions by default"
  );
  equal(params.requestType, "", "request type should be empty by default");
  equal(
    params.supportedTransports.length,
    0,
    "supported transports array should be empty by default"
  );
  ok(
    params.supportsWebSocketTransport,
    "WebSockets should be supported by default"
  );
  ok(!params.supportsL2CAPTransport, "L2CAP should be unsupported by default");

  // Making the only transport L2CAP should remove WebSockets
  params.supportedTransports = [1];
  ok(
    !params.supportsWebSocketTransport,
    "When L2CAP is the only transport, WebSockets should not be supported transport"
  );
  ok(params.supportsL2CAPTransport, "L2CAP should be a supported transport");

  // Supporting both
  params.supportedTransports = [0, 1];
  ok(
    params.supportsWebSocketTransport,
    "when supporting both transports, WebSockets should be supported"
  );
  ok(
    params.supportsL2CAPTransport,
    "when supporting both transports, L2CAP should be supported"
  );

  // Supporting just WebSockets, but with an explicit ID.
  params.supportedTransports = [0];
  ok(
    params.supportsWebSocketTransport,
    "when supporting only WebSockets, WebSockets should be supported"
  );
  ok(
    !params.supportsL2CAPTransport,
    "when supporting only WebSockets, L2CAP should not be supported"
  );
});
