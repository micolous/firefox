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
  let now = new Date().getTime() / 1000;
  let params = newDiscoveryParams();
  equal(
    params.knownDomainCount,
    2,
    "known domain count should be 2 by default"
  );
  lessOrEqual(
    Math.abs(now - params.timestamp),
    10,
    "timestamp should be the current time by default"
  );
  ok(
    !params.supportsStateAssistedTransactions,
    "should not support state-assisted transactions by default"
  );
  equal(params.requestType, "", "request type should be empty by default");
  ok(
    params.supportsWebSocketTransport,
    "WebSockets should be supported by default"
  );
  ok(!params.supportsL2CAPTransport, "L2CAP should be unsupported by default");

  // Supporting both
  params.supportsL2CAPTransport = true;
  ok(
    params.supportsWebSocketTransport,
    "when supporting both transports, WebSockets should be supported"
  );
  ok(
    params.supportsL2CAPTransport,
    "when supporting both transports, L2CAP should be supported"
  );

  // Making the only transport L2CAP should remove WebSockets
  params.supportsWebSocketTransport = false;
  ok(
    !params.supportsWebSocketTransport,
    "When L2CAP is the only transport, WebSockets should not be supported transport"
  );
  ok(params.supportsL2CAPTransport, "L2CAP should be a supported transport");
});

add_task(async function test_cable_discovery() {
  let initiator = gCtapCableDiscoveryService.startInitiator();
  initiator.requestType = "mc";
  ok(
    !initiator.foundAuthenticator,
    "authenticator must not be found by default"
  );
  equal(initiator.webSocketUrl, "", "WebSocket URL must be empty by default");
  notEqual(initiator.timestamp, 0, "timestamp must not be zero");
  equal(initiator.tunnelID.length, 16, "tunnel ID must be 16 bytes");
  notDeepEqual(
    initiator.tunnelID,
    new Uint8Array(16),
    "tunnel ID must not be all zero"
  );

  // Check the QR code URL is possibly well formed.
  /** @type string */
  let qrUrl = initiator.qrUrl;
  ok(
    qrUrl.startsWith("FIDO:/"),
    `QR code URL must start with "FIDO:/": "${qrUrl}"`
  );
  greater(qrUrl.length, 25, "QR code URL must be long");
  for (let i = 6; i < qrUrl.length; i++) {
    let c = qrUrl.charCodeAt(i);
    ok(c >= 0x30 && c <= 0x39, "QR code must only contain digits");
  }

  // Create random BLE beacons of various lengths that can't be decrypted.
  for (let i = 0; i <= 26; i++) {
    let otherEid = crypto.getRandomValues(new Uint8Array(i));
    ok(!initiator.tryDecryptEID(otherEid));
    ok(!initiator.foundAuthenticator);
  }

  // Make an authenticator to scan the QR code.
  let authenticator = gCtapCableDiscoveryService.startAuthenticator(qrUrl);

  // Request parameters should be propagated
  equal(
    initiator.requestType,
    authenticator.requestType,
    "request type parameters are equal"
  );
  equal(
    initiator.knownDomainCount,
    authenticator.knownDomainCount,
    "known domain counts are equal"
  );
  equal(
    initiator.supportsWebSocketTransport,
    authenticator.supportsWebSocketTransport,
    "supporting websockets is equal"
  );
  equal(
    initiator.supportsL2CAPTransport,
    authenticator.supportsL2CAPTransport,
    "supporting L2CAP is equal"
  );
  equal(
    initiator.supportsStateAssistedTransactions,
    authenticator.supportsStateAssistedTransactions,
    "supporting state-assisted transactions is equal"
  );
  equal(initiator.timestamp, authenticator.timestamp, "timestamps are equal");
  deepEqual(initiator.tunnelID, authenticator.tunnelID, "tunnel IDs are equal");
  /** @type string */
  let tunnelID = new Uint8Array(authenticator.tunnelID).toHex().toUpperCase();

  // Prepare a BLE beacon.
  let eid = authenticator.generateEncryptedEID(
    1,
    Uint8Array.fromHex("C0FFEE"),
    0
  );

  // Receive the BLE beacon
  ok(initiator.tryDecryptEID(eid), "initiator can decrypt EID");
  ok(initiator.foundAuthenticator, "initiator found authenticator");
  equal(
    initiator.webSocketUrl,
    `wss://cable.auth.com/cable/connect/C0FFEE/${tunnelID}`,
    "initiator can derive correct websocket URL"
  );

  // Start the initiator side of the handshake
  let initiatorHandshake = initiator.handshake();

  // Send the initial message to the authenticator to create a channel
  let responder = authenticator.handshake(initiatorHandshake.initialMessage);
  ok(responder.hasKeys, "responder channel should have keys");

  // Send the response message to the initiator to create a channel
  initiator = initiatorHandshake.processHandshakeResponse(
    responder.responseMessage
  );
  ok(initiator.hasKeys, "initiator channel should have keys");

  // Verify channel binding
  deepEqual(initiator.handshakeHash, responder.handshakeHash);

  // responder -> initiator
  let msg = "Hi initiator!";
  let msgBytes = stringToArray(msg);
  let ct = responder.encrypt(msgBytes);
  notDeepEqual(msgBytes, ct, "encrypted value should differ from plaintext");

  let pt = arrayToString(initiator.decrypt(ct));
  equal(msg, pt, "initiator should be able to decrypt responder's message");

  throws(
    () => initiator.decrypt(ct),
    /NS_ERROR_ILLEGAL_VALUE/,
    "decrypting the responder's message again should fail"
  );

  // initiator -> responder
  msg = "G'day, responder!";
  msgBytes = stringToArray(msg);
  ct = initiator.encrypt(msgBytes);
  notDeepEqual(msgBytes, ct, "encrypted value should differ from plaintext");

  pt = arrayToString(responder.decrypt(ct));
  equal(msg, pt, "responder should be able to decrypt initiator's message");
});

add_task(async function test_cable_discovery_bad_params() {
  let initiator = gCtapCableDiscoveryService.startInitiator();
  throws(
    () => initiator.qrUrl,
    /NS_ERROR_ILLEGAL_VALUE/,
    "creating a QR code with no request type should fail"
  );

  initiator.requestType = "mc";
  initiator.supportsWebSocketTransport = false;
  throws(
    () => initiator.qrUrl,
    /NS_ERROR_ILLEGAL_VALUE/,
    "creating a QR code with no transports should fail"
  );

  initiator.supportsL2CAPTransport = true;
  /** @type string */
  let qrUrl = initiator.qrUrl;
  ok(
    qrUrl.startsWith("FIDO:/"),
    `QR code URL must start with "FIDO:/": "${qrUrl}"`
  );

  // Make an authenticator to scan the QR code.
  let authenticator = gCtapCableDiscoveryService.startAuthenticator(qrUrl);

  throws(
    () =>
      authenticator.generateEncryptedEID(1, Uint8Array.fromHex("C0FFEE"), 0),
    /NS_ERROR_ILLEGAL_VALUE/,
    "unsupported transport should fail"
  );

  throws(
    () =>
      authenticator.generateEncryptedEID(
        1,
        Uint8Array.fromHex("C0FFEE"),
        0xffff
      ),
    /NS_ERROR_ILLEGAL_VALUE/,
    "invalid transport should fail"
  );

  throws(
    () => authenticator.generateEncryptedEID(1, Uint8Array.fromHex("CAFE"), 1),
    /NS_ERROR_ILLEGAL_VALUE/,
    "invalid routing ID should fail"
  );

  throws(
    () =>
      authenticator.generateEncryptedEID(250, Uint8Array.fromHex("C0FFEE"), 1),
    /NS_ERROR_ILLEGAL_VALUE/,
    "invalid tunnel server ID should fail"
  );

  let eid = new Uint8Array(
    authenticator.generateEncryptedEID(1, Uint8Array.fromHex("C0FFEE"), 1)
  );
  equal(eid.length, 23, "supported transport should succeed");

  let suffix = eid.subarray(20);
  eid = eid.subarray(0, 20);
  ok(initiator.tryDecryptEID(eid, suffix), "initiator can decrypt EID");
  ok(initiator.foundAuthenticator, "initiator found authenticator");
  equal(initiator.webSocketUrl, "", "websocket URL is empty for L2CAP");
});
