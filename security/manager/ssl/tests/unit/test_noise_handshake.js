/* Any copyright is dedicated to the Public Domain.
https://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

let gNoiseHandshakeService = Cc[
  "@mozilla.org/security/noisehandshakeservice;1"
].createInstance(Ci.nsINoiseHandshakeService);

add_task(async function test_noise_handshake_knpsk0() {
  // JavaScript version of Rust_NoiseHandshakeKNpsk0
  // (security/manager/ssl/noise/gtest/test.rs)
  let initiatorIdentityKey = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  let initiatorPub = new Uint8Array(
    await crypto.subtle.exportKey("raw", initiatorIdentityKey.publicKey)
  );
  let initiatorIdentity = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", initiatorIdentityKey.privateKey)
  );

  let psk = new Uint8Array(32);
  crypto.getRandomValues(psk);

  let hs = {};
  let initialMessage = {};

  gNoiseHandshakeService.initialKNpsk0HandshakeMessage(
    psk,
    initiatorIdentity,
    hs,
    initialMessage
  );

  let responderChannel = {};
  let responseMessage = {};

  gNoiseHandshakeService.buildKNpsk0Responder(
    psk,
    initiatorPub,
    initialMessage.value,
    responderChannel,
    responseMessage
  );

  responderChannel = responderChannel.value;
  ok(responderChannel.hasKeys, "responder channel should have keys");

  let initiatorChannel = {};
  hs.value.processHandshakeResponse(
    responseMessage.value,
    initiatorChannel,
    /* handshakeHash */ {}
  );
  initiatorChannel = initiatorChannel.value;
  ok(initiatorChannel.hasKeys, "initiator channel should have keys");

  // responder -> initiator
  let msg = "Hi initiator!";
  let msgBytes = stringToArray(msg);
  let ct = responderChannel.encrypt(msgBytes);
  notDeepEqual(msgBytes, ct, "encrypted value should differ from plaintext");

  let pt = arrayToString(initiatorChannel.decrypt(ct));
  equal(msg, pt, "initiator should be able to decrypt responder's message");

  throws(
    () => initiatorChannel.decrypt(ct),
    /NS_ERROR_FAILURE/,
    "decrypting the responder's message again should fail"
  );

  // initiator -> responder
  msg = "G'day, responder!";
  msgBytes = stringToArray(msg);
  ct = initiatorChannel.encrypt(msgBytes);
  notDeepEqual(msgBytes, ct, "encrypted value should differ from plaintext");

  pt = arrayToString(responderChannel.decrypt(ct));
  equal(msg, pt, "responder should be able to decrypt initiator's message");

  throws(
    () => responderChannel.decrypt(ct),
    /NS_ERROR_FAILURE/,
    "decrypting the initiator's message again should fail"
  );
});

add_task(async function test_noise_handshake_errors_knpsk0() {
  // Test Noise handshakes with incorrect key data. This would be a Rust test,
  // but nss_rs::ecdh_keygen can't generate the other ECDH keys due to a bug:
  // https://github.com/mozilla/nss-rs/issues/120
  let params = [
    { name: "ECDH", namedCurve: "P-384" },
    { name: "ECDH", namedCurve: "P-521" },
    { name: "X25519" },
  ];

  // Make a valid P-256 ephemeral key for the responder's initial message
  let validKey = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  let initialMessage = new Uint8Array(
    await crypto.subtle.exportKey("raw", validKey.publicKey)
  );

  await Promise.all(
    params.map(async param => {
      let key = await crypto.subtle.generateKey(param, true, ["deriveBits"]);
      let pub = new Uint8Array(
        await crypto.subtle.exportKey("raw", key.publicKey)
      );
      let priv = new Uint8Array(
        await crypto.subtle.exportKey("pkcs8", key.privateKey)
      );
      let psk = new Uint8Array(32);

      throws(
        () =>
          gNoiseHandshakeService.initialKNpsk0HandshakeMessage(
            psk,
            priv,
            {},
            {}
          ),
        // NS_ERROR_ILLEGAL_VALUE would be ideal, but nss_rs won't export a
        // P-521 pubkey and returns NS_ERROR_FAILURE.
        // https://github.com/mozilla/nss-rs/issues/120
        /NS_ERROR_/,
        `creating handshake message with ${JSON.stringify(param)} key fails`
      );

      throws(
        () =>
          gNoiseHandshakeService.buildKNpsk0Responder(
            psk,
            pub,
            initialMessage,
            {},
            {}
          ),
        /NS_ERROR_ILLEGAL_VALUE/,
        `creating responder with ${JSON.stringify(param)} key fails`
      );
    })
  );
});
