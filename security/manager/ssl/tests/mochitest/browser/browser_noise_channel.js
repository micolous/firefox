/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
"use strict";

function newNoiseChannel() {
  return Cc["@mozilla.org/security/noisechannel;1"].createInstance(
    Ci.nsINoiseChannel
  );
}

add_task(async function noiseChannelConsistency() {
  // JavaScript version of Rust_NoiseChannelConsistency
  // (security/manager/ssl/noise/gtest/test.rs)
  let key0 = Uint8Array.fromHex(
    "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
  );
  let key1 = Uint8Array.fromHex(
    "4343434343434343434343434343434343434343434343434343434343434343"
  );

  let alice = newNoiseChannel();
  ok(!alice.hasKeys, "alice should not have keys on creation");

  alice.initializeKeys(key0, key1);
  ok(alice.hasKeys, "alice should have keys after init");

  let bob = newNoiseChannel();
  ok(!bob.hasKeys, "bob should not have keys on creation");

  bob.initializeKeys(key1, key0);
  ok(bob.hasKeys, "bob should have keys after init");

  let msg = Uint8Array.from(
    "The quick brown fox jumps over the lazy dog."
      .split("")
      .map(x => x.charCodeAt())
  );
  let expected_crypted = Uint8Array.fromHex(
    "a4221bbd65ac9bd6da472f1c4a93950da19edaccbf61cd8e2febb60df5b2ae334cabad" +
      "4d74321e567b0d0c470429e0cba79c29a79f6148777cd000e31daa6eb71dfe23c59a" +
      "96b2fe48c62a21208821ec"
  );

  let crypted = Uint8Array.from(alice.encrypt(msg));
  is(crypted, expected_crypted, "encrypted value should be the expected value");

  let decrypted = Uint8Array.from(bob.decrypt(crypted));
  is(decrypted, msg, "decrypted value should be the original message");
});
