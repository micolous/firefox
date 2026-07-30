/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// This runs Noise protocol tests defined in //security/manager/ssl/noise/gtest

#include "gtest/gtest.h"
#include "nsComponentManagerUtils.h"
#include "nsICtapCableHandshake.h"
#include "nsString.h"
#include "nsTArray.h"
#include "nss.h"
#include "nss/pk11pub.h"

class psm_Noise : public ::testing::Test {
 public:
  static void SetUpTestSuite() { NSS_NoDB_Init(nullptr); }
};

extern "C" void Rust_NoiseChannelEncryptDecrypt();
TEST_F(psm_Noise, ChannelEncryptDecrypt) { Rust_NoiseChannelEncryptDecrypt(); }

extern "C" void Rust_NoiseChannelConsistency();
TEST_F(psm_Noise, ChannelConsistency) { Rust_NoiseChannelConsistency(); }

extern "C" void Rust_NoiseHandshakeKNpsk0();
TEST_F(psm_Noise, HandshakeKNpsk0) { Rust_NoiseHandshakeKNpsk0(); }

extern "C" void Rust_NoiseHandshakeNKpsk0();
TEST_F(psm_Noise, HandshakeNKpsk0) { Rust_NoiseHandshakeNKpsk0(); }

extern "C" void Rust_NoiseHandshakeNKpsk0NoInitiatorIdentity();
TEST_F(psm_Noise, HandshakeNKpsk0NoInitiatorIdentity) {
  Rust_NoiseHandshakeNKpsk0NoInitiatorIdentity();
}

extern "C" void Rust_NoiseHandshakeErrors();
TEST_F(psm_Noise, HandshakeErrors) { Rust_NoiseHandshakeErrors(); }

/**
 * Test a Noise handshake over the XPCOM boundary.
 *
 * This is equivalent to the `Rust_NoiseHandshakeKNpsk0` test.
 */
TEST_F(psm_Noise, HandshakeKNpsk0XPCOM) {
  nsCOMPtr<nsICtapCableHandshakeService> handshakeService =
      do_CreateInstance("@mozilla.org/security/ctapcablehandshakeservice;1");
  ASSERT_TRUE(handshakeService != nullptr);

  nsresult r;
  nsICtapCableInitiator* initiator = nullptr;
  nsICtapCableResponder* responder = nullptr;

  nsTArray<uint8_t> psk(32);
  psk.SetLength(32);
  SECStatus rv = PK11_GenerateRandom(psk.Elements(), psk.Length());
  EXPECT_EQ(rv, SECSuccess);

  // Generate ephemeral keys
  PLArenaPool* arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
  ASSERT_TRUE(arena != nullptr);

  PK11SlotInfo* slot = PK11_GetInternalSlot();
  ASSERT_TRUE(slot != nullptr);

  SECOidData* oid = SECOID_FindOIDByTag(SEC_OID_ANSIX962_EC_PRIME256V1);
  ASSERT_TRUE(oid != nullptr);
  ASSERT_TRUE(oid->oid.len < 128);

  SECItem* param = SECITEM_AllocItem(arena, nullptr, 2 + oid->oid.len);
  ASSERT_TRUE(param != nullptr);
  ASSERT_TRUE(param->data != nullptr);
  param->data[0] = SEC_ASN1_OBJECT_ID;
  param->data[1] = oid->oid.len;
  memcpy(param->data + 2, oid->oid.data, oid->oid.len);

  SECKEYPublicKey* pubk = nullptr;
  SECKEYPrivateKey* privk = PK11_GenerateKeyPair(
      slot, CKM_EC_KEY_PAIR_GEN, param, &pubk, PR_FALSE, PR_FALSE, nullptr);

  ASSERT_TRUE(privk != nullptr);
  ASSERT_TRUE(pubk != nullptr);

  // Export the private key
  SECItem* privkInfo = PK11_ExportDERPrivateKeyInfo(privk, nullptr);
  ASSERT_TRUE(privkInfo != nullptr);
  nsTArray<uint8_t> privkBytes(privkInfo->data, privkInfo->len);

  // Export the public key
  nsTArray<uint8_t> pubkBytes(65);
  {
    unsigned int len = 0;
    rv = PK11_HPKE_Serialize(pubk, pubkBytes.Elements(), &len,
                             pubkBytes.Capacity());
    EXPECT_EQ(rv, SECSuccess);
    ASSERT_EQ(65u, len);
    pubkBytes.SetLength(len);
  }

  // Handshake process
  {
    nsICtapCableInitiatorHandshake* handshake = nullptr;
    nsTArray<uint8_t> initialMessage;
    nsTArray<uint8_t> responseMessage;

    // Create the initiator
    r = handshakeService->InitialKNpsk0HandshakeMessage(psk, privkBytes,
                                                        &handshake);
    ASSERT_EQ(NS_OK, r);
    ASSERT_TRUE(handshake != nullptr);

    r = handshake->GetInitialMessage(initialMessage);
    ASSERT_EQ(NS_OK, r);
    ASSERT_EQ(81u, initialMessage.Length());

    // Check that the HandshakeState is not consumed.
    bool consumed = false;
    r = handshake->GetConsumed(&consumed);
    ASSERT_EQ(NS_OK, r);
    ASSERT_FALSE(consumed);

    // Create the responder
    r = handshakeService->BuildKNpsk0Responder(psk, pubkBytes, initialMessage,
                                               &responder);
    ASSERT_EQ(NS_OK, r);
    ASSERT_TRUE(responder != nullptr);

    r = responder->GetResponseMessage(responseMessage);
    ASSERT_EQ(NS_OK, r);
    ASSERT_EQ(81u, responseMessage.Length());

    // Process the hanshake response to build the initiator
    nsTArray<uint8_t> handshakeHash(32);
    r = handshake->ProcessHandshakeResponse(responseMessage, &initiator);
    ASSERT_EQ(NS_OK, r);
    ASSERT_TRUE(initiator != nullptr);

    // HandshakeState should now be consumed
    r = handshake->GetConsumed(&consumed);
    ASSERT_EQ(NS_OK, r);
    ASSERT_TRUE(consumed);

    // Further HandshakeState operations should fail
    nsICtapCableInitiator* dummyChannel = nullptr;
    r = handshake->ProcessHandshakeResponse(responseMessage, &dummyChannel);
    ASSERT_EQ(NS_ERROR_DOM_INVALID_STATE_ERR, r);
  }

  // Verify channel binding
  {
    nsTArray<uint8_t> initiatorHash;
    nsTArray<uint8_t> responderHash;
    r = initiator->GetHandshakeHash(initiatorHash);
    ASSERT_EQ(NS_OK, r);
    ASSERT_EQ(32u, initiatorHash.Length());

    r = responder->GetHandshakeHash(responderHash);
    ASSERT_EQ(NS_OK, r);

    ASSERT_EQ(initiatorHash, responderHash);
  }

  // responder -> initiator
  {
    constexpr auto responderMsgStr = "Hi, initiator!"_ns;
    nsTArray<uint8_t> responderMsg(responderMsgStr.Data(),
                                   responderMsgStr.Length());
    nsTArray<uint8_t> ct;
    r = responder->Encrypt(responderMsg, ct);
    ASSERT_EQ(NS_OK, r);
    ASSERT_EQ(48u, ct.Length());
    ASSERT_NE(responderMsg, ct);

    nsTArray<uint8_t> pt;
    r = initiator->Decrypt(ct, pt);
    ASSERT_EQ(NS_OK, r);
    ASSERT_EQ(responderMsg, pt);
  }

  // initiator -> responder
  {
    constexpr auto initiatorMsgStr = "G'day, responder!"_ns;
    nsTArray<uint8_t> initiatorMsg(initiatorMsgStr.Data(),
                                   initiatorMsgStr.Length());
    nsTArray<uint8_t> ct;
    r = initiator->Encrypt(initiatorMsg, ct);
    ASSERT_EQ(NS_OK, r);
    ASSERT_EQ(48u, ct.Length());
    ASSERT_NE(initiatorMsg, ct);

    nsTArray<uint8_t> pt;
    r = responder->Decrypt(ct, pt);
    ASSERT_EQ(NS_OK, r);
    ASSERT_EQ(initiatorMsg, pt);
  }
}

/**
 * Test incorrect Noise handshake calls over the XPCOM boundary.
 *
 * This is similar to the `Rust_NoiseHandshakeErrors` test, but covers errors
 * that Rust's type system would prevent.
 */
TEST_F(psm_Noise, HandshakeErrorsXPCOM) {
  nsCOMPtr<nsICtapCableHandshakeService> handshakeService =
      do_CreateInstance("@mozilla.org/security/ctapcablehandshakeservice;1");
  ASSERT_TRUE(handshakeService != nullptr);
  nsICtapCableResponder* responder = nullptr;
  nsICtapCableInitiatorHandshake* handshake = nullptr;
  nsTArray<uint8_t> initialMessage;
  nsresult r;

  // Check short PSKs
  nsTArray<uint8_t> psk(32);
  for (int l = 0; l < 32; l++) {
    psk.SetLength(l);

    r = handshakeService->InitialKNpsk0HandshakeMessage(psk, psk, &handshake);
    ASSERT_NE(NS_OK, r);
    ASSERT_TRUE(handshake == nullptr);

    r = handshakeService->BuildKNpsk0Responder(psk, psk, initialMessage,
                                               &responder);
    ASSERT_NE(NS_OK, r);
    ASSERT_TRUE(responder == nullptr);
  }

  // Invalid key bytes
  psk.SetLength(32);
  nsTArray<uint8_t> keyBytes(100);
  // 0 is not a valid first byte as either a private (DER) or public
  // (uncompressed X9.62 point) key.
  keyBytes.AppendElement(0);

  for (int l = 0; l <= 100; l++) {
    keyBytes.SetLength(l);

    // Check invalid private key
    r = handshakeService->InitialKNpsk0HandshakeMessage(psk, keyBytes,
                                                        &handshake);
    ASSERT_NE(NS_OK, r);
    ASSERT_TRUE(handshake == nullptr);

    // Check invalid public key
    r = handshakeService->BuildKNpsk0Responder(psk, keyBytes, initialMessage,
                                               &responder);
    ASSERT_NE(NS_OK, r);
    ASSERT_TRUE(responder == nullptr);
  }
}
