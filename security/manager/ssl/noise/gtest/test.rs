/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise protocol tests
//!
//! Called from `security/manager/ssl/tests/gtest/NoiseTest.cpp`.
#![allow(non_snake_case)]

extern crate noise;
extern crate nss_rs;

use noise::*;
use nss_rs::{
    aead::Aead,
    ec::{ecdh_keygen, EcCurve},
};
use std::{ffi::CString, os::raw::c_char};

fn nonfatal_fail(msg: String) {
    extern "C" {
        fn GTest_ExpectFailure(message: *const c_char);
    }
    unsafe {
        let msg = CString::new(msg).unwrap();
        GTest_ExpectFailure(msg.as_ptr());
    }
}

/// Check if the two arguments are equal, and causes a non-fatal GTest test
/// failure if they are not.
macro_rules! expect_eq {
    ($x:expr, $y:expr) => {
        match (&$x, &$y) {
            (x, y) => {
                if *x != *y {
                    nonfatal_fail(format!(
                        "check failed: (`{x:?}` == `{y:?}`) at {}:{}",
                        file!(),
                        line!()
                    ))
                }
            }
        }
    };
}

/// Check if the two arguments are not equal, and causes a non-fatal GTest test
/// failure if they are equal.
macro_rules! expect_ne {
    ($x:expr, $y:expr) => {
        match (&$x, &$y) {
            (x, y) => {
                if *x == *y {
                    nonfatal_fail(format!(
                        "check failed: (`{x:?}` != `{y:?}`) at {}:{}",
                        file!(),
                        line!()
                    ))
                }
            }
        }
    };
}

/// Check if that the first argument is greater than the second argument, and causes a non-fatal
/// GTest test failure if they are not.
macro_rules! expect_gt {
    ($x:expr, $y:expr) => {
        match (&$x, &$y) {
            (x, y) => {
                if *x <= *y {
                    nonfatal_fail(format!(
                        "check failed: (`{x:?}` > `{y:?}`) at {}:{}",
                        file!(),
                        line!()
                    ))
                }
            }
        }
    };
}

/// Test encryption and decryption with a pair of [`Channel`s][Channel].
#[no_mangle]
pub extern "C" fn Rust_NoiseChannelEncryptDecrypt() {
    let key0 = Aead::import_key(ALG, &[42; 32]).expect("import_key/key0");
    let key1 = Aead::import_key(ALG, &[67; 32]).expect("import_key/key1");

    let mut alice = Channel::new(key0.clone(), key1.clone());
    let mut bob = Channel::new(key1.clone(), key0.clone());
    let mut corrupted = Channel::new(key1, key0);

    assert!(
        alice.is_counterparty(&bob),
        "alice and bob must be counterparties",
    );

    assert!(
        alice.is_counterparty(&corrupted),
        "alice and corrupted must be counterparties",
    );

    for l in 0..512 {
        let msg = vec![0xff; l];

        // Synchronise the "corrupted" channel with "bob", such that it should
        // be able to decrypt the same messages (if they were valid).
        corrupted.set_reader_nonce(bob.get_reader_nonce());

        let mut crypted = alice.encrypt(&msg).unwrap();
        expect_eq!(false, alice.is_counterparty(&bob));
        let decrypted = bob.decrypt(&crypted).unwrap();
        expect_eq!(true, alice.is_counterparty(&bob));
        expect_eq!(msg.as_slice(), decrypted.as_slice());
        expect_ne!(msg.as_slice(), crypted.as_slice());

        // Output should have lengthened due to the AEAD tag (16 bytes) and at
        // least 1 byte of padding.
        expect_gt!(crypted.len(), l + 16);

        if l > 0 {
            // Corrupt the message
            crypted[(l * 3) % l] ^= 1;
            expect_eq!(true, corrupted.decrypt(&crypted).is_err());
        }
    }
}

/// Test that a [`Channel`] encrypts with consistent, known results.
#[no_mangle]
pub extern "C" fn Rust_NoiseChannelConsistency() {
    let key0 = Aead::import_key(ALG, &[42; 32]).expect("import_key/key0");
    let key1 = Aead::import_key(ALG, &[67; 32]).expect("import_key/key1");

    let mut alice = Channel::new(key0.clone(), key1.clone());
    let mut bob = Channel::new(key1.clone(), key0.clone());

    assert!(
        alice.is_counterparty(&bob),
        "alice and bob must be counterparties",
    );

    let msg = b"The quick brown fox jumps over the lazy dog.";
    let expected_crypted = [
        0xa4, 0x22, 0x1b, 0xbd, 0x65, 0xac, 0x9b, 0xd6, 0xda, 0x47, 0x2f, 0x1c, 0x4a, 0x93, 0x95,
        0x0d, 0xa1, 0x9e, 0xda, 0xcc, 0xbf, 0x61, 0xcd, 0x8e, 0x2f, 0xeb, 0xb6, 0x0d, 0xf5, 0xb2,
        0xae, 0x33, 0x4c, 0xab, 0xad, 0x4d, 0x74, 0x32, 0x1e, 0x56, 0x7b, 0x0d, 0x0c, 0x47, 0x04,
        0x29, 0xe0, 0xcb, 0xa7, 0x9c, 0x29, 0xa7, 0x9f, 0x61, 0x48, 0x77, 0x7c, 0xd0, 0x00, 0xe3,
        0x1d, 0xaa, 0x6e, 0xb7, 0x1d, 0xfe, 0x23, 0xc5, 0x9a, 0x96, 0xb2, 0xfe, 0x48, 0xc6, 0x2a,
        0x21, 0x20, 0x88, 0x21, 0xec,
    ];

    let crypted = alice.encrypt(msg).unwrap();
    assert_eq!(expected_crypted, crypted.as_slice());
    expect_eq!(false, alice.is_counterparty(&bob));

    let decrypted = bob.decrypt(&crypted).unwrap();
    assert_eq!(msg, decrypted.as_slice());
    expect_eq!(true, alice.is_counterparty(&bob));

    // Encrypting the same value again should use a different nonce, and thus different ciphertext.
    let expected_crypted2 = [
        0x15, 0xad, 0x06, 0x40, 0x3f, 0x68, 0xfc, 0xed, 0x80, 0x2b, 0x37, 0x09, 0xac, 0x2e, 0x9a,
        0xb5, 0xed, 0x40, 0x91, 0x71, 0xc7, 0xfc, 0x23, 0xc0, 0xc0, 0xad, 0x53, 0x72, 0x97, 0xb7,
        0x00, 0x19, 0x04, 0x2e, 0x73, 0x32, 0x1b, 0xdd, 0x4d, 0x03, 0x8f, 0xe0, 0x23, 0x74, 0x19,
        0x60, 0xfc, 0x82, 0x43, 0x82, 0xda, 0x53, 0x87, 0xd9, 0x3b, 0x42, 0x32, 0x72, 0x7b, 0x89,
        0xfc, 0x86, 0xac, 0x08, 0x9b, 0xc2, 0x95, 0xba, 0x14, 0x3a, 0x86, 0x79, 0x68, 0x44, 0x3b,
        0xe8, 0x54, 0x06, 0x73, 0xda,
    ];
    let crypted = alice.encrypt(msg).unwrap();
    assert_eq!(expected_crypted2, crypted.as_slice());
    expect_eq!(false, alice.is_counterparty(&bob));

    let decrypted = bob.decrypt(&crypted).unwrap();
    assert_eq!(msg, decrypted.as_slice());
    expect_eq!(true, alice.is_counterparty(&bob));
}

/// Test KNpsk0 flow (QR-initiated transaction)
#[no_mangle]
pub extern "C" fn Rust_NoiseHandshakeKNpsk0() {
    let initiator_identity = ecdh_keygen(&EcCurve::P256).expect("initiator_identity");
    let initiator_pub = initiator_identity.public.key_data().expect("initiator_pub");
    expect_eq!(65, initiator_pub.len());
    expect_eq!(4, initiator_pub[0]);
    let psk = nss_rs::random();

    let (initiator_hs, initiator_msg) =
        HandshakeState::<Sha256>::initial_handshake_message(&psk, Some(initiator_identity), None)
            .expect("initial_handshake_message");

    let (mut responder_channel, responder_msg) = HandshakeState::<Sha256>::build_responder(
        &psk,
        None,
        Some(initiator_pub.as_slice().try_into().unwrap()),
        &initiator_msg,
    )
    .expect("build_responder");

    let (mut initiator_channel, _) = initiator_hs
        .process_handshake_response(&responder_msg)
        .expect("process_handshake_response");

    // There's no point in continuing if the channels are not counterparties.
    assert!(
        initiator_channel.is_counterparty(&responder_channel),
        "initiator and responder must be counterparties",
    );

    // responder -> initiator
    let msg = b"Hi initiator!";
    let ct = responder_channel.encrypt(msg).unwrap();
    expect_ne!(msg, ct.as_slice());

    let pt = initiator_channel.decrypt(&ct).unwrap();
    expect_eq!(msg, pt.as_slice());

    // Decrypting the responder's message again should fail
    expect_eq!(true, initiator_channel.decrypt(&ct).is_err());

    // initiator -> responder
    let msg = b"G'day, responder!";
    let ct = initiator_channel.encrypt(msg).unwrap();
    expect_ne!(msg, ct.as_slice());

    let pt = responder_channel.decrypt(&ct).unwrap();
    expect_eq!(msg, pt.as_slice());

    // Decrypting the initiator's message again should fail
    expect_eq!(true, responder_channel.decrypt(&ct).is_err());
}

/// Test NKpsk0 flow (state-assisted transaction)
#[no_mangle]
pub extern "C" fn Rust_NoiseHandshakeNKpsk0() {
    let initiator_identity = ecdh_keygen(&EcCurve::P256).expect("initiator_identity");
    let initiator_pub = initiator_identity.public.key_data().expect("initiator_pub");
    expect_eq!(65, initiator_pub.len());
    expect_eq!(4, initiator_pub[0]);

    let responder_identity = ecdh_keygen(&EcCurve::P256).expect("responder_identity");
    let responder_pub = responder_identity.public.key_data().expect("responder_pub");
    expect_eq!(65, responder_pub.len());
    expect_eq!(4, responder_pub[0]);

    let psk = nss_rs::random();

    let (initiator_hs, initiator_msg) = HandshakeState::<Sha256>::initial_handshake_message(
        &psk,
        Some(initiator_identity),
        Some(responder_pub.as_slice().try_into().unwrap()),
    )
    .expect("initial_handshake_message");

    let (mut responder_channel, responder_msg) = HandshakeState::<Sha256>::build_responder(
        &psk,
        Some(responder_identity),
        Some(initiator_pub.as_slice().try_into().unwrap()),
        &initiator_msg,
    )
    .expect("build_responder");

    let (mut initiator_channel, _) = initiator_hs
        .process_handshake_response(&responder_msg)
        .expect("process_handshake_response");

    // There's no point in continuing if the channels are not counterparties.
    assert!(
        initiator_channel.is_counterparty(&responder_channel),
        "initiator and responder must be counterparties",
    );

    // responder -> initiator
    let msg = b"Hi initiator!";
    let ct = responder_channel.encrypt(msg).unwrap();
    expect_ne!(msg, ct.as_slice());

    let pt = initiator_channel.decrypt(&ct).unwrap();
    expect_eq!(msg, pt.as_slice());

    // initiator -> responder
    let msg = b"G'day, responder!";
    let ct = initiator_channel.encrypt(msg).unwrap();
    expect_ne!(msg, ct.as_slice());

    let pt = responder_channel.decrypt(&ct).unwrap();
    expect_eq!(msg, pt.as_slice());
}

/// Test NKpsk0 flow (state-assisted transaction) with no initiator identity
#[no_mangle]
pub extern "C" fn Rust_NoiseHandshakeNKpsk0NoInitiatorIdentity() {
    let responder_identity = ecdh_keygen(&EcCurve::P256).expect("responder_identity");
    let responder_pub = responder_identity.public.key_data().expect("responder_pub");
    expect_eq!(65, responder_pub.len());
    expect_eq!(4, responder_pub[0]);

    let psk = nss_rs::random();

    let (initiator_hs, initiator_msg) = HandshakeState::<Sha256>::initial_handshake_message(
        &psk,
        None,
        Some(responder_pub.as_slice().try_into().unwrap()),
    )
    .expect("initial_handshake_message");

    let (mut responder_channel, responder_msg) = HandshakeState::<Sha256>::build_responder(
        &psk,
        Some(responder_identity),
        None,
        &initiator_msg,
    )
    .expect("build_responder");

    let (mut initiator_channel, _) = initiator_hs
        .process_handshake_response(&responder_msg)
        .expect("process_handshake_response");

    // There's no point in continuing if the channels are not counterparties.
    assert!(
        initiator_channel.is_counterparty(&responder_channel),
        "initiator and responder must be counterparties",
    );

    // responder -> initiator
    let msg = b"Hi initiator!";
    let ct = responder_channel.encrypt(msg).unwrap();
    expect_ne!(msg, ct.as_slice());

    let pt = initiator_channel.decrypt(&ct).unwrap();
    expect_eq!(msg, pt.as_slice());

    // initiator -> responder
    let msg = b"G'day, responder!";
    let ct = initiator_channel.encrypt(msg).unwrap();
    expect_ne!(msg, ct.as_slice());

    let pt = responder_channel.decrypt(&ct).unwrap();
    expect_eq!(msg, pt.as_slice());
}

/// Test incorrect psk flows
#[no_mangle]
pub extern "C" fn Rust_NoiseHandshakeErrors() {
    let initiator_identity = ecdh_keygen(&EcCurve::P256).expect("initiator_identity");
    let initiator_pub: [u8; 65] = initiator_identity
        .public
        .key_data()
        .expect("initiator_pub")
        .try_into()
        .unwrap();
    expect_eq!(4, initiator_pub[0]);

    let responder_identity = ecdh_keygen(&EcCurve::P256).expect("responder_identity");
    let responder_pub: [u8; 65] = responder_identity
        .public
        .key_data()
        .expect("responder_pub")
        .try_into()
        .unwrap();
    expect_eq!(4, responder_pub[0]);

    let psk = nss_rs::random();

    // Missing key arguments
    expect_eq!(
        true,
        HandshakeState::<Sha256>::initial_handshake_message(&psk, None, None).is_err()
    );
    let fake: [u8; 128] = nss_rs::random();
    expect_eq!(
        true,
        HandshakeState::<Sha256>::build_responder(&psk, None, None, &fake).is_err()
    );

    let (initiator_hs, mut initiator_msg) =
        HandshakeState::<Sha256>::initial_handshake_message(&psk, Some(initiator_identity), None)
            .expect("initial_handshake_message");

    // Invalid initiator message
    assert_eq!(
        true,
        HandshakeState::<Sha256>::build_responder(
            &psk,
            None,
            Some(&initiator_pub),
            &initiator_msg[..64],
        )
        .is_err()
    );

    // Set invalid point form
    expect_eq!(4, initiator_msg[0]);
    initiator_msg[0] = 1;
    assert_eq!(true, HandshakeState::<Sha256>::build_responder(
        &psk,
        None,
        Some(&initiator_pub),
        &initiator_msg,
    ).is_err());

    // Reset point form
    initiator_msg[0] = 4;
    let (_, mut responder_msg) =
        HandshakeState::<Sha256>::build_responder(&psk, None, Some(&initiator_pub), &initiator_msg)
            .expect("build_responder");

    // Return an incorrect responder message.
    // We can only do this once, because process_handshake_response mutates internal state.
    // Set invalid point form
    expect_eq!(4, responder_msg[0]);
    responder_msg[0] = 1;
    expect_eq!(
        true,
        initiator_hs
            .process_handshake_response(&responder_msg)
            .is_err()
    );
}
