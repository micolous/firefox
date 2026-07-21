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
use nss_rs::aead::Aead;
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

/// Test that a [`Channel`] encrypts with a consistent, known result.
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
}
