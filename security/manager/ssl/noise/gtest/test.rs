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

    for l in 0..512 {
        let msg = vec![0xff; l];

        // Synchronise the "corrupted" channel with "bob", such that it should
        // be able to decrypt the same messages (if they were valid).
        corrupted.set_reader_nonce(bob.get_reader_nonce());

        let mut crypted = alice.encrypt(&msg).unwrap();
        let decrypted = bob.decrypt(&crypted).unwrap();
        expect_eq!(alice.get_writer_nonce(), bob.get_reader_nonce());
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
