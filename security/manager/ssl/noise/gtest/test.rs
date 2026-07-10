#![allow(non_snake_case)]

extern crate noise;
extern crate nss_rs;

use noise::*;
use nss_rs::aead::{Aead, AeadAlgorithms};
use std::{ffi::CString, fmt::Write, os::raw::c_char};

fn nonfatal_fail(msg: String) {
    extern "C" {
        fn GTest_ExpectFailure(message: *const c_char);
    }
    unsafe {
        let msg = CString::new(msg).unwrap();
        GTest_ExpectFailure(msg.as_ptr());
    }
}

/// This macro checks if the two arguments are equal, and causes a non-fatal
/// GTest test failure if they are not.
macro_rules! expect_eq {
    ($x:expr, $y:expr) => {
        match (&$x, &$y) {
            (x, y) => {
                if *x != *y {
                    nonfatal_fail(format!(
                        "check failed: (`{:?}` == `{:?}`) at {}:{}",
                        x,
                        y,
                        file!(),
                        line!()
                    ))
                }
            }
        }
    };
}

macro_rules! expect_ne {
    ($x:expr, $y:expr) => {
        match (&$x, &$y) {
            (x, y) => {
                if *x == *y {
                    nonfatal_fail(format!(
                        "check failed: (`{:?}` != `{:?}`) at {}:{}",
                        x,
                        y,
                        file!(),
                        line!()
                    ))
                }
            }
        }
    };
}


#[no_mangle]
pub extern "C" fn Rust_NoiseChannelEncryptDecrypt() {
    let key0 = Aead::import_key(AeadAlgorithms::Aes256Gcm, &[42; 32]).unwrap();
    let key1 = Aead::import_key(AeadAlgorithms::Aes256Gcm, &[67; 32]).unwrap();

    let mut alice = Channel::new(key0.clone(), key1.clone());
    let mut bob = Channel::new(key1.clone(), key0.clone());
    // let mut corrupted = Channel::new(key1, key0);

    for l in 0..512 {
        let msg = vec![0xff; l];
        let crypted = alice.encrypt(&msg).unwrap();
        let decrypted = bob.decrypt(&crypted).unwrap();
        expect_eq!(msg.as_slice(), decrypted.as_slice());
        expect_ne!(msg.as_slice(), crypted.as_slice());

        // Corrupt the message
        // if l > 0 {
        //     crypted[(l * 3) * l] ^= 1;
        // }
        // corrupted.reader.set_nonce(bob.reader.get_nonce());
        // assert!(corrupted.decrypt(&crypted).is_err());
    }
}
