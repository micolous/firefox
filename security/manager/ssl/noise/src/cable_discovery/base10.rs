/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE base10 encode/decode

/// Chunk size for input/decoded data
const CHUNK_SIZE: usize = 7;

/// Chunk size for output/encoded data
const CHUNK_DIGITS: usize = 17;

pub const fn encoded_size(len: usize) -> usize {
    (match len % CHUNK_SIZE {
        6 => 15,
        5 => 13,
        4 => 10,
        3 => 8,
        2 => 5,
        1 => 3,
        0 => 0,
        // Shouldn't happen
        _ => unreachable!(),
    }) + (len / CHUNK_SIZE * CHUNK_DIGITS)
}

/// The decoded size of some base10-encoded data, in bytes.
///
/// Returns `None` on invalid lengths.
pub const fn decoded_size(len: usize) -> Option<usize> {
    let r = match len % CHUNK_DIGITS {
        15 => 6,
        13 => 5,
        10 => 4,
        8 => 3,
        5 => 2,
        3 => 1,
        0 => 0,
        // Invalid
        _ => return None,
    };

    Some(r + (len / CHUNK_DIGITS * CHUNK_SIZE))
}
