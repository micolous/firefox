/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise discovery tests.

use noise::discovery::*;

fn discovery() {
    let shared_secret = SharedSecret::from([0; 16]);
    let p = Params::new_with_shared_secret_for_tests(shared_secret)
        .expect("Params::new_with_shared_secret");

    let tunnel_id = p.tunnel_id();
    let expected_tunnel_id = TunnelID::from([
        0x3e, 0xef, 0x97, 0x09, 0x79, 0x86, 0x41, 0x3b, 0x05, 0x9e, 0xaa, 0x2a, 0x30, 0xd6, 0x53,
        0xd4,
    ]);
    expect_eq!(&expected_tunnel_id, tunnel_id);

    // Known response for secret
    let shared_secret = SharedSecret::from([
        1, 254, 166, 247, 196, 128, 116, 147, 220, 37, 111, 158, 172, 247, 86, 201,
    ]);
    let encrypted_eid = [
        2, 125, 132, 237, 96, 118, 181, 94, 36, 124, 131, 15, 130, 149, 94, 77, 18, 110, 127, 67,
    ];
    let expected = Eid::new_with_nonce_for_tests(
        0,
        [2, 101, 85],
        0,
        [139, 181, 197, 201, 164, 77, 145, 58, 94, 178],
    );

    let p = Params::new_with_shared_secret_for_tests(shared_secret)
        .expect("Params::new_with_shared_secret");

    let mut initiator = InitiatorSession::new(p).expect("InitiatorSession::new");
    let success = initiator.try_decrypt_eid(&encrypted_eid, None);
    expect_eq!(true, success);

    let eid = initiator.eid();
    expect_eq!(Some(&expected), eid);

    expect_eq!(
        "wss://cable.ua5v.com/cable/connect/026555/367CBBF5F5085DF4098476AFE4B9B1D2",
        initiator.websocket_url()
    );
}
