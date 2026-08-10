/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise discovery tests.

use noise::{discovery::*, Error};
use nss_rs::random;

#[test]
fn chromium() {
    nss_rs::init().expect("nss_rs::init");

    let u = "FIDO:/162870791865632382552704231438327900152302540348097243854039966655366469794954476199158014113179232779520163209900691930075274801398564434658077048963842109321447142660";
    let session = AuthenticatorSession::new_with_qr_url(u).expect("new_with_qr_url");

    assert_eq!("mc", session.request_type);
    assert_eq!(2, session.known_domain_count);
    assert_eq!(1666589051, session.timestamp);
    assert!(session.supports_websocket_transport);
    assert!(!session.supports_l2cap_transport);
    assert!(session.supports_state_assisted_transactions);
    assert_eq!(
        "88EA778BEF7FEF7474BBCE36A2EFA282",
        session.tunnel_id().encode_hex()
    );

    // Chromium 145
    let u = "FIDO:/258473327900755586143665566879417871127860505704909541444130070144141296274130454836270492384743490254202060441129710420074451564345311200244582987727618109321447142404";
    let session = AuthenticatorSession::new_with_qr_url(u).expect("new_with_qr_url");

    assert_eq!("mc", session.request_type);
    assert_eq!(2, session.known_domain_count);
    assert_eq!(1785912832, session.timestamp);
    assert!(session.supports_websocket_transport);
    assert!(!session.supports_l2cap_transport);
    assert!(!session.supports_state_assisted_transactions);
    assert_eq!(
        "7ADA6999389F52D8EE291DF0E83337C9",
        session.tunnel_id().encode_hex()
    );
}

#[test]
fn safari_ios() {
    nss_rs::init().expect("nss_rs::init");

    let u = "FIDO:/089962132878132862898875319509818655951233947060166026934941652203853844930597225184066237811614893181300344014421205790072080843938838513707157859599106109321447142404";
    let session = AuthenticatorSession::new_with_qr_url(u).expect("new_with_qr_url");

    assert_eq!("mc", session.request_type);
    assert_eq!(2, session.known_domain_count);
    assert_eq!(1670820400, session.timestamp);
    assert!(session.supports_websocket_transport);
    assert!(!session.supports_l2cap_transport);
    assert!(!session.supports_state_assisted_transactions);
    assert_eq!(
        "0E3C01B56A36DA8997401413E3F7A783",
        session.tunnel_id().encode_hex()
    );
}

/// Start an initiator session, and attempt to "discover" it.
#[test]
fn discovery() {
    nss_rs::init().expect("nss_rs::init");

    let mut initiator = InitiatorSession::new().expect("InitiatorSession::new");
    initiator.request_type = "mc".to_string();
    assert_eq!(2, initiator.known_domain_count);
    assert!(initiator.supports_websocket_transport);
    assert!(!initiator.supports_l2cap_transport);
    assert!(!initiator.supports_state_assisted_transactions);
    assert!(!initiator.found_authenticator());
    assert!(initiator.websocket_url().is_empty());
    assert_ne!([0u8; 16].as_slice(), initiator.tunnel_id().as_slice());

    #[cfg(feature = "system-time")]
    assert_ne!(0, initiator.timestamp);

    let qr = initiator.qr_url().expect("InitiatorSession::qr_url");
    assert!(
        qr.starts_with("FIDO:/"),
        "should start with FIDO:/ : {qr:?}"
    );

    // Create random BLE beacon, it shouldn't be decrypted.
    let other_encrypted_eid = random();
    let r = initiator.try_decrypt_eid(&other_encrypted_eid, None);
    assert!(!r, "shouldn't be able to decrypt the other EID");
    assert!(!initiator.found_authenticator());
    assert!(initiator.eid().is_none());

    // "scan" the QR code with the actual authenticator
    let mut authenticator =
        AuthenticatorSession::new_with_qr_url(&qr).expect("AuthenticatorSession::new_with_qr_url");

    // Request parameters should be propagated
    assert_eq!(initiator.request_type, authenticator.request_type);
    assert_eq!(
        initiator.known_domain_count,
        authenticator.known_domain_count
    );
    assert_eq!(
        initiator.supports_websocket_transport,
        authenticator.supports_websocket_transport
    );
    assert_eq!(
        initiator.supports_l2cap_transport,
        authenticator.supports_l2cap_transport
    );
    assert_eq!(
        initiator.supports_state_assisted_transactions,
        authenticator.supports_state_assisted_transactions
    );
    assert_eq!(initiator.timestamp, authenticator.timestamp);

    // Should get the same tunnel metadata
    assert_eq!(initiator.tunnel_id(), authenticator.tunnel_id());

    // Prepare a BLE beacon to respond
    let eid = Eid::new(0, [0xc0, 0xff, 0xee], Params::TRANSPORT_WEBSOCKETS).expect("Eid::new");
    let encrypted_eid = authenticator
        .encrypt_eid(eid)
        .expect("AuthenticatorSession::encrypt_eid");
    let authenticator_eid = authenticator.eid().expect("AuthenticatorSession::eid");

    // We didn't pick a transport, so this should be exactly 20 bytes
    assert_eq!(20, encrypted_eid.len());

    // Receive the BLE beacon
    let r = initiator.try_decrypt_eid(encrypted_eid.as_slice().try_into().unwrap(), None);
    assert!(r, "should be able to decrypt the EID");

    assert!(initiator.found_authenticator());

    // Our settings should propagate
    let initiator_eid = initiator.eid().expect("InitiatorSession::eid");
    assert_eq!(
        authenticator_eid.tunnel_server_id(),
        initiator_eid.tunnel_server_id()
    );
    assert_eq!(authenticator_eid.routing_id(), initiator_eid.routing_id());
    assert_eq!(authenticator_eid.transport(), initiator_eid.transport());

    assert_eq!(
        format!(
            "wss://cable.ua5v.com/cable/connect/C0FFEE/{}",
            initiator.tunnel_id().encode_hex()
        ),
        initiator.websocket_url()
    );

    // A wild iPhone appears!
    let mut authenticator =
        AuthenticatorSession::new_with_qr_url(&qr).expect("AuthenticatorSession::new_with_qr_url");
    // iPhone uses new key material!
    let eid = Eid::new(1, [0xca, 0xfe, 0x42], Params::TRANSPORT_WEBSOCKETS).expect("Eid::new");
    let encrypted_eid = authenticator
        .encrypt_eid(eid)
        .expect("AuthenticatorSession::encrypt_eid");
    assert_eq!(20, encrypted_eid.len());
    let authenticator_eid = authenticator.eid().expect("AuthenticatorSession::eid");

    // Receive the iPhone's BLE beacon
    let r = initiator.try_decrypt_eid(encrypted_eid.as_slice().try_into().unwrap(), None);
    assert!(r, "should be able to decrypt the EID");
    assert!(initiator.found_authenticator());

    // We should now be talking to the iPhone.
    let initiator_eid = initiator.eid().expect("InitiatorSession::eid");
    assert_eq!(
        authenticator_eid.tunnel_server_id(),
        initiator_eid.tunnel_server_id()
    );
    assert_eq!(authenticator_eid.routing_id(), initiator_eid.routing_id());
    assert_eq!(authenticator_eid.transport(), initiator_eid.transport());
    let authenticator_ws = format!(
        "wss://cable.auth.com/cable/connect/CAFE42/{}",
        initiator.tunnel_id().encode_hex()
    );
    assert_eq!(authenticator_ws, initiator.websocket_url());

    // Create another random BLE beacon, it shouldn't be decrypted.
    let other_encrypted_eid = random();
    let r = initiator.try_decrypt_eid(&other_encrypted_eid, None);
    assert!(!r, "shouldn't be able to decrypt the other EID");

    // Should still be set up for the iPhone.
    assert!(initiator.found_authenticator());
    assert_eq!(authenticator_ws, initiator.websocket_url());

    // Establish a Noise channel
    let initiator_hs = initiator
        .as_handshake()
        .expect("InitiatorSession::into_handshake");

    let mut authenticator = authenticator
        .as_responder(initiator_hs.initial_message())
        .expect("AuthenticatorSession::into_responder");

    let mut initiator = initiator_hs
        .process_handshake_response(&authenticator.response_message)
        .expect("InitiatorHandshake::process_handshake_response");

    // authenticator -> initiator
    let msg = b"Hi initiator!";
    let ct = authenticator.encrypt(msg).unwrap();
    assert_ne!(msg, ct.as_slice());

    let pt = initiator.decrypt(&ct).unwrap();
    assert_eq!(msg, pt.as_slice());

    // Decrypting the authenticator's message again should fail
    assert!(initiator.decrypt(&ct).is_err());

    // initiator -> authenticator
    let msg = b"G'day, authenticator!";
    let ct = initiator.encrypt(msg).unwrap();
    assert_ne!(msg, ct.as_slice());

    let pt = authenticator.decrypt(&ct).unwrap();
    assert_eq!(msg, pt.as_slice());

    // Decrypting the initiator's message again should fail
    assert!(authenticator.decrypt(&ct).is_err());
}

/// Bad initiator parameters
#[test]
fn bad_params() {
    nss_rs::init().expect("nss_rs::init");

    let mut initiator = InitiatorSession::new().expect("InitiatorSession::new");

    assert_eq!(
        Error::InvalidArgument,
        initiator.qr_url().expect_err("no request type should fail")
    );

    initiator.request_type = "mc".to_string();
    initiator.supports_websocket_transport = false;
    assert_eq!(
        Error::InvalidArgument,
        initiator.qr_url().expect_err("no transports should fail")
    );

    initiator.supports_l2cap_transport = true;
    let qr = initiator
        .qr_url()
        .expect("only L2CAP transport should succeed");

    let mut authenticator =
        AuthenticatorSession::new_with_qr_url(&qr).expect("AuthenticatorSession::new_with_qr_url");

    let eid = Eid::new(1, [0xca, 0xfe, 0x42], Params::TRANSPORT_WEBSOCKETS).expect("Eid::new");
    assert_eq!(
        Error::InvalidArgument,
        authenticator
            .encrypt_eid(eid)
            .expect_err("unsupported transport should fail")
    );

    let eid = Eid::new(1, [0xca, 0xfe, 0x42], Params::TRANSPORT_L2CAP).expect("Eid::new");
    let encrypted_eid = authenticator
        .encrypt_eid(eid)
        .expect("supported transport should succeed");
    assert_eq!(23, encrypted_eid.len());

    let (encrypted_eid, suffix) = encrypted_eid.as_slice().split_at(20);
    let r = initiator.try_decrypt_eid(encrypted_eid.try_into().unwrap(), Some(suffix));
    assert!(r, "should be able to decrypt the EID");
    assert!(initiator.found_authenticator());
    assert_eq!("", initiator.websocket_url());
}
