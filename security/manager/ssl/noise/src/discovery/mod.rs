/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery and XPCOM bindings.

mod authenticator_session;
mod initiator_session;
mod params;
#[cfg(feature = "xpcom")]
mod service;
mod suffix;

use crate::{hash::Hash as _, hex, Error, Result, Sha256};
use nss_rs::{p11, random, IntoResult as _, SECItemBorrowed, SymKey};
use pkcs11_bindings::{CKA_ENCRYPT, CKA_SIGN, CKM_AES_CBC};
use sha2::Digest;
use std::ptr::null_mut;

pub use self::{
    authenticator_session::AuthenticatorSession, initiator_session::InitiatorSession,
    params::Params, suffix::Suffix,
};

const QR_PROTOCOL: &str = "FIDO:/";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
enum KeyPurpose {
    EidKey = 1,
    TunnelID = 2,
    Psk = 3,
}

#[derive(Clone)]
pub struct EidKey {
    encryption_key: SymKey,
    signing_key: SymKey,
}

/// Unencrypted form of EID (authenticator's BLE advertisement).
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Eid {
    /// Tunnel server ID from an authenticator's EID BLE advertisement.
    tunnel_server_id: u16,

    /// Routing ID from an authenticator's EID BLE advertisement.
    routing_id: [u8; 3],

    /// Authenticator-generated random nonce, sent to the initator in the EID BLE advertisement.
    nonce: [u8; 10],

    /// The transport selected by the authenticator.
    transport: u32,
}

#[derive(Clone)]
pub struct SharedSecret(pub(self) [u8; 16]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelID([u8; 16]);

impl KeyPurpose {
    /// Derive caBLE material for this [`KeyPurpose`][].
    pub fn derive(self, ikm: &[u8], salt: &[u8], count: usize) -> Result<Vec<u8>> {
        nss_rs::init()?;

        let info = (self as u32).to_le_bytes();
        Sha256::hkdf_bytes(salt, ikm, &info, count)
    }
}

impl Eid {
    /// Create a new EID (authenticator's BLE advertisement) in unencrypted form, with a random
    /// nonce.
    pub fn new(tunnel_server_id: u16, routing_id: [u8; 3], transport: u32) -> Option<Self> {
        if tunnel_server_id < 256 && tunnel_server_id >= (KNOWN_TUNNEL_SERVER_DOMAINS.len() as u16)
        {
            return None;
        }

        if transport > Params::TRANSPORT_L2CAP {
            return None;
        }

        Some(Self {
            tunnel_server_id,
            routing_id,
            nonce: random(),
            transport,
        })
    }

    #[cfg(test)]
    /// Create a new EID (authenticator's BLE advertisement) in unencrypted form, with a
    /// fixed nonce, for tests.
    pub fn new_with_nonce_for_tests(
        tunnel_server_id: u16,
        routing_id: [u8; 3],
        transport: u32,
        nonce: [u8; 10],
    ) -> Self {
        Self {
            tunnel_server_id,
            routing_id,
            nonce,
            transport,
        }
    }

    pub fn tunnel_server_id(&self) -> u16 {
        self.tunnel_server_id
    }

    pub fn routing_id(&self) -> [u8; 3] {
        self.routing_id
    }

    pub fn transport(&self) -> u32 {
        self.transport
    }

    /// Parse a decrypted advertisement from the authenticator.
    pub fn from_decrypted_bytes(eid: &[u8; 16], suffix: Option<&[u8]>) -> Option<Self> {
        if eid[0] != 0 {
            // Reserved bits
            return None;
        }

        let nonce = [
            eid[1], eid[2], eid[3], eid[4], eid[5], eid[6], eid[7], eid[8], eid[9], eid[10],
        ];
        let routing_id = [eid[11], eid[12], eid[13]];
        let tunnel_server_id = u16::from_le_bytes([eid[14], eid[15]]);

        if usize::from(tunnel_server_id) > KNOWN_TUNNEL_SERVER_DOMAINS.len()
            && tunnel_server_id < 256
        {
            // Invalid
            return None;
        }

        let mut eid = Self {
            nonce,
            tunnel_server_id,
            routing_id,
            transport: 0,
        };

        if let Some(suffix) = suffix.and_then(|s| Suffix::from_cbor(s).ok()) {
            if let Some(transport_channel_identifier) = suffix.transport_channel_identifier {
                eid.transport = transport_channel_identifier;
            }
        }

        Some(eid)
    }

    /// Serialize advertisement parameters as an unencrypted EID.
    pub fn to_decrypted_bytes(&self) -> Result<Vec<u8>> {
        let mut o = Vec::with_capacity(16);
        o.push(0);
        o.extend_from_slice(&self.nonce);
        o.extend_from_slice(&self.routing_id);
        o.extend_from_slice(&self.tunnel_server_id.to_le_bytes());

        if self.transport != 0 {
            let suffix = Suffix {
                transport_channel_identifier: Some(self.transport),
            };

            if let Some(cbor) = suffix.as_cbor()? {
                o.extend_from_slice(&cbor);
            }
        }

        Ok(o)
    }
}

impl SharedSecret {
    pub fn random() -> Self {
        SharedSecret(random())
    }

    pub fn to_tunnel_id(&self) -> Result<TunnelID> {
        KeyPurpose::TunnelID
            .derive(&self.0, &[], 16)?
            .try_into()
            .map(TunnelID)
            .map_err(|_| Error::Internal)
    }

    /// Derive the EID key from the shared secret.
    pub fn to_eid_key(&self) -> Result<EidKey> {
        let eid_key = KeyPurpose::EidKey.derive(&self.0, &[], 64)?;
        let (encryption_key, signing_key) = eid_key.split_at(32);

        let slot = p11::Slot::internal()?;
        let mut encryption_key = SECItemBorrowed::wrap(encryption_key)?;
        let encryption_key = unsafe {
            p11::PK11_ImportSymKey(
                *slot,
                CKM_AES_CBC,
                p11::PK11Origin::PK11_OriginUnwrap,
                CKA_ENCRYPT,
                encryption_key.as_mut(),
                null_mut(),
            )
        }
        .into_result()?;

        let mut signing_key = SECItemBorrowed::wrap(signing_key)?;
        let signing_key = unsafe {
            p11::PK11_ImportSymKey(
                *slot,
                Sha256::HMAC_ALGORITHM,
                p11::PK11Origin::PK11_OriginUnwrap,
                CKA_SIGN,
                signing_key.as_mut(),
                null_mut(),
            )
        }
        .into_result()?;

        Ok(EidKey {
            encryption_key,
            signing_key,
        })
    }
}

impl AsRef<[u8; 16]> for TunnelID {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::ops::Deref for TunnelID {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TunnelID {
    pub fn encode_hex(&self) -> String {
        hex(self.0)
    }
}

// Unsafe APIs that should only be used in unit tests.
#[cfg(test)]
impl From<[u8; 16]> for SharedSecret {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

#[cfg(test)]
impl From<[u8; 16]> for TunnelID {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

const KNOWN_TUNNEL_SERVER_DOMAINS: [&str; 2] = ["cable.ua5v.com", "cable.auth.com"];

/// Decode a tunnel server ID into a domain name.
///
/// Returns `None` for invalid or unknown tunnel server IDs.
pub fn decode_tunnel_server_id(tunnel_server_id: u16) -> Option<String> {
    const TUNNEL_SERVER_SALT: &[u8; 31] = b"caBLEv2 tunnel server domain\0\0\0";
    const TUNNEL_SERVER_ID_OFFSET: usize = TUNNEL_SERVER_SALT.len() - 3;
    const TUNNEL_SERVER_TLDS: [&str; 4] = [".com", ".org", ".net", ".info"];
    const BASE32_CHARS: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

    if tunnel_server_id < 256 {
        return KNOWN_TUNNEL_SERVER_DOMAINS
            .get(usize::from(tunnel_server_id))
            .map(|d| d.to_string());
    }

    let mut hash_input = *TUNNEL_SERVER_SALT;
    hash_input[TUNNEL_SERVER_ID_OFFSET..TUNNEL_SERVER_ID_OFFSET + 2]
        .copy_from_slice(&tunnel_server_id.to_le_bytes());
    let hash = Sha256::digest(hash_input);

    let mut v = u64::from_le_bytes(hash[..8].try_into().ok()?);
    let tld = TUNNEL_SERVER_TLDS[(v & 3) as usize];
    v >>= 2;

    let len = 6 + 5 + (62 - v.leading_zeros() as usize).div_ceil(5);
    let mut r = String::with_capacity(len);
    r.push_str("cable.");

    while v != 0 {
        let c = char::from_u32(BASE32_CHARS[(v & 31) as usize] as u32)?;
        r.push(c);
        v >>= 5;
    }

    r.push_str(tld);

    Some(r)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tunnel_server() {
        assert_eq!("cable.ua5v.com", decode_tunnel_server_id(0).unwrap());
        assert_eq!("cable.auth.com", decode_tunnel_server_id(1).unwrap());
        assert_eq!(
            "cable.qz2ekwmnd332c.info",
            decode_tunnel_server_id(256).unwrap()
        );
        for s in 2..=255 {
            assert!(
                decode_tunnel_server_id(s).is_none(),
                "tunnel server {s} should be invalid"
            );
        }
    }

    #[test]
    fn discovery() {
        let shared_secret = SharedSecret::from([0; 16]);
        let p =
            Params::new_with_shared_secret(shared_secret).expect("Params::new_with_shared_secret");

        let tunnel_id = p.tunnel_id();
        let expected_tunnel_id = TunnelID::from([
            0x3e, 0xef, 0x97, 0x09, 0x79, 0x86, 0x41, 0x3b, 0x05, 0x9e, 0xaa, 0x2a, 0x30, 0xd6,
            0x53, 0xd4,
        ]);
        assert_eq!(&expected_tunnel_id, tunnel_id);

        // Known response for secret
        let shared_secret = SharedSecret::from([
            0x01, 0xfe, 0xa6, 0xf7, 0xc4, 0x80, 0x74, 0x93, 0xdc, 0x25, 0x6f, 0x9e, 0xac, 0xf7,
            0x56, 0xc9,
        ]);

        let p =
            Params::new_with_shared_secret(shared_secret).expect("Params::new_with_shared_secret");
        let mut initiator = InitiatorSession::new_with_params(p).expect("InitiatorSession::new");

        let encrypted_eid = [
            0x02, 0x7d, 0x84, 0xed, 0x60, 0x76, 0xb5, 0x5e, 0x24, 0x7c, 0x83, 0x0f, 0x82, 0x95,
            0x5e, 0x4d, 0x12, 0x6e, 0x7f, 0x43,
        ];
        let expected = Eid::new_with_nonce_for_tests(
            0,
            [0x02, 0x65, 0x55],
            0,
            [0x8b, 0xb5, 0xc5, 0xc9, 0xa4, 0x4d, 0x91, 0x3a, 0x5e, 0xb2],
        );

        assert!(
            initiator.try_decrypt_eid(&encrypted_eid, None),
            "InitiatorSession::try_decrypt_eid"
        );

        let eid = initiator.eid();
        assert_eq!(Some(&expected), eid);

        assert_eq!(
            "wss://cable.ua5v.com/cable/connect/026555/367CBBF5F5085DF4098476AFE4B9B1D2",
            initiator.websocket_url()
        );
    }
}
