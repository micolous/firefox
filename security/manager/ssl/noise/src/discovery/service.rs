/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery service

use crate::{
    discovery::{
        authenticator_session::CtapCableAuthenticatorDiscoverySession,
        initiator_session::CtapCableInitiatorDiscoverySession, AuthenticatorSession,
        InitiatorSession,
    },
    Error, Result,
};
use nserror::{nsresult, NS_ERROR_FAILURE, NS_OK};
use nsstring::nsACString;
use xpcom::{
    interfaces::{
        nsICtapCableAuthenticatorDiscoverySession, nsICtapCableInitiatorDiscoverySession,
    },
    RefPtr,
};

/// `nsICtapCableDiscoveryService`-compatible XPCOM wrapper for [`Service`][].
#[xpcom(implement(nsICtapCableDiscoveryService), atomic)]
pub struct CtapCableDiscoveryService {}

impl CtapCableDiscoveryService {
    xpcom_method!(start_initiator => StartInitiator() -> *const nsICtapCableInitiatorDiscoverySession);
    fn start_initiator(&self) -> Result<RefPtr<nsICtapCableInitiatorDiscoverySession>> {
        let session = InitiatorSession::new()?;
        let session: RefPtr<CtapCableInitiatorDiscoverySession> = session.into();
        session
            .query_interface::<nsICtapCableInitiatorDiscoverySession>()
            .ok_or(Error::Internal)
    }

    xpcom_method!(start_authenticator =>
        StartAuthenticator(aURL: *const nsACString) -> *const nsICtapCableAuthenticatorDiscoverySession);
    fn start_authenticator(
        &self,
        url: &nsACString,
    ) -> Result<RefPtr<nsICtapCableAuthenticatorDiscoverySession>> {
        let url = url.to_string();
        let session = AuthenticatorSession::new_with_qr_url(url)?;
        let session: RefPtr<CtapCableAuthenticatorDiscoverySession> = session.into();
        session
            .query_interface::<nsICtapCableAuthenticatorDiscoverySession>()
            .ok_or(Error::Internal)
    }
}

/// Create a new `nsICtapCableDiscoveryService`-compatible [`Service`][]
#[no_mangle]
pub unsafe extern "C" fn ctap_cable_discovery_service_constructor(
    iid: *const xpcom::nsIID,
    result: *mut *mut xpcom::reexports::libc::c_void,
) -> nsresult {
    if nss_rs::init().is_err() {
        return NS_ERROR_FAILURE;
    }

    let service: RefPtr<CtapCableDiscoveryService> =
        CtapCableDiscoveryService::allocate(InitCtapCableDiscoveryService {});

    unsafe { service.QueryInterface(iid, result) }
}
