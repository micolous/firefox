/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery service

use crate::Result;
use nserror::{nsresult, NS_ERROR_FAILURE, NS_ERROR_NOT_IMPLEMENTED, NS_OK};
use nsstring::nsACString;
use xpcom::{
    interfaces::{
        nsICtapCableAuthenticatorDiscoverySession, nsICtapCableDiscoveryParams,
        nsICtapCableInitiatorDiscoverySession,
    },
    RefPtr,
};

/// Discovery service singleton.
pub struct Service {}

/// `nsICtapCableDiscoveryService`-compatible XPCOM wrapper for [`Service`][].
#[xpcom(implement(nsICtapCableDiscoveryService), atomic)]
pub struct XPCService {}

impl XPCService {
    xpcom_method!(start_initiator =>
        StartInitiator(aParams: *const nsICtapCableDiscoveryParams) -> *const nsICtapCableInitiatorDiscoverySession);
    fn start_initiator(
        &self,
        params: &nsICtapCableDiscoveryParams,
    ) -> Result<RefPtr<nsICtapCableInitiatorDiscoverySession>> {
        let _ = params;
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(start_authenticator =>
        StartAuthenticator(aURL: *const nsACString) -> *const nsICtapCableAuthenticatorDiscoverySession);
    fn start_authenticator(
        &self,
        url: &nsACString,
    ) -> Result<RefPtr<nsICtapCableAuthenticatorDiscoverySession>> {
        let _ = url;
        Err(NS_ERROR_NOT_IMPLEMENTED)
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

    let service: RefPtr<XPCService> = XPCService::allocate(InitXPCService {});

    unsafe { service.QueryInterface(iid, result) }
}
