/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery service

use crate::Result;
use nserror::{nsresult, NS_ERROR_FAILURE, NS_ERROR_NOT_IMPLEMENTED, NS_OK};
use nsstring::nsACString;
use xpcom::{
    interfaces::{nsICableDiscoveryParams, nsICableDiscoverySession},
    RefPtr,
};

/// Discovery service singleton.
pub struct Service {}

/// `nsICableDiscoveryService`-compatible XPCOM wrapper for [`Service`][].
#[xpcom(implement(nsICableDiscoveryService), atomic)]
pub struct CableDiscoveryService {}

impl CableDiscoveryService {
    xpcom_method!(start_initiator =>
        StartInitiator(aParams: *const nsICableDiscoveryParams) -> *const nsICableDiscoverySession);
    fn start_initiator(
        &self,
        params: &nsICableDiscoveryParams,
    ) -> Result<RefPtr<nsICableDiscoverySession>> {
        let _ = params;
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(start_authenticator =>
        StartAuthenticator(aURL: *const nsACString) -> *const nsICableDiscoverySession);
    fn start_authenticator(&self, url: &nsACString) -> Result<RefPtr<nsICableDiscoverySession>> {
        let _ = url;
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }
}

/// Create a new `nsICableDiscoveryService`-compatible [`Service`][]
#[no_mangle]
pub unsafe extern "C" fn cable_discovery_service_constructor(
    iid: *const xpcom::nsIID,
    result: *mut *mut xpcom::reexports::libc::c_void,
) -> nsresult {
    if nss_rs::init().is_err() {
        return NS_ERROR_FAILURE;
    }

    let service: RefPtr<CableDiscoveryService> =
        CableDiscoveryService::allocate(InitCableDiscoveryService {});

    unsafe { service.QueryInterface(iid, result) }
}
