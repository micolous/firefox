/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! `nsICtapBleManager` implementation
use crate::{
    central::{Central, CtapBleCentral},
    Error, Result,
};
use log::*;
use nserror::{nsresult, NS_OK};
use thin_vec::{thin_vec, ThinVec};
use xpcom::{interfaces::nsICtapBleCentral, RefPtr};

#[xpcom(implement(nsICtapBleManager), atomic)]
pub struct Manager {}

impl Manager {
    xpcom_method!(get_centrals => GetCentrals() -> ThinVec<Option<RefPtr<nsICtapBleCentral>>>);
    fn get_centrals(&self) -> Result<ThinVec<Option<RefPtr<nsICtapBleCentral>>>> {
        warn!("get_centrals not implemented");
        let central: RefPtr<CtapBleCentral> = Central::new_mock()?.into();
        let interface = central
            .query_interface::<nsICtapBleCentral>()
            .ok_or(Error::Internal)?;
        Ok(thin_vec![Some(interface)])
    }
}

#[no_mangle]
pub unsafe extern "C" fn ctap_ble_manager_constructor(
    iid: *const xpcom::nsIID,
    result: *mut *mut xpcom::reexports::libc::c_void,
) -> nserror::nsresult {
    let manager: RefPtr<Manager> = Manager::allocate(InitManager {});
    unsafe { manager.QueryInterface(iid, result) }
}
