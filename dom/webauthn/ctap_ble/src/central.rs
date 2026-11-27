/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! `nsICtapBleCentral` implementation
use crate::{Error, Result};
use log::*;
use moz_task::RunnableBuilder;
use nserror::{nsresult, NS_OK};
use nsstring::{nsACString, nsCString};
use std::{
    sync::{Mutex, MutexGuard},
    time::Duration,
};
use thin_vec::{thin_vec, ThinVec};
use xpcom::{interfaces::nsICtapBleCentralEventCallback, nsID, RefPtr};

#[derive(Default, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    #[default]
    Unknown = 0,
    Off = 1,
    On = 2,
}

#[derive(Debug)]
pub struct Advert {
    pub peripheral_id: ThinVec<u8>,
    pub service_id: nsID,
    pub data: ThinVec<u8>,
}

pub struct Central {
    callback: Option<RefPtr<nsICtapBleCentralEventCallback>>,
    // mock_adverts: Vec<Advert>,
}

impl Central {
    /// Create a new mock BLE central.
    pub fn new_mock() -> Result<Self> {
        Ok(Self {
            callback: None,
            // mock_adverts: Vec::new(),
        })
    }

    pub fn start_scan(
        &mut self,
        _duration: Duration,
        callback: RefPtr<nsICtapBleCentralEventCallback>,
    ) -> Result {
        warn!("start_scan not implemented");
        self.callback = Some(callback);
        Ok(())
    }

    pub fn stop_scan(&mut self) -> Result {
        warn!("stop_scan not implemented");
        self.callback = None;
        Ok(())
    }

    pub fn get_adapter_name(&self) -> Result<String> {
        warn!("get_adapter_name not implemented");
        Ok("Bluey".to_string())
    }

    pub fn get_state(&self) -> Result<State> {
        warn!("get_state not implemented");
        Ok(State::On)
    }

    pub fn insert_mock_service_data_advert(&mut self, advert: Advert) -> Result {
        // self.mock_adverts.push(advert);
        self.send_advert(advert)
    }

    fn send_advert(&self, advert: Advert) -> Result {
        let Some(ref callback) = self.callback else {
            return Err(Error::Internal);
        };

        let r = unsafe {
            callback.ServiceDataAdvert(&advert.peripheral_id, &advert.service_id, &advert.data)
        };
        r.to_result().map_err(Error::from)
    }
}

#[xpcom(implement(nsICtapBleCentral), atomic)]
pub struct CtapBleCentral {
    inner: Mutex<Central>,
}

impl From<Central> for RefPtr<CtapBleCentral> {
    fn from(value: Central) -> Self {
        CtapBleCentral::allocate(InitCtapBleCentral {
            inner: Mutex::new(value),
        })
    }
}

impl CtapBleCentral {
    fn get_self(&self) -> Result<MutexGuard<'_, Central>> {
        self.inner.lock().map_err(|_| Error::Internal)
    }

    xpcom_method!(start_scan => StartScan(
        aDurationMS: u32,
        aCallback: *const nsICtapBleCentralEventCallback
    ));
    fn start_scan(&self, duration_ms: u32, callback: &nsICtapBleCentralEventCallback) -> Result {
        let mut this = self.get_self()?;
        this.start_scan(
            Duration::from_millis(duration_ms.into()),
            RefPtr::new(callback),
        )
    }

    xpcom_method!(stop_scan => StopScan());
    fn stop_scan(&self) -> Result {
        let mut this = self.get_self()?;
        this.stop_scan()
    }

    xpcom_method!(get_adapter_name => GetAdapterName() -> nsACString);
    fn get_adapter_name(&self) -> Result<nsCString> {
        let this = self.get_self()?;
        this.get_adapter_name().map(nsCString::from)
    }

    xpcom_method!(get_state => GetState() -> u8);
    fn get_state(&self) -> Result<u8> {
        let this = self.get_self()?;
        this.get_state().map(|r| r as u8)
    }

    xpcom_method!(insert_mock_service_data_advert => InsertMockServiceDataAdvert(
        aPeripheralID: *const ThinVec<u8>,
        aServiceID: *const nsID,
        aData: *const ThinVec<u8>
    ));
    fn insert_mock_service_data_advert(
        &self,
        peripheral_id: &ThinVec<u8>,
        service_id: &nsID,
        data: &ThinVec<u8>,
    ) -> Result {
        let advert = Advert {
            peripheral_id: peripheral_id.clone(),
            service_id: *service_id,
            data: data.clone(),
        };
        let mut this = self.get_self()?;
        this.insert_mock_service_data_advert(advert)
    }
}
