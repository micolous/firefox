/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::{fmt::Debug, io::ErrorKind};

use authenticator::{
    AuthenticatorInfo, BlinkResult, FidoDevice, FidoDeviceIO, FidoProtocol, Pin,
    crypto::{PinUvAuthToken, SharedSecret},
    ctap2::commands::{RequestCtap1, RequestCtap2, client_pin::PinUvAuthTokenPermission},
    errors::{CommandError, HIDError},
};
use serde_cbor_2::from_slice;

pub trait CableIO: Debug {
    type Error: std::error::Error;

    fn read_msg(&mut self, keep_alive: &dyn Fn() -> bool) -> Result<Vec<u8>, Self::Error>;
    fn send_msg(&mut self, msg: &[u8]) -> Result<(), Self::Error>;
    fn get_info_bytes(&self) -> Result<&[u8], Self::Error>;
}

#[derive(Debug)]
pub struct CableDevice<T: CableIO> {
    authenticator_info: Option<AuthenticatorInfo>,
    channel: T,
}

impl<T: CableIO> From<T> for CableDevice<T> {
    fn from(channel: T) -> Self {
        Self {
            authenticator_info: None,
            channel,
        }
    }
}

impl<T: CableIO> FidoDevice for CableDevice<T> {
    fn pre_init(&mut self) -> Result<(), HIDError> {
        Ok(())
    }

    fn init(&mut self) -> Result<(), HIDError> {
        let get_info_bytes = self
            .channel
            .get_info_bytes()
            .map_err(|_| HIDError::DeviceError)?;

        self.authenticator_info =
            Some(from_slice(get_info_bytes).map_err(CommandError::Deserializing)?);

        Ok(())
    }

    fn initialized(&self) -> bool {
        true
    }

    fn is_u2f(&mut self) -> bool {
        true
    }

    fn should_try_ctap2(&self) -> bool {
        true
    }

    fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        self.authenticator_info.as_ref()
    }

    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
        let _ = authenticator_info;
        panic!("shouldn't call");
    }

    fn get_protocol(&self) -> FidoProtocol {
        FidoProtocol::CTAP2
    }

    fn downgrade_to_ctap1(&mut self) {}

    fn get_shared_secret(&self) -> Option<&SharedSecret> {
        None
    }

    fn set_shared_secret(&mut self, secret: SharedSecret) {
        let _ = secret;
    }

    fn block_and_blink(&mut self, keep_alive: &dyn Fn() -> bool) -> BlinkResult {
        // caBLE is implicitly selected
        Ok(BlinkResult::Selected)
    }

    fn establish_shared_secret(
        &mut self,
        alive: &dyn Fn() -> bool,
    ) -> Result<SharedSecret, HIDError> {
        let _ = alive;
        Err(HIDError::UnsupportedCommand)
    }

    fn get_pin_token(
        &mut self,
        pin: &Option<Pin>,
        alive: &dyn Fn() -> bool,
    ) -> Result<PinUvAuthToken, HIDError> {
        let _ = pin;
        let _ = alive;
        Err(HIDError::UnsupportedCommand)
    }

    fn get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        pin: &Option<Pin>,
        permission: PinUvAuthTokenPermission,
        rp_id: Option<&String>,
        alive: &dyn Fn() -> bool,
    ) -> Result<PinUvAuthToken, HIDError> {
        let _ = pin;
        let _ = permission;
        let _ = rp_id;
        let _ = alive;
        Err(HIDError::UnsupportedCommand)
    }

    fn get_pin_uv_auth_token_using_uv_with_permissions(
        &mut self,
        permission: PinUvAuthTokenPermission,
        rp_id: Option<&String>,
        alive: &dyn Fn() -> bool,
    ) -> Result<PinUvAuthToken, HIDError> {
        let _ = permission;
        let _ = rp_id;
        let _ = alive;
        Err(HIDError::UnsupportedCommand)
    }
}

impl<T: CableIO> FidoDeviceIO for CableDevice<T> {
    fn send_msg_cancellable<Out, Req: RequestCtap1<Output = Out> + RequestCtap2<Output = Out>>(
        &mut self,
        msg: &Req,
        keep_alive: &dyn Fn() -> bool,
    ) -> Result<Out, HIDError> {
        self.send_cbor_cancellable(msg, keep_alive)
    }

    fn send_cbor_cancellable<Req: RequestCtap2>(
        &mut self,
        msg: &Req,
        keep_alive: &dyn Fn() -> bool,
    ) -> Result<Req::Output, HIDError> {
        let mut req_cbor = msg.wire_format()?;
        req_cbor.insert(0, /* typeCTAP */ 1);
        self.channel.send_msg(&req_cbor).map_err(|_| HIDError::DeviceError)?;

        // send here

        while keep_alive() {
            let resp_cbor = self.channel.read_msg(keep_alive).map_err(|_| HIDError::DeviceError)?;

            if resp_cbor.is_empty() {
                return Err(HIDError::DeviceError);
            }

            let msg_type = resp_cbor[0];
            match msg_type {
                0 => {
                    // Shutdown
                    return Err(HIDError::IO(None, ErrorKind::ConnectionReset.into()));
                }

                1 => {
                    // CBOR
                    return msg.handle_response_ctap2(self, &resp_cbor[1..]);
                }

                2 => {
                    // Linking info, ignore
                }

                t => return Err(HIDError::UnexpectedCmd(t)),
            }
        }

        Err(HIDError::DeviceError)
    }

    fn send_ctap1_cancellable<Req: RequestCtap1>(
        &mut self,
        msg: &Req,
        keep_alive: &dyn Fn() -> bool,
    ) -> Result<Req::Output, HIDError> {
        let _ = msg;
        let _ = keep_alive;
        Err(HIDError::UnexpectedVersion)
    }
}
