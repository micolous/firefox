/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use authenticator::{
    AuthenticatorInfo, BlinkResult, CtapVersionSupport, FidoDevice, FidoDeviceIO, FidoProtocol,
    Pin, StatusUpdate,
    crypto::{PinUvAuthToken, SharedSecret},
    ctap2::commands::{RequestCtap1, RequestCtap2, client_pin::PinUvAuthTokenPermission},
    errors::{CommandError, HIDError},
};
use nserror::{NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG, NS_OK, nsresult};
use nsstring::{nsACString, nsCString};
use serde_cbor_2::from_slice;
use std::{
    fmt::Debug, io::ErrorKind, sync::{
        Mutex, MutexGuard, mpsc::{sync_channel, Receiver, Sender, SyncSender},
    }, time::Duration,
};
use xpcom::{
    RefPtr,
    interfaces::{
        nsICtapCableInitiatorDiscoverySession, nsICtapCableWebSocket, nsICtapCableWebSocketChannel,
    },
    xpcom, xpcom_method,
};

#[xpcom(implement(nsICtapCableWebSocketCallback), atomic)]
pub struct CableDevice {
    inner: Mutex<CableDeviceInner>,
    recv_queue: SyncSender<Vec<u8>>,
}

struct CableDeviceInner {
    authenticator_info: Option<AuthenticatorInfo>,
    handshake_hash: Vec<u8>,
    channel: Option<RefPtr<nsICtapCableWebSocketChannel>>,
    recv_queue: Receiver<Vec<u8>>,

    ws: RefPtr<nsICtapCableWebSocket>,
    discovery: RefPtr<nsICtapCableInitiatorDiscoverySession>,
}

// impl<T: CableIO> From<T> for CableDevice<T> {
//     fn from(channel: T) -> Self {
//         Self {
//             authenticator_info: None,
//             channel,
//         }
//     }
// }

impl CableDevice {
    pub fn new() -> Result<RefPtr<Self>, nsresult> {
        let (tx, rx) = sync_channel(1);
        let inner = CableDeviceInner {
            authenticator_info: None,
            handshake_hash: Vec::new(),
            channel: None,
            recv_queue: rx,
            ws: todo!(),
            discovery: todo!(),
        };

        Ok(CableDevice::allocate(InitCableDevice {
            inner: Mutex::new(inner),
            recv_queue: tx,
        }))

    }

    fn get_self(&self) -> Result<MutexGuard<'_, CableDeviceInner>, nsresult> {
        self.inner.lock().map_err(|_| NS_ERROR_FAILURE)
    }

    // nsICtapCableWebSocketCallback
    xpcom_method!(status_update => StatusUpdate(status: u32));
    fn status_update(&self, status: u32) -> Result<(), nsresult> {
        println!("status_update: {status}");
        Ok(())
    }

    xpcom_method!(reject => Reject(error: nsresult));
    fn reject(&self, error: nsresult) -> Result<(), nsresult> {
        println!("reject: {error:?}");
        Ok(())
    }

    xpcom_method!(handshake_complete => HandshakeComplete(
        aPostHandshakeMessage: *const nsACString,
        aHandshakeHash: *const nsACString,
        aChannel: *const nsICtapCableWebSocketChannel
    ));
    fn handshake_complete(
        &self,
        post_handshake_message: &nsACString,
        handshake_hash: &nsACString,
        channel: &nsICtapCableWebSocketChannel,
    ) -> Result<(), nsresult> {
        println!("handshake_complete: {post_handshake_message:?}");
        let mut guard = self.get_self()?;
        guard.set_authenticator_info(from_slice(post_handshake_message).map_err(|e| {
            error!("deserialize failed: {e:?}");
            NS_ERROR_INVALID_ARG
        })?);
        guard.handshake_hash = handshake_hash.to_vec();
        guard.channel = Some(RefPtr::new(channel));

        Ok(())
    }

    xpcom_method!(cable_message => CableMessage(aMessage: *const nsACString));
    fn cable_message(&self, message: &nsACString) -> Result<(), nsresult> {
        println!("cable_message: {message:?}");
        self.recv_queue.send(message.to_vec()).map_err(|e| {
            error!("failed to push message: {:?}", e.0);
            NS_ERROR_FAILURE
        })
    }
}

impl Debug for CableDeviceInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CableDeviceInner")
            .field("authenticator_info", &self.authenticator_info)
            .finish()
    }
}

impl FidoDevice for CableDeviceInner {
    fn pre_init(&mut self) -> Result<(), HIDError> {
        Ok(())
    }

    fn init(&mut self) -> Result<(), HIDError> {
        Ok(())
    }

    fn initialized(&self) -> bool {
        self.authenticator_info.is_some()
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
        self.authenticator_info = Some(authenticator_info);
    }

    fn get_protocol(&self) -> FidoProtocol {
        FidoProtocol::CTAP2
    }

    fn downgrade_to_ctap1(&mut self) -> Result<(), HIDError> {
        Err(HIDError::UnexpectedVersion)
    }

    fn get_shared_secret(&self) -> Option<&SharedSecret> {
        None
    }

    fn set_shared_secret(&mut self, _secret: SharedSecret) {}

    fn block_and_blink(&mut self, _keep_alive: &dyn Fn() -> bool) -> BlinkResult {
        // caBLE is implicitly selected
        BlinkResult::DeviceSelected
    }

    fn establish_shared_secret(
        &mut self,
        _alive: &dyn Fn() -> bool,
    ) -> Result<SharedSecret, HIDError> {
        Err(HIDError::UnsupportedCommand)
    }

    fn get_pin_token(
        &mut self,
        _pin: &Option<Pin>,
        _alive: &dyn Fn() -> bool,
    ) -> Result<PinUvAuthToken, HIDError> {
        Err(HIDError::UnsupportedCommand)
    }

    fn get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        _pin: &Option<Pin>,
        _permission: PinUvAuthTokenPermission,
        _rp_id: Option<&String>,
        _alive: &dyn Fn() -> bool,
    ) -> Result<PinUvAuthToken, HIDError> {
        Err(HIDError::UnsupportedCommand)
    }

    fn get_pin_uv_auth_token_using_uv_with_permissions(
        &mut self,
        _permission: PinUvAuthTokenPermission,
        _rp_id: Option<&String>,
        _alive: &dyn Fn() -> bool,
    ) -> Result<PinUvAuthToken, HIDError> {
        Err(HIDError::UnsupportedCommand)
    }
}

impl FidoDeviceIO for CableDeviceInner {
    fn send_msg_cancellable<Out, Req: RequestCtap1<Output = Out> + RequestCtap2<Output = Out>>(
        &mut self,
        msg: &Req,
        keep_alive: &dyn Fn() -> bool,
        status: Option<&Sender<StatusUpdate>>,
    ) -> Result<Out, HIDError> {
        self.send_cbor_cancellable(msg, keep_alive, status)
    }

    fn send_cbor_cancellable<Req: RequestCtap2>(
        &mut self,
        msg: &Req,
        keep_alive: &dyn Fn() -> bool,
        _status: Option<&Sender<StatusUpdate>>,
    ) -> Result<Req::Output, HIDError> {
        let channel = self
            .channel
            .as_ref()
            .ok_or(HIDError::DeviceNotInitialized)?;

        let mut req_cbor = msg.wire_format()?;
        req_cbor.insert(0, /* typeCTAP */ 1);
        let req_cbor = nsCString::from(req_cbor);

        unsafe {
            let r = channel.Write(&*req_cbor);
            if r != NS_OK {
                error!("cable write error: {r:?}");
                return Err(HIDError::DeviceError);
            }
        }

        while keep_alive() {
            let resp_cbor = self
                .recv_queue
                .recv_timeout(Duration::from_millis(500))
                .map_err(|_| HIDError::DeviceError)?;

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
        _msg: &Req,
        _keep_alive: &dyn Fn() -> bool,
        _status: Option<&Sender<StatusUpdate>>,
    ) -> Result<Req::Output, HIDError> {
        Err(HIDError::UnexpectedVersion)
    }
}

impl CtapVersionSupport for CableDeviceInner {
    fn supports_ctap1(&self) -> bool {
        false
    }

    fn supports_ctap2(&self) -> bool {
        true
    }
}
