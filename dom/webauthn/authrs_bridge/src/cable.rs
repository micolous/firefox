/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use authenticator::{
    authenticatorservice::{RegisterArgs, SignArgs},
    crypto::{PinUvAuthToken, SharedSecret},
    ctap2::commands::{client_pin::PinUvAuthTokenPermission, RequestCtap1, RequestCtap2},
    errors::{AuthenticatorError, CommandError, HIDError},
    statecallback::StateCallback,
    AuthenticatorInfo, BlinkResult, CtapVersionSupport, FidoDevice, FidoDeviceIO, FidoProtocol,
    Pin, SignResult, StatusUpdate,
};
use moz_task::{get_main_thread, RunnableBuilder};
use noise::{discovery::InitiatorSession, CtapCableInitiatorHandshake};
use nserror::{
    nsresult, NS_ERROR_DOM_INVALID_STATE_ERR, NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG, NS_OK,
};
use nsstring::{nsACString, nsCString};
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_cbor_2::from_slice;
use std::{
    fmt::{self, Debug},
    io::ErrorKind,
    sync::{
        mpsc::{sync_channel, Receiver, Sender, SyncSender},
        Mutex, MutexGuard,
    },
    time::Duration,
};
use thin_vec::{thin_vec, ThinVec};
use xpcom::{
    components::{CtapBleManager, CtapCableWebSocket},
    interfaces::{
        nsICtapBleCentral, nsICtapBleCentralEventCallback, nsICtapBleManager,
        nsICtapCableInitiatorDiscoverySession, nsICtapCableInitiatorHandshake,
        nsICtapCableWebSocket, nsICtapCableWebSocketCallback, nsICtapCableWebSocketChannel,
    },
    nsID, xpcom, xpcom_method, RefPtr, ThreadBoundRefPtr,
};

use crate::{AuthrsService, RegisterResult};

type Result<T = (), E = nsresult> = std::result::Result<T, E>;

/// Pre-standard caBLE service UUID, used by older devices.
const GOOGLE_CABLE_SERVICE: u16 = 0xfde2;
/// CTAP 2.3 caBLE service UUID.
const FIDO_CABLE_SERVICE: u16 = 0xfff9;

const GOOGLE_CABLE_UUID: nsID = uuid_from_u16(GOOGLE_CABLE_SERVICE);
const FIDO_CABLE_UUID: nsID = uuid_from_u16(FIDO_CABLE_SERVICE);

/// Convert a 16-bit short BLE UUID into a full-length [`nsID`].
///
/// Reference: [Bluetooth Core Specification 6.0, Volume 3, Part B, Section 2.5.1 (UUID)][0].
///
/// [0]: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host/service-discovery-protocol--sdp--specification.html#UUID-5f7f2ee0-5e87-0c77-417f-fd7aac61f6f5
const fn uuid_from_u16(short: u16) -> nsID {
    nsID(
        short as u32,
        0,
        0x1000,
        [0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb],
    )
}

fn get_central() -> Result<RefPtr<nsICtapBleCentral>> {
    let manager = CtapBleManager::service::<nsICtapBleManager>()?;
    let mut centrals = ThinVec::new();
    unsafe { manager.GetCentrals(&mut centrals) }.to_result()?;

    if centrals.len() != 1 {
        error!("Expected 1 central, got {}", centrals.len());
        return Err(NS_ERROR_FAILURE);
    }

    let Some(central) = centrals[0].clone() else {
        error!("Central contained None?");
        return Err(NS_ERROR_FAILURE);
    };

    Ok(central)
}

pub(crate) struct CableTokenManager {
    central: Option<RefPtr<nsICtapBleCentral>>,
    pending_session: Option<PendingSession>,
}

pub struct PendingSession {
    discovery: InitiatorSession,
    status: Sender<StatusUpdate>,
    ws: RefPtr<nsICtapCableWebSocket>,
    ceremony: Ceremony,
}

pub enum Ceremony {
    Register {
        args: RegisterArgs,
        callback: StateCallback<authenticator::Result<RegisterResult>>,
    },
    Sign {
        args: SignArgs,
        callback: StateCallback<authenticator::Result<SignResult>>,
    },
}

/// Insert a dummy advertisement for testing.
fn insert_fake_advert(interface: RefPtr<nsICtapBleCentral>) -> Result {
    let peripheral_id = thin_vec![0xab, 0x12];
    let service_id = nsID(
        0xfff9,
        0,
        0x1000,
        [0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb],
    );
    let data = thin_vec![
        0xa1, 0x73, 0xa4, 0x06, 0x8d, 0xab, 0x49, 0x8d, 0xc9, 0x6b, 0xe2, 0x80, 0xf2, 0x32, 0x07,
        0x07, 0x9c, 0xa9, 0x21, 0x0d
    ];

    let main_thread = get_main_thread()?;
    let interface = ThreadBoundRefPtr::new(interface);

    RunnableBuilder::new("AuthrsService::insert_fake_advert", move || {
        unsafe {
            interface
                .get_ref()
                .expect("nsICtapBleCentral for fake advert")
                .InsertMockServiceDataAdvert(&peripheral_id, &service_id, &data)
        }
        .to_result()
        .unwrap();
    })
    .dispatch(main_thread.coerce())
}

impl CableTokenManager {
    pub fn new() -> Result<Self> {
        Ok(CableTokenManager {
            central: None,
            pending_session: None,
        })
    }

    fn start_scanning(&mut self, service: &AuthrsService, timeout: u32) -> Result {
        let central = get_central()?;
        let interface = service
            .query_interface::<nsICtapBleCentralEventCallback>()
            .ok_or(NS_ERROR_FAILURE)?;

        unsafe { central.StartScan(timeout, &*interface) }.to_result()?;
        insert_fake_advert(central.clone())?;
        self.central = Some(central);
        Ok(())
    }

    pub fn register(
        &mut self,
        service: &AuthrsService,
        timeout: u32,
        args: RegisterArgs,
        discovery: InitiatorSession,
        status: Sender<StatusUpdate>,
        callback: StateCallback<authenticator::Result<RegisterResult>>,
    ) {
        warn!("cable: register not implemented");
        if args.use_ctap1_fallback {
            error!("Cannot use CTAP1 over caBLE");
            callback.call(Err(AuthenticatorError::HIDError(
                HIDError::UnexpectedVersion,
            )));
        }

        if let Err(e) = self.start_scanning(service, timeout) {
            callback.call(Err(AuthenticatorError::Custom(format!("nserror: {e:?}"))));
            return;
        }

        let ws = match CtapCableWebSocket::create() {
            Ok(w) => w,
            Err(e) => {
                callback.call(Err(AuthenticatorError::Custom(format!(
                    "websocket error: {e:?}"
                ))));
                return;
            }
        };

        self.pending_session = Some(PendingSession {
            discovery,
            status,
            ws,
            ceremony: Ceremony::Register { args, callback },
        });

        // TODO: more
    }

    pub fn sign(
        &mut self,
        service: &AuthrsService,
        timeout: u32,
        args: SignArgs,
        discovery: InitiatorSession,
        status: Sender<StatusUpdate>,
        callback: StateCallback<authenticator::Result<SignResult>>,
    ) {
        warn!("cable: sign not implemented");
        if args.use_ctap1_fallback {
            error!("Cannot use CTAP1 over caBLE");
            callback.call(Err(AuthenticatorError::HIDError(
                HIDError::UnexpectedVersion,
            )));
        }

        if let Err(e) = self.start_scanning(service, timeout) {
            callback.call(Err(AuthenticatorError::Custom(format!("nserror: {e:?}"))));
            return;
        }

        let ws = match CtapCableWebSocket::create() {
            Ok(w) => w,
            Err(e) => {
                callback.call(Err(AuthenticatorError::Custom(format!(
                    "websocket error: {e:?}"
                ))));
                return;
            }
        };

        self.pending_session = Some(PendingSession {
            discovery,
            status,
            ws,
            ceremony: Ceremony::Sign { args, callback },
        });

        // TODO: more
    }

    pub fn service_data_advert(
        &mut self,
        peripheral_id: &ThinVec<u8>,
        service_id: &nsID,
        data: &ThinVec<u8>,
    ) -> Result {
        info!("service_data_advert: {peripheral_id:?}, {service_id:?}, {data:?}");
        let Some(pending_session) = &mut self.pending_session else {
            return Err(NS_ERROR_DOM_INVALID_STATE_ERR);
        };

        let service_id = service_id.clone();
        if GOOGLE_CABLE_UUID != service_id && FIDO_CABLE_UUID != service_id {
            // Not for us.
            return Ok(());
        }

        if data.len() < 20 {
            warn!("caBLE advertisement too short: {data:?}");
            return Ok(());
        }

        let Ok(encrypted_eid) = &data[..20].try_into() else {
            warn!("caBLE advertisement wrong length: {data:?}");
            return Ok(());
        };

        if pending_session.discovery.found_authenticator() {
            warn!("Already found a matching authenticator");
        }

        let success = pending_session
            .discovery
            .try_decrypt_eid(encrypted_eid, None);
        if success {
            info!("Connecting to WebSocket...");
            let pending_session = self.pending_session.take().unwrap();
            CableDevice::new(pending_session).expect("websocket failure");
        } else {
            info!("Unknown caBLE advertisement: {encrypted_eid:?}");
        }

        Ok(())
    }

    pub fn state_update(&mut self, state: u8) -> Result {
        warn!("state_update not implemented: {state}");

        Ok(())
    }

    pub fn stopped(&mut self) -> Result {
        warn!("stopped not implemented");

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PostHandshakeMessage {
    pub info: AuthenticatorInfo,
}

macro_rules! parse_next_optional_value {
    ($name:expr, $map:expr) => {
        if $name.is_some() {
            return Err(serde::de::Error::duplicate_field("$name"));
        }
        $name = Some($map.next_value()?);
    };
}

impl<'de> Deserialize<'de> for PostHandshakeMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PostHandshakeMessageVisitor;

        impl<'de> Visitor<'de> for PostHandshakeMessageVisitor {
            type Value = PostHandshakeMessage;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut info = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        // padding
                        0x00 => (),

                        0x01 => {
                            parse_next_optional_value!(info, map);
                        }

                        _ => (),
                    }
                }

                if let Some(info) = info {
                    Ok(PostHandshakeMessage { info })
                } else {
                    Err(M::Error::custom(
                        "No GetInfo response specified".to_string(),
                    ))
                }
            }
        }

        deserializer.deserialize_bytes(PostHandshakeMessageVisitor)
    }
}

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
    status: Sender<StatusUpdate>,
    ws: RefPtr<nsICtapCableWebSocket>,
    ceremony: Ceremony,
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
    pub fn new(pending_session: PendingSession) -> Result {
        let (tx, rx) = sync_channel(1);

        let inner = CableDeviceInner {
            authenticator_info: None,
            handshake_hash: Vec::new(),
            channel: None,
            recv_queue: rx,
            status: pending_session.status,
            ws: pending_session.ws,
            ceremony: pending_session.ceremony,
        };

        let websocket_url = nsCString::from(pending_session.discovery.websocket_url());

        let handshake: RefPtr<CtapCableInitiatorHandshake> = pending_session.discovery.as_handshake()?.into();
        let handshake_intf = handshake
            .query_interface::<nsICtapCableInitiatorHandshake>()
            .ok_or(NS_ERROR_FAILURE)?;

        let device = CableDevice::allocate(InitCableDevice {
            inner: Mutex::new(inner),
            recv_queue: tx,
        });

        let cb_intf = device
            .query_interface::<nsICtapCableWebSocketCallback>()
            .ok_or(NS_ERROR_FAILURE)?;

        let guard = device.inner.lock().unwrap();

        unsafe {
            guard
                .ws
                .ConnectToAuthenticator(&*handshake_intf, &*websocket_url, &*cb_intf)
        }
        .to_result()
    }

    fn get_self(&self) -> Result<MutexGuard<'_, CableDeviceInner>> {
        self.inner.lock().map_err(|_| NS_ERROR_FAILURE)
    }

    // nsICtapCableWebSocketCallback
    xpcom_method!(status_update => StatusUpdate(status: u32));
    fn status_update(&self, status: u32) -> Result {
        info!("status_update: {status}");
        Ok(())
    }

    xpcom_method!(reject => Reject(error: nsresult));
    fn reject(&self, error: nsresult) -> Result {
        info!("reject: {error:?}");
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
    ) -> Result {
        info!("handshake_complete: {post_handshake_message:?}");
        let mut guard = self.get_self()?;
        let post_handshake_message: PostHandshakeMessage = from_slice(post_handshake_message)
            .map_err(|e| {
                error!("deserialize failed: {e:?}");
                NS_ERROR_INVALID_ARG
            })?;
        guard.set_authenticator_info(post_handshake_message.info);
        guard.handshake_hash = handshake_hash.to_vec();
        guard.channel = Some(RefPtr::new(channel));

        // TODO: send the request in self.ceremony

        Ok(())
    }

    xpcom_method!(cable_message => CableMessage(aMessage: *const nsACString));
    fn cable_message(&self, message: &nsACString) -> Result {
        info!("cable_message: {message:?}");
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

#[cfg(test)]
mod test {
    use crate::cable::{uuid_from_u16, FIDO_CABLE_UUID, GOOGLE_CABLE_UUID};

    #[test]
    fn uuid() {
        assert_eq!(
            FIDO_CABLE_UUID.to_string(),
            "0000fff9-0000-1000-8000-00805f9b34fb"
        );
        assert_eq!(
            GOOGLE_CABLE_UUID.to_string(),
            "0000fde2-0000-1000-8000-00805f9b34fb"
        );
    }
}
