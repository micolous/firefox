/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";

/*

// ./mach run -- -jsconsole
// ENABLE NETWORK TRACING BEFORE STARTING!

let gCtapCableWebSocket = Cc[
  "@mozilla.org/webauthn/cable-websocket;1"
].createInstance(Ci.nsICtapCableWebSocket);
let gCtapCableDiscoveryService = Cc[
  "@mozilla.org/security/ctapcablediscoveryservice;1"
].createInstance(Ci.nsICtapCableDiscoveryService); 
class DummyCallback {
  QueryInterface = ChromeUtils.generateQI(["nsICtapCableWebSocketCallback"]);

  statusUpdate(status) {
    console.info('statusUpdate', status);
  }

  reject(error) {
    console.error('reject', error);
  }

  handshakeComplete(postHandshake, hash, channel) {
    console.info('handshakeComplete', postHandshake, hash, channel);
  }

  cableMessage(msg) {
    console.info('cableMessage', msg);
  }
}

cb = new DummyCallback();
let initiator = gCtapCableDiscoveryService.startInitiator();
initiator.requestType = "mc";
initiator.qrUrl

// copy FIDO:/ URL

RUST_LOG="debug" cargo run --example cable_tunnel --features ui-cli,cable,softtoken -- --stdout --softtoken-path /tmp/softtoken.dat -c FIDO:/

// copy payload

initiator.tryDecryptEID(Uint8Array.fromHex( '' ))

gCtapCableWebSocket.connectToAuthenticator(initiator.handshake(), initiator.webSocketUrl, cb);

*/

// const lazy = {};

// ChromeUtils.defineESModuleGetters(lazy, {
//   GeckoViewPrompter: "resource://gre/modules/GeckoViewPrompter.sys.mjs",
// });

/**
 * Create a connection to a WebSocket server
 * @param {string} uri WebSocket URI to connect to
 * @returns {nsIWebSocketProtocolHandler}
 */
function makeWebSocket(uri) {
  let scheme = uri.scheme;
  if (scheme != "ws" && scheme != "wss") {
    throw new Error(`uri scheme must be 'ws' or 'wss', got ${scheme}`);
  }

  // https://searchfox.org/firefox-main/rev/be3847db4e2bcc52fa3f078b8b4a1ff167ad158f/dom/push/PushServiceWebSocket.sys.mjs#470
  if (Services.io.offline) {
    lazy.console.warn("makeWebSocket: Network is offline.");
    return null;
  }

  let socket = Cc[`@mozilla.org/network/protocol;1?name=${scheme}`]
    .getService(Ci.nsIWebSocketProtocolHandler)
    .newWebSocketChannel();

  socket.initLoadInfo(
    null, // aLoadingNode
    Services.scriptSecurityManager.getSystemPrincipal(),
    null, // aTriggeringPrincipal
    Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
    Ci.nsIContentPolicy.TYPE_WEBSOCKET
  );
  // Allow deprecated HTTP request from SystemPrincipal
  socket.loadInfo.allowDeprecatedSystemRequests = true;

  return socket;
}

/**
 * The WebSocket is shut down.
 */
const STATE_SHUT_DOWN = 0;

/**
 * The WebSocket has been opened on the client side, waiting for start message.
 */
const STATE_WAITING_FOR_WS_START = 1;

/**
 * WebSocket opened, initial handshake sent, waiting for authenticator reply.
 */
const STATE_WAITING_FOR_HELLO = 2;

/**
 * WebSocket opened, waiting for post-handshake message.
 */
const STATE_WAITING_FOR_POST_HANDSHAKE = 3;

/**
 * Websocket operational, handshake completed, begin protocol messaging.
 */
const STATE_READY = 4;

class CtapCableChannel {
  QueryInterface = ChromeUtils.generateQI([
    "nsIWebSocketListener",
    "nsICtapCableWebSocketChannel",
  ]);

  _initiator = null;

  constructor(handshake, ws, callback) {
    if (handshake.consumed) {
      throw new Error("Handshake is already consumed!");
    }

    this._handshake = handshake;
    this._ws = ws;
    this._callback = callback;
    this._state = STATE_WAITING_FOR_WS_START;
  }

  // nsIWebSocketListener
  onStart() {
    if (this._state != STATE_WAITING_FOR_WS_START) {
      console.error("onStart: not waiting for start?");
      this._callback.reject(Cr.NS_ERROR_UNKNOWN);
      return;
    }

    this._state = STATE_WAITING_FOR_HELLO;
    this._ws.sendBinaryMsg(this._handshake.initialMessage);
  }

  onStop() {
    this._state = STATE_SHUT_DOWN;
    console.error("connection stopped");
    this._callback.reject(Cr.NS_ERROR_UNKNOWN);
  }

  onMessageAvailable() {
    this._state = STATE_SHUT_DOWN;
    console.error("unexpected text message");
    this._callback.reject(Cr.NS_ERROR_UNKNOWN);
  }

  onBinaryMessageAvailable(context, msg) {
    switch (this._state) {
      case STATE_WAITING_FOR_HELLO:
        // This is our handshake response
        if (this._handshake.consumed || this._initiator) {
          console.error("Handshake already consumed");
          this._state = STATE_SHUT_DOWN;
          this._ws.close(0, "handshake already consumed");
          this._callback.reject(Cr.NS_ERROR_UNKNOWN);
          throw new Error("Handshake already consumed");
        }

        try {
          this._initiator = this._handshake.processHandshakeResponse(msg);
          this._callback.statusUpdate(2 /* TODO */);
        } catch (e) {
          console.error("Noise handshake failed", e);
          this._state = STATE_SHUT_DOWN;
          this._ws.close(0, "bad handshake");
          this._callback.reject(Cr.NS_ERROR_UNKNOWN);
          throw new Error("Noise handshake failure");
        }

        this._state = STATE_WAITING_FOR_POST_HANDSHAKE;
        break;

      case STATE_WAITING_FOR_POST_HANDSHAKE:
        if (!this._initiator) {
          console.error("Bad state: no initiator?");
          this._state = STATE_SHUT_DOWN;
          this._ws.close(0, "invalid state");
          this._callback.reject(Cr.NS_ERROR_UNKNOWN);
          throw new Error("Bad state: no initiator?");
        }

        let postHandshakeMsg;
        try {
          postHandshakeMsg = this._initiator.decrypt(msg);
        } catch (e) {
          console.error("Noise post-handshake failed", e);
          this._state = STATE_SHUT_DOWN;
          this._ws.close(0, "bad post-handshake");
          this._callback.reject(Cr.NS_ERROR_UNKNOWN);
          throw new Error("Could not decrypt post-handshake message");
        }

        this._callback.handshakeComplete(
          postHandshakeMsg,
          this._initiator.handshakeHash,
          this
        );

        break;

      case STATE_READY:
        // Normal channel message
        if (!this._initiator) {
          console.error("Bad state: no initiator?");
          this._state = STATE_SHUT_DOWN;
          this._ws.close(0, "invalid state");
          this._callback.reject(Cr.NS_ERROR_UNKNOWN);
          throw new Error("Bad state: no initiator?");
        }

        let decryptedMsg;
        try {
          decryptedMsg = this._initiator.decrypt(msg);
        } catch (e) {
          console.error("Noise message decrypt failed", e);
          this._state = STATE_SHUT_DOWN;
          this._ws.close(0, "bad message");
          this._callback.reject(Cr.NS_ERROR_UNKNOWN);
          throw new Error("Could not decrypt message");
        }

        this._callback.cableMessage(descryptedMsg);
        break;

      default:
        console.error(`Bad state for onBinaryMessageAvailable: ${this._state}`);
        this._state = STATE_SHUT_DOWN;
        this._ws.close(0, "invalid state");
        this._callback.reject(Cr.NS_ERROR_UNKNOWN);
        throw new Error(
          `Bad state for onBinaryMessageAvailable: ${this._state}`
        );
    }
  }

  onAcknowledge() {}

  // nsICtapCableWebSocketChannel
  write(msg) {
    if (this._state != STATE_READY) {
      console.error(`Bad state for write: ${this._state}`);
      this._callback.reject(Cr.NS_ERROR_UNKNOWN);
      throw new Error(`Bad state for write: ${this._state}`);
    }

    this._ws.sendBinaryMsg(msg);
  }

  close() {
    this._state = STATE_SHUT_DOWN;
    this._ws.close(0, "closed");
  }
}

export class CtapCableWebSocket {
  _callback = null;
  _abortController = null;

  QueryInterface = ChromeUtils.generateQI(["nsICtapCableWebSocket"]);

  connectToAuthenticator(aHandshake, aWebSocketUrl, aCallback) {
    let uri = Services.io.newURI(aWebSocketUrl);
    let socket = makeWebSocket(uri);
    let ws = socket.QueryInterface(Ci.nsIWebSocketChannel);
    ws.protocol = "fido.cable";
    let channel = new CtapCableChannel(aHandshake, ws, aCallback);
    aCallback.statusUpdate(1 /* TODO */);

    try {
      ws.asyncOpen(uri, uri.spec, {}, 0, channel, null);
    } catch (e) {
      console.error("connectToAuthenticator: connection error", e);
      aCallback.reject(Cr.NS_ERROR_UNKNOWN);
    }
  }

  cancel() {
    console.error("cancel not implemented");
  }
}
