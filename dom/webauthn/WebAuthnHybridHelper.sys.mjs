/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { XPCOMUtils } from "resource://gre/modules/XPCOMUtils.sys.mjs";

const lazy = {};

XPCOMUtils.defineLazyServiceGetter(
  lazy,
  "bleManager",
  "@mozilla.org/webauthn/ctap-ble-manager;1",
  Ci.nsICtapBleManager
);

XPCOMUtils.defineLazyServiceGetter(
  lazy,
  "webauthnService",
  "@mozilla.org/webauthn/service;1",
  Ci.nsIWebAuthnService
);

ChromeUtils.defineESModuleGetters(lazy, {
  QRCodeGenerator:
    "moz-src:///browser/components/qrcode/QRCodeGenerator.sys.mjs",
});

export let WebAuthnHybridHelper = {
  _icon: "webauthn-notification-icon",
  _topic: "webauthn-hybrid",

  // The current notification, if any. The U2F manager is a singleton, we will
  // never allow more than one active request. And thus we'll never have more
  // than one notification either.
  _current: null,

  // The current transaction ID. Will be checked when we're notified of the
  // cancellation of an ongoing WebAuthhn request.
  _tid: 0,

  // Translation object
  _l10n: new Localization(
    ["branding/brand.ftl", "toolkit/webauthnDialog.ftl"],
    true
  ),

  observe(aSubject, aTopic, aData) {
    let _ = aSubject;

    // TODO: handle fullscreen blocking like WebAuthnPromptHelper.
    // But we might not need this if integrating into a platform-like WebAuthn
    // dialog.
    if (aTopic != this._topic) {
      return;
    }

    // BrowserHybridCommand
    let data = JSON.parse(aData);
    console.log("WebAuthn Hybrid command:", data);

    // If we receive a cancel, it might be a WebAuthn prompt starting in another
    // window, and the other window's browsing context will send out the
    // cancellations, so any cancel action we get should prompt us to cancel.
    if (data.command.type == "cancel") {
      this.cancel(data);
      return;
    }

    let browsingContext = BrowsingContext.get(data.browsingContextId);

    switch (data.command.type) {
      case "show-qr-code":
        this.show_qr_code(browsingContext, data);
        break;

      default:
        console.warn("Unkown WebAuthn Hybrid command:", data);
        break;
    }
  },

  async show_qr_code(
    browsingContext,
    { origin, tid, command: { qr, request_type } }
  ) {
    // WIP: Based on SharingUtilsCls::showQRCodePanel:
    // https://searchfox.org/firefox-main/rev/4de791e9c62b308a5ab1e4464dc1fd19d8c4d13b/browser/components/sharing/SharingUtils.sys.mjs#161
    //
    // TODO: build some custom UI for this.
    let qrCodeDataURI = null;
    try {
      qrCodeDataURI = await lazy.QRCodeGenerator.generateQRCode(qr);
    } catch (error) {
      console.error("Failed to generate QR code:", error);
      lazy.webauthnService.cancel(tid);
    }

    let mainAction = this.buildCancelAction(tid);
    try {
      origin = Services.io.newURI(origin).asciiHost;
    } catch (e) {
      /* Might fail for arbitrary U2F RP IDs. */
    }

    let params = {
      url: qr,
      qrCodeDataURI,
      hideActions: true,
      titleL10nId: `webauthn-hybrid-${request_type}-title`,
    };

    let chromeWin = browsingContext.topChromeWindow;
    let browser = browsingContext.top.embedderElement;

    // Ensure that no DOM elements are already fullscreen.
    chromeWin.FullScreen.exitDomFullScreen();

    // Ensure that the nav toolbox is being shown.
    if (chromeWin.fullScreen) {
      chromeWin.FullScreen.showNavToolbox();
    }

    let { closedPromise, dialog } = chromeWin.gBrowser
      .getTabDialogBox(browser)
      .open(
        "chrome://browser/content/qrcode/qrcode-dialog.html",
        { features: "resizable=no", allowDuplicateDialogs: false },
        params
      );
    if (dialog) {
      await closedPromise;
      lazy.webauthnService.cancel(tid);
    }

    // let options = {
    //   escAction: "buttoncommand",
    //   name: origin,
    //   hintText: qr,
    //   // TODO: render a qr code
    //   popupIconURL: "chrome://global/skin/icons/security.svg",
    // };

    // this.show_formatted_msg(
    //   browsingContext,
    //   tid,
    //   "show-cable-qr-code",
    //   message,
    //   mainAction,
    //   null,
    //   options
    // );
  },

  cancel({ tid }) {
    if (this._tid == tid) {
      this.reset();
    }
  },

  reset() {
    if (this._current) {
      this._current.remove();
    }
  },

  buildCancelAction(tid) {
    let [cancelMsg] = this._l10n.formatMessagesSync([
      { id: "webauthn-cancel" },
    ]);
    return {
      label: cancelMsg.value,
      accessKey: cancelMsg.attributes.find(a => a.name == "accesskey").value,
      callback() {
        lazy.webauthnService.cancel(tid);
      },
    };
  },
};
