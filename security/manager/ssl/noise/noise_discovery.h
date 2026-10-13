/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _noise_discovery_h_
#define _noise_discovery_h_

#include "nsISupportsUtils.h"  // for nsresult, etc.
#include "nsLiteralString.h"

/**
 * caBLE request type: CTAP GetAssertion request (WebAuthn
 * `navigator.credentials.get()`).
 */
constexpr nsLiteralCString CABLE_REQUEST_TYPE_CTAP_GET_ASSERTION = "ga"_ns;

/**
 * caBLE request type: CTAP MakeCredential request (WebAuthn
 * `navigator.credentials.create()`).
 */
constexpr nsLiteralCString CABLE_REQUEST_TYPE_CTAP_MAKE_CREDENTIAL = "mc"_ns;

/**
 * caBLE request type: Digital Credentials API: credential presentation:
 * <https://www.w3.org/TR/digital-credentials/>
 */
constexpr nsLiteralCString CABLE_REQUEST_TYPE_DC_PRESENTATION = "dcp"_ns;

/**
 * caBLE request type: Digital Credentials API: credential issuance:
 * <https://www.w3.org/TR/digital-credentials/>
 */
constexpr nsLiteralCString CABLE_REQUEST_TYPE_DC_ISSUANCE = "dci"_ns;

extern "C" {
nsresult ctap_cable_discovery_params_constructor(REFNSIID iid, void** result);
nsresult ctap_cable_discovery_service_constructor(REFNSIID iid, void** result);
};

#endif  // _noise_discovery_h_
