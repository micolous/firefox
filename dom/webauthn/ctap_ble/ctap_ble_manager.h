/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _ctap_ble_manager_h_
#define _ctap_ble_manager_h_

#include "nsISupportsUtils.h"  // for nsresult, etc.

extern "C" {
nsresult ctap_ble_manager_constructor(REFNSIID iid, void** result);
};

#endif  // _ctap_ble_manager_h_
