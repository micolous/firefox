/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Error handling.

use nserror::nsresult;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("Internal error")]
    Internal,

    #[error("Not implemented")]
    NotImplemented,

    #[error("nsresult: {0:?}")]
    NsResult(#[from] nsresult),
}

impl From<Error> for nsresult {
    fn from(value: Error) -> Self {
        use nserror::{NS_ERROR_FAILURE, NS_ERROR_NOT_IMPLEMENTED};
        use Error::*;

        match value {
            Internal => NS_ERROR_FAILURE,
            NotImplemented => NS_ERROR_NOT_IMPLEMENTED,
            NsResult(r) => r,
        }
    }
}
