// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("get resource failed: {0}")]
    GetResource(String),

    #[error("init Hub failed: {0}")]
    InitializationFailed(String),

    #[error("unseal secret failed: {0}")]
    UnsealSecret(String),
}
