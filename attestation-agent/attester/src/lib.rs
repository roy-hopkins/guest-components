// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use kbs_types::Tee;

pub mod sample;

#[cfg(feature = "az-snp-vtpm-attester")]
pub mod az_snp_vtpm;

#[cfg(feature = "cca-attester")]
pub mod cca;

#[cfg(feature = "tdx-attester")]
pub mod tdx;

#[cfg(feature = "sgx-attester")]
pub mod sgx_dcap;

#[cfg(feature = "snp-attester")]
pub mod snp;

#[cfg(feature = "csv-attester")]
pub mod csv;

pub type BoxedAttester = Box<dyn Attester + Send + Sync>;

impl TryFrom<Tee> for BoxedAttester {
    type Error = anyhow::Error;

    fn try_from(value: Tee) -> Result<Self> {
        let attester: Box<dyn Attester + Send + Sync> = match value {
            Tee::Sample => Box::<sample::SampleAttester>::default(),
            #[cfg(feature = "tdx-attester")]
            Tee::Tdx => Box::<tdx::TdxAttester>::default(),
            #[cfg(feature = "sgx-attester")]
            Tee::Sgx => Box::<sgx_dcap::SgxDcapAttester>::default(),
            #[cfg(feature = "az-snp-vtpm-attester")]
            Tee::AzSnpVtpm => Box::<az_snp_vtpm::AzSnpVtpmAttester>::default(),
            #[cfg(feature = "cca-attester")]
            Tee::Cca => Box::<cca::CCAAttester>::default(),
            #[cfg(feature = "snp-attester")]
            Tee::Snp => Box::<snp::SnpAttester>::default(),
            #[cfg(feature = "csv-attester")]
            Tee::Csv => Box::<csv::CsvAttester>::default(),
            _ => bail!("TEE is not supported!"),
        };

        Ok(attester)
    }
}

#[async_trait::async_trait]
pub trait Attester {
    /// Call the hardware driver to get the Hardware specific evidence.
    /// The parameter `report_data` will be used as the user input of the
    /// evidence to avoid reply attack.
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<String>;
}

// Detect which TEE platform the KBC running environment is.
pub fn detect_tee_type() -> Option<Tee> {
    if sample::detect_platform() {
        return Some(Tee::Sample);
    }

    #[cfg(feature = "tdx-attester")]
    if tdx::detect_platform() {
        return Some(Tee::Tdx);
    }

    #[cfg(feature = "sgx-attester")]
    if sgx_dcap::detect_platform() {
        return Some(Tee::Sgx);
    }

    #[cfg(feature = "az-snp-vtpm-attester")]
    if az_snp_vtpm::detect_platform() {
        return Some(Tee::AzSnpVtpm);
    }

    #[cfg(feature = "snp-attester")]
    if snp::detect_platform() {
        return Some(Tee::Snp);
    }

    #[cfg(feature = "csv-attester")]
    if csv::detect_platform() {
        return Some(Tee::Csv);
    }

    #[cfg(feature = "cca-attester")]
    if cca::detect_platform() {
        return Some(Tee::Cca);
    }

    None
}
