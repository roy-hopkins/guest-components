// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::mem::size_of;

//use anyhow::*;
use crate::{Error, Result};
use async_trait::async_trait;
use kbs_types::Tee;
use serde::{Deserialize, Serialize};
use sev::firmware::{guest::AttestationReport, host::CertTableEntry};

use super::EvidenceProvider;

#[derive(Serialize, Deserialize, Debug)]
struct SvsmSnpQuote {
    pub attestation_report: AttestationReport,
    pub cert_chain: Vec<CertTableEntry>,
}

pub struct SvsmEvidenceProvider(Box<SvsmSnpQuote>);

impl SvsmEvidenceProvider {
    /// # Safety
    /// Caller must ensure evidence buffer is at least as large as evidence_len
    pub unsafe fn new(
        evidence: *const u8,
        evidence_len: usize,
        certs: Vec<CertTableEntry>,
    ) -> Result<Self> {
        if evidence_len < size_of::<AttestationReport>() {
            return Err(Error::NativeEvidenceProvider("Invalid evidence".to_owned()));
        }
        let report = evidence as *const AttestationReport;
        let quote = Box::new(SvsmSnpQuote {
            attestation_report: *report,
            cert_chain: certs,
        });
        Ok(Self(quote))
    }
}

#[async_trait]
impl EvidenceProvider for SvsmEvidenceProvider {
    async fn get_evidence(&self, runtime_data: Vec<u8>) -> Result<String> {
        serde_json::to_string(&self.0)
            .map_err(|_| Error::NativeEvidenceProvider("Serialize sample evidence failed".into()))
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(Tee::Snp)
    }
}
