// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Story — Tax service (tax forms, tax QR, tax PDF).
//! All operations are stubs returning placeholder data. In production these
//! will be backed by a tax document store and rendering pipeline.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A tax form (e.g. 1099-INT, 1099-DIV).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxForm {
    pub form_id: Uuid,
    pub form_type: String,
    pub tax_year: i32,
    pub data: serde_json::Value,
}

/// Get tax forms for a customer (stub).
pub async fn get_tax_forms(_customer_id: Uuid) -> Result<Vec<TaxForm>, String> {
    // Stub: return an empty list.
    Ok(vec![])
}

/// Generate a QR code for a tax form (stub — returns a placeholder string).
pub async fn generate_tax_qr(form_id: Uuid) -> Result<String, String> {
    Ok(format!("fdx-tax-qr:{}", form_id))
}

/// Generate a PDF for a tax form (stub — returns placeholder bytes).
pub async fn generate_tax_pdf(form_id: Uuid) -> Result<Vec<u8>, String> {
    Ok(format!("%PDF-1.4 stub for {}\n%%EOF\n", form_id).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_tax_forms_returns_empty() {
        let forms = get_tax_forms(Uuid::new_v4()).await.unwrap();
        assert!(forms.is_empty());
    }

    #[tokio::test]
    async fn test_generate_tax_qr() {
        let id = Uuid::new_v4();
        let qr = generate_tax_qr(id).await.unwrap();
        assert!(qr.contains(&id.to_string()));
        assert!(qr.starts_with("fdx-tax-qr:"));
    }

    #[tokio::test]
    async fn test_generate_tax_pdf_starts_with_pdf_header() {
        let pdf = generate_tax_pdf(Uuid::new_v4()).await.unwrap();
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
    }

    #[tokio::test]
    async fn test_generate_tax_pdf_nonempty() {
        let pdf = generate_tax_pdf(Uuid::new_v4()).await.unwrap();
        assert!(!pdf.is_empty());
    }

    #[test]
    fn test_tax_form_serialization() {
        let f = TaxForm {
            form_id: Uuid::new_v4(),
            form_type: "1099-INT".into(),
            tax_year: 2025,
            data: serde_json::json!({}),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("1099-INT"));
        assert!(json.contains("2025"));
    }
}
