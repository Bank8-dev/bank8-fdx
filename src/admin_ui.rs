// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Bank8:FDX Admin UI handlers - RFW (Remote Flutter Widget) definitions.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;

use crate::handlers::AppState;

/// GET /v1/admin/ui/{page} - return RFW definition for the requested admin page.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the FDX consent/scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:fdx:consents:read"),
    )
    .await?;

    let page_def = match page.as_str() {
        "overview" => overview_page(),
        "provider" => provider_page(),
        "recipients" => recipients_page(),
        "consents" => consents_page(),
        "csdf" => csdf_page(),
        "settings" => settings_page(),
        // ── Policy Studio (design §3.7, story 28.14) - shared page
        // constructors; the guard guarantees `Some` (§3.7 dispatch).
        p if sentin8::rfw::policy_page("bank8:fdx", p).is_some() => {
            sentin8::rfw::policy_page("bank8:fdx", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };

    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(page_def)).unwrap(),
    ))
}

fn overview_page() -> AdminUiPage {
    AdminPage::new("FDX Overview")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("Provider Profile".into()),
            subtitle: None,
            children: vec![
                RemoteWidget::Text(WidgetText { text: "Provider profile, recipient catalog, consent review, CSDF classification, certification.".into(), text_type: WidgetTextType::Body, align: TextAlign::Left, max_lines: None }),
            ],
            actions: vec![],
        }))
        .build()
}

fn provider_page() -> AdminUiPage {
    AdminPage::new("Provider Profile")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("Provider Configuration".into()),
            subtitle: None,
            children: vec![RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "provider_name".into(),
                        label: "Provider Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "fdx_version".into(),
                        label: "FDX Version".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::Value::String("6.5".into())),
                        options: Some(vec![FormFieldOption {
                            value: "6.5".into(),
                            label: "FDX v6.5".into(),
                        }]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "supported_data_clusters".into(),
                        label: "Supported Data Clusters".into(),
                        field_type: FormFieldType::Multiselect,
                        required: false,
                        placeholder: None,
                        default_value: None,
                        options: Some(vec![
                            FormFieldOption {
                                value: "ACCOUNT_BASIC".into(),
                                label: "Account Basic".into(),
                            },
                            FormFieldOption {
                                value: "ACCOUNT_DETAILED".into(),
                                label: "Account Detailed".into(),
                            },
                            FormFieldOption {
                                value: "TRANSACTIONS".into(),
                                label: "Transactions".into(),
                            },
                            FormFieldOption {
                                value: "PAYMENTS".into(),
                                label: "Payments".into(),
                            },
                        ]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/provider-profile".into(),
                submit_label: "Update Provider Profile".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Put,
            })],
            actions: vec![],
        }))
        .build()
}

fn recipients_page() -> AdminUiPage {
    AdminPage::new("Recipient Catalog")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Recipient ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/recipients".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No recipients registered.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn consents_page() -> AdminUiPage {
    AdminPage::new("Consents")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Consent ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
                WidgetDataTableColumn {
                    key: "expires_at".into(),
                    label: "Expires".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/consents".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No consents found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn csdf_page() -> AdminUiPage {
    AdminPage::new("CSDF Classification")
        .widget(RemoteWidget::Text(WidgetText { text: "CSDF data classification dashboard - field-level filtering based on consent, scope, and product.".into(), text_type: WidgetTextType::Body, align: TextAlign::Left, max_lines: None }))
        .build()
}

fn settings_page() -> AdminUiPage {
    AdminPage::new("FDX Settings")
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![
                WidgetFormField {
                    key: "enabled".into(),
                    label: "Enable FDX".into(),
                    field_type: FormFieldType::Toggle,
                    required: false,
                    placeholder: None,
                    default_value: Some(serde_json::Value::Bool(true)),
                    options: None,
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "mode".into(),
                    label: "Mode".into(),
                    field_type: FormFieldType::Select,
                    required: true,
                    placeholder: None,
                    default_value: None,
                    options: Some(vec![
                        FormFieldOption {
                            value: "provider".into(),
                            label: "Data Provider".into(),
                        },
                        FormFieldOption {
                            value: "recipient".into(),
                            label: "Data Recipient".into(),
                        },
                        FormFieldOption {
                            value: "both".into(),
                            label: "Both".into(),
                        },
                    ]),
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
            ],
            submit_endpoint: "/settings".into(),
            submit_label: "Save Settings".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Put,
        }))
        .build()
}
