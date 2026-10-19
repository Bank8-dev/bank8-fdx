// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Typed response DTOs for the FDX-facing surfaces (OAPEC-9). Every body
//! here documents the wire shape a handler emits; genuinely dynamic
//! forwarded payloads (Ledger/Payments passthroughs) are documented by
//! `FdxAccountsPassthrough` and never claimed as a fixed schema.

use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// FDX account/customer/statement passthrough envelope (OAPEC-9 honest
/// freeform): the forwarded provider document (Ledger/Payments payload,
/// CSDF-minimized) is provider-controlled, so the response body IS the
/// forwarded document itself - serialized transparently (wire-identical),
/// documented as an open object to keep the schema non-empty without
/// inventing fields the ledger owns.
#[derive(Debug, Serialize, ToSchema)]
#[serde(transparent)]
pub struct FdxAccountsPassthrough(
    /// The forwarded provider document (dynamic, provider-controlled).
    pub serde_json::Value,
);

/// Consent introspection document.
#[derive(Debug, Serialize, ToSchema)]
pub struct FdxConsentIntrospection {
    /// The consent id.
    #[serde(rename = "consentId")]
    pub consent_id: Uuid,
    /// The customer that granted the consent.
    #[serde(rename = "customerId")]
    pub customer_id: Uuid,
    /// The consent status.
    pub status: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Granted data clusters.
    #[serde(rename = "dataClusters")]
    pub data_clusters: Vec<String>,
    /// Expiry (absent for unlimited consents).
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    /// Resource-level grants.
    pub resources: Vec<FdxConsentResource>,
}

/// One consented resource.
#[derive(Debug, Serialize, ToSchema)]
pub struct FdxConsentResource {
    /// Resource type (e.g. `account`).
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    /// The resource id.
    #[serde(rename = "resourceId")]
    pub resource_id: String,
    /// Data clusters granted on the resource.
    #[serde(rename = "dataClusters")]
    pub data_clusters: Vec<String>,
}

/// Recipient provider catalog entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderCard {
    /// Provider id.
    pub id: Uuid,
    /// Provider display name.
    pub name: String,
    /// The provider's issuer URL.
    #[serde(rename = "issuerUrl")]
    pub issuer_url: String,
    /// The FDX version the provider declares.
    #[serde(rename = "fdxVersion")]
    pub fdx_version: String,
    /// Data clusters the provider serves.
    #[serde(rename = "supportedDataClusters")]
    pub supported_data_clusters: Vec<String>,
    /// Registration status.
    pub status: String,
}

/// Recipient provider catalog.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderCatalogResponse {
    /// Registered providers.
    pub providers: Vec<ProviderCard>,
}

/// FDX capability announcement.
#[derive(Debug, Serialize, ToSchema)]
pub struct FdxCapability {
    /// The FDX spec version served.
    #[serde(rename = "fdxVersion")]
    pub fdx_version: String,
    /// Announced operation capabilities.
    pub capabilities: Vec<String>,
    /// Announced data clusters.
    #[serde(rename = "dataClusters")]
    pub data_clusters: Vec<String>,
}

/// Availability endpoint document.
#[derive(Debug, Serialize, ToSchema)]
pub struct FdxAvailability {
    /// Availability status (always `available` when serving).
    pub status: String,
    /// Human description of the outage window (if any).
    pub description: String,
}

/// Certification metrics bundle.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CertificationMetrics {
    /// Whether the deployment declares FDX certification.
    pub certified: bool,
    /// The FDX spec version certified.
    #[serde(rename = "fdxVersion")]
    pub fdx_version: String,
    /// The metric counters.
    pub metrics: CertificationMetricCounters,
}

/// Certification metric counters.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CertificationMetricCounters {
    /// Consents granted.
    #[serde(rename = "consentsGranted")]
    pub consents_granted: i64,
    /// Consents revoked.
    #[serde(rename = "consentsRevoked")]
    pub consents_revoked: i64,
    /// Data calls served.
    #[serde(rename = "dataCalls")]
    pub data_calls: i64,
}

/// Consent-start redirect (OAPEC-9 typed body).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentStartResponse {
    /// The started consent id.
    #[serde(rename = "consent_id")]
    pub consent_id: Uuid,
    /// The provider authorization URL to open.
    #[serde(rename = "authorization_url")]
    pub authorization_url: String,
    /// The consent status after start (`pending`).
    pub status: String,
    /// The provider name.
    #[serde(rename = "provider_name")]
    pub provider_name: String,
}

/// One consent row of the recipient consent list.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecipientConsentRow {
    /// The consent id.
    pub id: Uuid,
    /// The customer the consent belongs to.
    pub customer_id: Uuid,
    /// The provider id.
    pub provider_id: String,
    /// The provider display name.
    pub provider_name: String,
    /// The consent status.
    pub status: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Granted data clusters (mirrors scopes until clusters are separable).
    pub data_clusters: Vec<String>,
    /// Account ids selected by the customer.
    pub selected_account_ids: Vec<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Recipient consent list.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecipientConsentListResponse {
    /// The consent rows.
    pub consents: Vec<RecipientConsentRow>,
}

/// Recipient consent action acknowledgement (refresh/revoke).
#[derive(Debug, Serialize, ToSchema)]
pub struct RecipientConsentActionResponse {
    /// The consent id.
    pub id: Uuid,
    /// The customer id.
    pub customer_id: Uuid,
    /// The provider id.
    pub provider_id: String,
    /// The resulting status.
    pub status: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
}

/// Notification feed list.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationsListResponse {
    /// The notification documents (dynamic feed stub until the feed ships).
    pub notifications: Vec<serde_json::Value>,
}

/// Provider profile document.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderProfile {
    /// The profile id.
    pub id: Uuid,
    /// The provider name.
    #[serde(rename = "provider_name")]
    pub provider_name: String,
    /// The issuer URL.
    #[serde(rename = "issuer_url")]
    pub issuer_url: String,
    /// The declared FDX version.
    #[serde(rename = "fdx_version")]
    pub fdx_version: String,
    /// Registration status.
    pub status: String,
}

/// Provider profile read (null when not yet registered).
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderProfileResponse {
    /// The profile (null when unset).
    #[serde(rename = "provider_profile")]
    pub provider_profile: Option<ProviderProfile>,
}

/// Profile-update acknowledgement.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderProfileUpdated {
    /// The profile id.
    pub id: Uuid,
    /// The resulting status.
    pub status: String,
}

/// Admin recipient row.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminRecipientRow {
    /// The recipient id.
    pub id: Uuid,
    /// The recipient name.
    pub name: String,
    /// The M2M client id.
    pub client_id: String,
    /// Recipient status.
    pub status: String,
}

/// Admin audit row.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminAuditRow {
    /// The audit event id.
    pub id: Uuid,
    /// The acting principal (empty for service actors).
    pub actor_user_id: String,
    /// The audited action.
    pub action: String,
    /// The target resource (empty when unscoped).
    pub target_resource_id: String,
    /// When the action happened.
    pub timestamp: DateTime<Utc>,
}

/// Liveness/build identity (OAPEC-9 typed body).
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceHealth {
    /// Always `ok` when serving.
    pub status: String,
    /// The service identifier.
    pub service: String,
    /// The build version.
    pub version: String,
    /// The build hash.
    pub build: String,
}

/// Consent revocation record (consumer-presented).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentRevocationRecord {
    /// The revoked consent id.
    #[serde(rename = "consentId")]
    pub consent_id: Uuid,
    /// The revocation reason code.
    pub reason: String,
    /// Free-text reason for `other`.
    #[serde(rename = "otherReason", skip_serializing_if = "Option::is_none")]
    pub other_reason: Option<String>,
    /// The revoking party (`customer` | `provider` | `tpsp`).
    pub initiator: String,
    /// When the revocation happened.
    #[serde(rename = "revokedAt")]
    pub revoked_at: DateTime<Utc>,
}

/// Consent lifecycle read/update result.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentLifecycleResponse {
    /// The consent id.
    #[serde(rename = "consentId")]
    pub consent_id: Uuid,
    /// The duration type (`days` | `months` | `years`).
    #[serde(rename = "durationType")]
    pub duration_type: String,
    /// Duration period (absent for unlimited).
    #[serde(rename = "durationPeriod", skip_serializing_if = "Option::is_none")]
    pub duration_period: Option<i32>,
    /// Transaction lookback window (months).
    #[serde(rename = "lookbackPeriod", skip_serializing_if = "Option::is_none")]
    pub lookback_period: Option<i32>,
}

/// Consent approve/deny redirect.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentRedirectResponse {
    /// The URL to navigate back to (the auth flow continuation).
    #[serde(rename = "redirect_url")]
    pub redirect_url: String,
}

/// One notification-subscription row.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationSubscription {
    /// The subscription id.
    #[serde(rename = "subscriptionId")]
    pub subscription_id: Uuid,
    /// Subscription type.
    #[serde(rename = "type")]
    pub r#type: String,
    /// Subscription category.
    pub category: String,
    /// The subscriber callback URL.
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
    /// The subscriber identity document (genuinely freeform).
    pub subscriber: serde_json::Value,
    /// Subscription status.
    pub status: String,
    /// Effective date.
    #[serde(rename = "effectiveDate")]
    pub effective_date: DateTime<Utc>,
}

/// Subscription list envelope.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationSubscriptionListResponse {
    /// The subscription rows.
    #[serde(rename = "notificationSubscriptions")]
    pub notification_subscriptions: Vec<NotificationSubscription>,
}

/// Notification publish acknowledgement.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationAcceptedResponse {
    /// The accepted notification id.
    #[serde(rename = "notificationId")]
    pub notification_id: Uuid,
    /// Always `accepted`.
    pub status: String,
    /// Acceptance timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

/// One notification feed row.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationFeedRow {
    /// The notification id.
    #[serde(rename = "notificationId")]
    pub notification_id: Uuid,
    /// The notification type.
    #[serde(rename = "type")]
    pub r#type: String,
    /// The category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// The priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// The notification payload (genuinely freeform).
    pub payload: serde_json::Value,
    /// Delivery status.
    #[serde(rename = "deliveryStatus")]
    pub delivery_status: String,
    /// Send timestamp.
    #[serde(rename = "sentOn")]
    pub sent_on: DateTime<Utc>,
}

/// Notification feed envelope.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationListResponse {
    /// The feed rows.
    pub notifications: Vec<NotificationFeedRow>,
}

/// Payment-network revocation event.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentNetworkRevocationEvent {
    /// The revocation id.
    #[serde(rename = "revocationId")]
    pub revocation_id: Uuid,
    /// The revocation reason code.
    pub reason: String,
    /// Free-text reason for `other`.
    #[serde(rename = "otherReason", skip_serializing_if = "Option::is_none")]
    pub other_reason: Option<String>,
    /// The revoking party.
    pub initiator: String,
    /// When the revocation happened.
    #[serde(rename = "revokedAt")]
    pub revoked_at: DateTime<Utc>,
}

/// Revocation-events list envelope.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentNetworkRevocationListResponse {
    /// The lifecycle events.
    #[serde(rename = "paymentNetworkLifecycleEvents")]
    pub payment_network_lifecycle_events: Vec<PaymentNetworkRevocationEvent>,
}

/// PIP party detail.
#[derive(Debug, Serialize, ToSchema)]
pub struct PipPartyDetail {
    /// The party id.
    #[serde(rename = "paymentInitiationPartyId")]
    pub payment_initiation_party_id: Uuid,
    /// The party name.
    #[serde(rename = "partyName")]
    pub party_name: String,
    /// The party type.
    #[serde(rename = "partyType")]
    pub party_type: String,
    /// Contact document (genuinely freeform).
    pub contact: serde_json::Value,
    /// The registry slug (absent for unregistered parties).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// The registry-assigned id (absent for unregistered parties).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_id: Option<String>,
    /// Party status.
    pub status: String,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

/// PIP payment-method registration result.
#[derive(Debug, Serialize, ToSchema)]
pub struct PipPaymentMethodRegistered {
    /// The registration id.
    #[serde(rename = "paymentMethodRegistrationId")]
    pub payment_method_registration_id: Uuid,
    /// The method type.
    #[serde(rename = "methodType")]
    pub method_type: String,
    /// Always `active` after registration.
    pub status: String,
}

/// PIP payment-method revocation result.
#[derive(Debug, Serialize, ToSchema)]
pub struct PipPaymentMethodRevoked {
    /// The revoked registration id.
    #[serde(rename = "paymentMethodRegistrationId")]
    pub payment_method_registration_id: Uuid,
    /// Always `revoked`.
    pub status: String,
}

/// Recurring-payment creation result.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecurringPaymentCreated {
    /// The recurring-payment id (as assigned by Payments).
    #[serde(rename = "recurringPaymentId")]
    pub recurring_payment_id: String,
    /// The payment frequency.
    pub frequency: String,
    /// Always `ACTIVE` right after creation.
    pub status: String,
    /// The forwarded Payments envelope (genuinely freeform).
    #[serde(rename = "payments_service")]
    pub payments_service: serde_json::Value,
}

/// Operation-support surface declaration.
#[derive(Debug, Serialize, ToSchema)]
pub struct OperationSupport {
    /// Operations this deployment serves.
    pub implemented: Vec<String>,
    /// Operations explicitly out of scope.
    #[serde(rename = "outOfScope")]
    pub out_of_scope: Vec<String>,
}
