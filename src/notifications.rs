// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Story - Notification service (subscriptions, publish, retry, DLQ).
//! All operations are stubs. In production these will be backed by a
//! notification store and delivery worker.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A notification subscription registered by a recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSubscription {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub event_types: Vec<String>,
    pub callback_url: String,
}

/// A single notification event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Create a notification subscription (stub - returns a new UUID).
pub async fn create_subscription(
    customer_id: Uuid,
    event_types: Vec<String>,
    _callback_url: String,
) -> Result<Uuid, String> {
    if event_types.is_empty() {
        return Err("event_types must not be empty".into());
    }
    if customer_id == Uuid::nil() {
        return Err("customer_id must not be nil".into());
    }
    Ok(Uuid::new_v4())
}

/// Publish a notification to a subscription (stub).
pub async fn publish_notification(
    _subscription_id: Uuid,
    event_type: String,
    _payload: serde_json::Value,
) -> Result<(), String> {
    if event_type.is_empty() {
        return Err("event_type must not be empty".into());
    }
    Ok(())
}

/// Retry failed notifications (stub - returns the IDs that would be retried).
pub async fn retry_failed_notifications() -> Result<Vec<Uuid>, String> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_subscription_success() {
        let id = create_subscription(
            Uuid::new_v4(),
            vec!["account.closed".into()],
            "https://cb".into(),
        )
        .await
        .unwrap();
        assert!(Uuid::parse_str(&id.to_string()).is_ok());
    }

    #[tokio::test]
    async fn test_create_subscription_empty_event_types() {
        let r = create_subscription(Uuid::new_v4(), vec![], "https://cb".into()).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_create_subscription_nil_customer() {
        let r = create_subscription(Uuid::nil(), vec!["x".into()], "https://cb".into()).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_publish_notification_success() {
        let r = publish_notification(
            Uuid::new_v4(),
            "account.closed".into(),
            serde_json::json!({}),
        )
        .await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn test_publish_notification_empty_event_type() {
        let r = publish_notification(Uuid::new_v4(), "".into(), serde_json::json!({})).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_retry_failed_notifications_returns_empty() {
        let r = retry_failed_notifications().await.unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn test_notification_subscription_serialization() {
        let s = NotificationSubscription {
            id: Uuid::new_v4(),
            customer_id: Uuid::new_v4(),
            event_types: vec!["account.closed".into()],
            callback_url: "https://cb".into(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("account.closed"));
    }

    #[test]
    fn test_notification_serialization() {
        let n = Notification {
            id: Uuid::new_v4(),
            subscription_id: Uuid::new_v4(),
            event_type: "transfer.completed".into(),
            payload: serde_json::json!({"id": "t1"}),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("transfer.completed"));
    }
}
