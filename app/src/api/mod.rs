pub mod analytics;
pub mod auth;
pub mod client;
pub mod groups;
pub mod members;
pub mod share_offers;
pub mod shares;
pub mod validation;

// Re-export commonly used items for SSR mode
pub use client::{
    api, get_dashboard_metrics, get_groups, get_members, get_shares, ApiClient, ApiError, ApiResponse, 
    PaginatedResponse, PaginationQuery, SearchQuery,
};

use axum::{
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;

use crate::{repositories::Repositories, services::Services};

pub fn create_api_router(repositories: Repositories, services: Services) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/info", get(api_info))
        .nest(
            "/analytics",
            analytics::router(repositories.clone(), services.clone()),
        )
        .nest(
            "/auth",
            auth::router(repositories.clone(), services.clone()),
        )
        .nest(
            "/groups",
            groups::router(repositories.clone(), services.clone()),
        )
        .nest(
            "/members",
            members::router(repositories.clone(), services.clone()),
        )
        .nest(
            "/share-offers",
            share_offers::router(repositories.clone(), services.clone()),
        )
        .nest(
            "/shares",
            shares::router(repositories.clone(), services.clone()),
        )
        .nest("/validation", validation::router(repositories, services))
}

pub async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "bitsacco-server-api"
    }))
}

pub async fn api_info() -> impl IntoResponse {
    Json(json!({
        "name": "Bitsacco Server API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "REST API for SACCO management system",
        "database": "connected",
        "environment": "development",
        "endpoints": {
            "analytics": "/api/analytics",
            "auth": "/api/auth",
            "groups": "/api/groups",
            "members": "/api/members",
            "share_offers": "/api/share-offers",
            "shares": "/api/shares",
            "validation": "/api/validation"
        }
    }))
}
