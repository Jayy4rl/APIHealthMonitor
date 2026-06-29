use axum::extract::FromRequestParts;

impl<S> FromRequestParts<S> for Claims where S: Send +Sync,{
        type Rejection = (StatusCode, Json<serde_json::Value>);

}