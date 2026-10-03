use crate::commands::profiles::ProfileState;
use crate::s3::{self, BucketInfo, S3State};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Serialize, Deserialize)]
pub struct BucketWithRegion {
    pub name: String,
    pub region: String,
    pub creation_date: Option<String>,
    pub object_count: Option<u64>,
    pub total_size: Option<u64>,
    pub total_size_formatted: Option<String>,
}

/// List all accessible S3 buckets
#[tauri::command]
pub async fn list_buckets(
    expected_profile_id: Option<String>,
    profile_state: State<'_, ProfileState>,
    s3_state: State<'_, S3State>,
) -> Result<Vec<BucketInfo>, String> {
    // Get active profile
    let profile_manager = profile_state.read().await;
    let target_profile = if let Some(ref id) = expected_profile_id {
        profile_manager.get_profile(id).await.ok()
    } else {
        None
    };
    let active_profile = match target_profile {
        Some(p) => p,
        None => profile_manager
            .get_active_profile()
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "No active profile selected".to_string())?,
    };

    drop(profile_manager);

    // Get S3 client
    let mut s3_manager = s3_state.write().await;
    let client = s3_manager
        .get_client(&active_profile)
        .await
        .map_err(|e| e.to_string())?
        .clone();
    drop(s3_manager);

    // List buckets
    let mut discovered = match s3::client::list_buckets(&client).await {
        Ok(b) => b,
        Err(err) => {
            let err_msg = err.to_string();
            let is_access_denied = err_msg.contains("AccessDenied")
                || err_msg.contains("403")
                || err_msg.contains("Access Denied")
                || err_msg.contains("Forbidden")
                || err_msg.contains("MethodNotAllowed")
                || err_msg.contains("NotImplemented");

            if is_access_denied || !active_profile.buckets.is_empty() {
                log::warn!(
                    "list_buckets permission denied for profile '{}', returning configured or empty bucket list: {}",
                    active_profile.name,
                    err_msg
                );
                Vec::new()
            } else {
                return Err(err_msg);
            }
        }
    };

    if !active_profile.buckets.is_empty() {
        let existing: std::collections::HashSet<String> =
            discovered.iter().map(|b| b.name.clone()).collect();
        for custom_name in &active_profile.buckets {
            if !existing.contains(custom_name) {
                discovered.push(crate::s3::BucketInfo {
                    name: custom_name.clone(),
                    region: Some(active_profile.effective_region()),
                    creation_date: None,
                    object_count: None,
                    total_size: None,
                    total_size_formatted: None,
                });
            }
        }
    }

    Ok(discovered)
}

/// List buckets with their regions
#[tauri::command]
pub async fn list_buckets_with_regions(
    expected_profile_id: Option<String>,
    profile_state: State<'_, ProfileState>,
    s3_state: State<'_, S3State>,
) -> Result<Vec<BucketWithRegion>, String> {
    // Get active profile
    let profile_manager = profile_state.read().await;
    let target_profile = if let Some(ref id) = expected_profile_id {
        profile_manager.get_profile(id).await.ok()
    } else {
        None
    };
    let active_profile = match target_profile {
        Some(p) => p,
        None => profile_manager
            .get_active_profile()
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "No active profile selected".to_string())?,
    };

    drop(profile_manager);

    // Get S3 client
    let mut s3_manager = s3_state.write().await;
    let client = s3_manager
        .get_client(&active_profile)
        .await
        .map_err(|e| e.to_string())?
        .clone();
    drop(s3_manager);

    // For custom endpoints (non-AWS providers like Linode, DigitalOcean, MinIO, etc.),
    // the GetBucketLocation API is often unsupported and causes "dispatch failure" errors.
    // Use the profile's configured region directly instead of querying per-bucket.
    let is_custom_endpoint = matches!(
        &active_profile.credential_type,
        crate::credentials::CredentialType::CustomEndpoint { .. }
    );
    let profile_region = active_profile.effective_region();

    // List buckets
    let mut buckets = match s3::client::list_buckets(&client).await {
        Ok(b) => b,
        Err(err) => {
            let err_msg = err.to_string();
            let is_access_denied = err_msg.contains("AccessDenied")
                || err_msg.contains("403")
                || err_msg.contains("Access Denied")
                || err_msg.contains("Forbidden")
                || err_msg.contains("MethodNotAllowed")
                || err_msg.contains("NotImplemented");

            if is_access_denied || !active_profile.buckets.is_empty() {
                log::warn!(
                    "list_buckets permission denied for profile '{}', using configured bucket list: {}",
                    active_profile.name,
                    err_msg
                );
                Vec::new()
            } else if is_custom_endpoint && err_msg.contains("dispatch failure") {
                return Err(format!(
                    "Could not connect to custom S3 endpoint. Please verify the endpoint URL, region, and network connectivity. Error: {}",
                    err_msg
                ));
            } else {
                return Err(err_msg);
            }
        }
    };

    // Merge any explicitly configured profile buckets
    if !active_profile.buckets.is_empty() {
        let existing: std::collections::HashSet<String> =
            buckets.iter().map(|b| b.name.clone()).collect();
        for custom_name in &active_profile.buckets {
            if !existing.contains(custom_name) {
                buckets.push(crate::s3::BucketInfo {
                    name: custom_name.clone(),
                    region: Some(profile_region.clone()),
                    creation_date: None,
                    object_count: None,
                    total_size: None,
                    total_size_formatted: None,
                });
            }
        }
    }

    if is_custom_endpoint {
        // Skip GetBucketLocation entirely for custom endpoints
        s3_state.write().await.set_bucket_regions(
            &active_profile,
            buckets.iter().map(|bucket| bucket.name.as_str()),
            &profile_region,
        );
        let buckets_with_regions: Vec<BucketWithRegion> = buckets
            .into_iter()
            .map(|bucket| BucketWithRegion {
                name: bucket.name,
                region: profile_region.clone(),
                creation_date: bucket.creation_date,
                object_count: bucket.object_count,
                total_size: bucket.total_size,
                total_size_formatted: bucket.total_size_formatted,
            })
            .collect();

        return Ok(buckets_with_regions);
    }

    // For standard AWS profiles, fetch regions in PARALLEL for much faster startup
    let client_clone = client.clone();
    let fallback_region = profile_region.clone();
    let futures: Vec<_> = buckets
        .into_iter()
        .map(|bucket| {
            let client_ref = client_clone.clone();
            let bucket_name = bucket.name.clone();
            let fallback = fallback_region.clone();
            async move {
                let region = match s3::client::get_bucket_region(&client_ref, &bucket_name).await {
                    Ok(r) => r,
                    Err(_) => fallback,
                };
                BucketWithRegion {
                    name: bucket.name,
                    region,
                    creation_date: bucket.creation_date,
                    object_count: bucket.object_count,
                    total_size: bucket.total_size,
                    total_size_formatted: bucket.total_size_formatted,
                }
            }
        })
        .collect();

    let buckets_with_regions = futures::stream::iter(futures)
        .buffered(8)
        .collect::<Vec<_>>()
        .await;

    Ok(buckets_with_regions)
}

/// Get the region for a specific bucket
#[tauri::command]
pub async fn get_bucket_region(
    bucket_name: String,
    expected_profile_id: Option<String>,
    profile_state: State<'_, ProfileState>,
    s3_state: State<'_, S3State>,
) -> Result<String, String> {
    // Get active profile
    let profile_manager = profile_state.read().await;
    let target_profile = if let Some(ref id) = expected_profile_id {
        profile_manager.get_profile(id).await.ok()
    } else {
        None
    };
    let active_profile = match target_profile {
        Some(p) => p,
        None => profile_manager
            .get_active_profile()
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "No active profile selected".to_string())?,
    };

    drop(profile_manager);

    let region = active_profile.effective_region();

    if matches!(
        &active_profile.credential_type,
        crate::credentials::CredentialType::CustomEndpoint { .. }
    ) || active_profile.buckets.contains(&bucket_name) {
        let mut s3_manager = s3_state.write().await;
        s3_manager.set_bucket_region(&active_profile, &bucket_name, region.clone());
        return Ok(region);
    }

    // Get S3 client
    let mut s3_manager = s3_state.write().await;
    let client = s3_manager
        .get_client(&active_profile)
        .await
        .map_err(|e| e.to_string())?
        .clone();
    drop(s3_manager);

    // Get region
    match s3::client::get_bucket_region(&client, &bucket_name).await {
        Ok(r) => Ok(r),
        Err(_) => Ok(region),
    }
}

/// Refresh the S3 client (clear cache)
#[tauri::command]
pub async fn refresh_s3_client(s3_state: State<'_, S3State>) -> Result<(), String> {
    let mut s3_manager = s3_state.write().await;
    s3_manager.clear_cache();
    Ok(())
}
