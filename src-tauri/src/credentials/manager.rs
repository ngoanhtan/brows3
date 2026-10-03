use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

const PROFILES_FILE: &str = "profiles.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CredentialType {
    /// Use environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    Environment,

    /// Use AWS shared config file (~/.aws/credentials)
    SharedConfig { profile_name: Option<String> },

    /// Manual entry with access key and secret (stored in keychain)
    Manual {
        access_key_id: String,
        #[serde(default, skip_serializing)]
        secret_access_key: String,
    },

    /// Custom S3-compatible endpoint (MinIO, Wasabi, etc.)
    CustomEndpoint {
        endpoint_url: String,
        access_key_id: String,
        #[serde(default, skip_serializing)]
        secret_access_key: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub public_urls: crate::transfer::public_url::PublicUrls,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub secret_ref: Option<String>,
    pub name: String,
    pub credential_type: CredentialType,
    pub region: Option<String>,
    #[serde(default)]
    pub buckets: Vec<String>,
    pub is_default: bool,
    #[serde(default)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Profile {
    pub fn cache_identity(&self) -> String {
        format!(
            "{}:{}",
            self.id,
            self.updated_at
                .map(|date| date.to_rfc3339())
                .unwrap_or_default()
        )
    }

    pub fn new(name: String, credential_type: CredentialType, region: Option<String>) -> Self {
        let now = chrono::Utc::now();
        Self {
            public_urls: Default::default(),
            id: Uuid::new_v4().to_string(),
            name,
            secret_ref: None,
            credential_type,
            region,
            buckets: Vec::new(),
            is_default: false,
            created_at: Some(now),
            updated_at: Some(now),
        }
    }

    /// Return the resolved AWS SigV4 region. If the profile has an explicit region
    /// configured that is not "auto" or empty, use it. If it is "auto" or empty,
    /// attempt to infer the region from known S3-compatible provider endpoint URLs
    /// (e.g. Backblaze B2, Wasabi, DigitalOcean, Linode) before falling back.
    pub fn effective_region(&self) -> String {
        let configured = self
            .region
            .as_ref()
            .map(|r| r.trim())
            .filter(|r| !r.is_empty());

        if let Some(reg) = configured {
            if !reg.eq_ignore_ascii_case("auto") {
                return reg.to_string();
            }
        }

        if let CredentialType::CustomEndpoint { endpoint_url, .. } = &self.credential_type {
            if let Some(inferred) = infer_region_from_endpoint(endpoint_url) {
                return inferred;
            }
            if let Some(reg) = configured {
                if reg.eq_ignore_ascii_case("auto") {
                    return "auto".to_string();
                }
            }
        }

        configured
            .map(|r| r.to_string())
            .unwrap_or_else(|| "us-east-1".to_string())
    }
}

/// Infer the S3 signing region from a custom endpoint URL when the user
/// enters "auto", leaves region blank, or when the endpoint domain encodes the cluster/region.
pub fn infer_region_from_endpoint(endpoint_url: &str) -> Option<String> {
    let lower = endpoint_url.to_lowercase();
    let host = lower
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?
        .split(':')
        .next()?;

    // Backblaze B2: s3.<region>.backblazeb2.com (e.g. s3.us-east-005.backblazeb2.com)
    if let Some(rest) = host.strip_suffix(".backblazeb2.com") {
        if let Some(region) = rest.strip_prefix("s3.") {
            if !region.is_empty() && !region.contains('.') {
                return Some(region.to_string());
            }
        }
    }

    // Wasabi: s3.<region>.wasabisys.com (e.g. s3.us-east-2.wasabisys.com)
    if let Some(rest) = host.strip_suffix(".wasabisys.com") {
        if let Some(region) = rest.strip_prefix("s3.") {
            if !region.is_empty() && !region.contains('.') {
                return Some(region.to_string());
            }
        }
    }

    // DigitalOcean Spaces: <region>.digitaloceanspaces.com (e.g. nyc3.digitaloceanspaces.com)
    if let Some(region) = host.strip_suffix(".digitaloceanspaces.com") {
        if !region.is_empty() && !region.contains('.') {
            return Some(region.to_string());
        }
    }

    // Linode Object Storage: <region>.linodeobjects.com (e.g. us-east-1.linodeobjects.com)
    if let Some(region) = host.strip_suffix(".linodeobjects.com") {
        if !region.is_empty() && !region.contains('.') {
            return Some(region.to_string());
        }
    }

    // Scaleway: s3.<region>.scw.cloud (e.g. s3.fr-par.scw.cloud)
    if let Some(rest) = host.strip_suffix(".scw.cloud") {
        if let Some(region) = rest.strip_prefix("s3.") {
            if !region.is_empty() && !region.contains('.') {
                return Some(region.to_string());
            }
        }
    }

    // Vultr: <region>.vultrobjects.com (e.g. ewr1.vultrobjects.com)
    if let Some(region) = host.strip_suffix(".vultrobjects.com") {
        if !region.is_empty() && !region.contains('.') {
            return Some(region.to_string());
        }
    }

    None
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct ProfilesData {
    profiles: HashMap<String, Profile>,
    active_profile_id: Option<String>,
    pending_secret_deletions: Vec<String>,
}

pub struct ProfileManager {
    config_dir: PathBuf,
    data: ProfilesData,
    keychain: super::KeychainStorage,
}

impl ProfileManager {
    pub fn new(config_dir: PathBuf, force_secret_fallback: bool) -> Result<Self> {
        let profiles_path = config_dir.join(PROFILES_FILE);
        log::info!(
            "Initializing ProfileManager. Storage path: {:?}",
            profiles_path
        );

        let data = if profiles_path.exists() {
            log::info!("Found existing profiles file.");
            let content = std::fs::read_to_string(&profiles_path)?;
            match Self::load_profiles_data(&content) {
                Ok(d) => {
                    log::info!("Successfully loaded profiles data.");
                    d
                }
                Err(e) => {
                    use std::io::Write;
                    let backup_path =
                        config_dir.join(format!("profiles.invalid-{}.json", Uuid::new_v4()));
                    let mut options = std::fs::OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    let mut backup = options.open(&backup_path)?;
                    backup.write_all(content.as_bytes())?;
                    backup.sync_all()?;
                    log::error!(
                        "Failed to parse profiles.json: {}. Original saved to {:?}.",
                        e,
                        backup_path
                    );
                    ProfilesData::default()
                }
            }
        } else {
            log::info!("No profiles file found. Creating new.");
            ProfilesData::default()
        };

        let keychain = super::KeychainStorage::new("brows3", &config_dir, force_secret_fallback);

        let mut manager = Self {
            config_dir,
            data,
            keychain,
        };
        manager.cleanup_pending_secrets();
        Ok(manager)
    }

    fn load_profiles_data(content: &str) -> std::result::Result<ProfilesData, serde_json::Error> {
        let value: serde_json::Value = serde_json::from_str(content)?;
        if value.is_array() {
            let profiles: Vec<Profile> = serde_json::from_value(value)?;
            return Ok(Self::normalize_profiles_data(ProfilesData {
                profiles: profiles
                    .into_iter()
                    .map(|profile| (profile.id.clone(), profile))
                    .collect(),
                active_profile_id: None,
                pending_secret_deletions: Vec::new(),
            }));
        }

        if value.get("profiles").is_some() || value.get("active_profile_id").is_some() {
            if let Ok(data) = serde_json::from_value::<ProfilesData>(value.clone()) {
                return Ok(Self::normalize_profiles_data(data));
            }
        }

        let profiles = serde_json::from_value::<HashMap<String, Profile>>(value)?;
        Ok(Self::normalize_profiles_data(ProfilesData {
            profiles,
            active_profile_id: None,
            pending_secret_deletions: Vec::new(),
        }))
    }

    fn normalize_profiles_data(mut data: ProfilesData) -> ProfilesData {
        let mut normalized_profiles = HashMap::with_capacity(data.profiles.len());
        let mut first_profile_id: Option<String> = None;
        let mut default_profile_id: Option<String> = None;

        for (key, mut profile) in data.profiles.drain() {
            if profile.id.is_empty() {
                profile.id = if !key.is_empty() {
                    key
                } else {
                    Uuid::new_v4().to_string()
                };
            }

            if first_profile_id.is_none() {
                first_profile_id = Some(profile.id.clone());
            }
            if profile.is_default && default_profile_id.is_none() {
                default_profile_id = Some(profile.id.clone());
            }

            normalized_profiles.insert(profile.id.clone(), profile);
        }

        let mut active_profile_id = data
            .active_profile_id
            .filter(|id| normalized_profiles.contains_key(id));

        if active_profile_id.is_none() {
            active_profile_id = default_profile_id.or(first_profile_id.clone());
        }

        for profile in normalized_profiles.values_mut() {
            profile.is_default = active_profile_id.as_ref() == Some(&profile.id);
        }

        ProfilesData {
            profiles: normalized_profiles,
            active_profile_id,
            pending_secret_deletions: data.pending_secret_deletions,
        }
    }

    fn sync_default_flags(&mut self) {
        let active_profile_id = self.data.active_profile_id.clone();
        for profile in self.data.profiles.values_mut() {
            profile.is_default = active_profile_id.as_ref() == Some(&profile.id);
        }
    }

    fn commit(&mut self, previous: ProfilesData) -> Result<()> {
        if let Err(error) = self.save() {
            self.data = previous;
            return Err(error);
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        let profiles_path = self.config_dir.join(PROFILES_FILE);
        log::info!("Saving profiles atomically to {:?}", profiles_path);
        let content = serde_json::to_string_pretty(&self.data)?;
        super::write_private_file(&profiles_path, content.as_bytes())
    }

    pub async fn list_profiles(&self) -> Result<Vec<Profile>> {
        let mut profiles: Vec<Profile> = self.data.profiles.values().cloned().collect();
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(profiles)
    }

    pub async fn get_profile(&self, id: &str) -> Result<Profile> {
        let profile = self
            .data
            .profiles
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::ProfileNotFound(id.to_string()))?;
        Ok(self.hydrate_profile(profile))
    }

    pub async fn add_profile(&mut self, mut profile: Profile) -> Result<Profile> {
        profile.public_urls.validate()?;
        // Generate ID if not provided
        if profile.id.is_empty() {
            profile.id = Uuid::new_v4().to_string();
        }
        // Check for duplicate name
        if self.data.profiles.values().any(|p| p.name == profile.name) {
            return Err(AppError::ProfileExists(profile.name.clone()));
        }

        if self.data.profiles.contains_key(&profile.id) {
            return Err(AppError::ProfileExists(profile.id));
        }
        let previous = self.data.clone();
        profile.secret_ref = Some(Uuid::new_v4().to_string());
        self.store_secret(&profile)?;

        // Set timestamps
        let now = chrono::Utc::now();
        profile.created_at = Some(now);
        profile.updated_at = Some(now);

        // If this is the first profile, make it default
        if self.data.profiles.is_empty() {
            profile.is_default = true;
            self.data.active_profile_id = Some(profile.id.clone());
        }

        self.data
            .profiles
            .insert(profile.id.clone(), profile.clone());
        self.sync_default_flags();
        if let Err(error) = self.commit(previous) {
            self.remove_secret(&profile);
            return Err(error);
        }

        Ok(self.hydrate_profile(
            self.data
                .profiles
                .get(&profile.id)
                .cloned()
                .ok_or_else(|| AppError::ProfileNotFound(profile.id.clone()))?,
        ))
    }

    pub async fn update_profile(&mut self, id: &str, mut profile: Profile) -> Result<Profile> {
        profile.public_urls.validate()?;
        let existing_profile = self
            .data
            .profiles
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::ProfileNotFound(id.to_string()))?;
        let hydrated_existing_profile = self.hydrate_profile(existing_profile.clone());

        if self
            .data
            .profiles
            .values()
            .any(|p| p.id != id && p.name == profile.name)
        {
            return Err(AppError::ProfileExists(profile.name.clone()));
        }

        profile.id = id.to_string();
        profile.created_at = existing_profile.created_at;
        profile.is_default = self.data.active_profile_id.as_deref() == Some(id);
        profile.updated_at = Some(chrono::Utc::now());

        // Keep previous secret if the edit payload omitted it.
        match (
            &hydrated_existing_profile.credential_type,
            &mut profile.credential_type,
        ) {
            (
                CredentialType::Manual {
                    secret_access_key: old_secret,
                    ..
                },
                CredentialType::Manual {
                    secret_access_key, ..
                },
            ) if secret_access_key.is_empty() => {
                *secret_access_key = old_secret.clone();
            }
            (
                CredentialType::CustomEndpoint {
                    secret_access_key: old_secret,
                    ..
                },
                CredentialType::CustomEndpoint {
                    secret_access_key, ..
                },
            ) if secret_access_key.is_empty() => {
                *secret_access_key = old_secret.clone();
            }
            (
                CredentialType::Manual {
                    secret_access_key: old_secret,
                    ..
                },
                CredentialType::CustomEndpoint {
                    secret_access_key, ..
                },
            ) if secret_access_key.is_empty() && !old_secret.is_empty() => {
                *secret_access_key = old_secret.clone();
            }
            (
                CredentialType::CustomEndpoint {
                    secret_access_key: old_secret,
                    ..
                },
                CredentialType::Manual {
                    secret_access_key, ..
                },
            ) if secret_access_key.is_empty() && !old_secret.is_empty() => {
                *secret_access_key = old_secret.clone();
            }
            _ => {}
        }

        let previous = self.data.clone();
        profile.secret_ref = Some(Uuid::new_v4().to_string());
        self.store_secret(&profile)?;

        self.queue_secret_cleanup(&existing_profile);
        self.data.profiles.insert(id.to_string(), profile.clone());
        self.sync_default_flags();
        if let Err(error) = self.commit(previous) {
            self.remove_secret(&profile);
            return Err(error);
        }

        self.cleanup_pending_secrets();
        Ok(self.hydrate_profile(profile))
    }

    pub async fn delete_profile(&mut self, id: &str) -> Result<()> {
        let previous = self.data.clone();
        let profile = self
            .data
            .profiles
            .remove(id)
            .ok_or_else(|| AppError::ProfileNotFound(id.to_string()))?;

        self.queue_secret_cleanup(&profile);
        // If this was the active profile, clear it
        if self.data.active_profile_id.as_deref() == Some(id) {
            self.data.active_profile_id = self.data.profiles.keys().next().cloned();
        }

        self.sync_default_flags();

        self.commit(previous)?;
        self.cleanup_pending_secrets();
        Ok(())
    }

    pub async fn set_active_profile(&mut self, id: &str) -> Result<()> {
        if !self.data.profiles.contains_key(id) {
            return Err(AppError::ProfileNotFound(id.to_string()));
        }

        let previous = self.data.clone();
        self.data.active_profile_id = Some(id.to_string());
        self.sync_default_flags();
        self.commit(previous)?;
        Ok(())
    }

    pub async fn get_active_profile(&self) -> Result<Option<Profile>> {
        match &self.data.active_profile_id {
            Some(id) => {
                let profile = self.data.profiles.get(id).cloned();
                Ok(profile.map(|p| self.hydrate_profile(p)))
            }
            None => Ok(None),
        }
    }

    /// Get a profile and populate its secret from the keychain if applicable
    pub fn hydrate_profile(&self, mut profile: Profile) -> Profile {
        let stored = self.data.profiles.get(&profile.id).unwrap_or(&profile);
        if let Some(secret) = self.load_secret(stored).ok().flatten() {
            match &mut profile.credential_type {
                CredentialType::Manual {
                    secret_access_key, ..
                } => {
                    *secret_access_key = secret;
                }
                CredentialType::CustomEndpoint {
                    secret_access_key, ..
                } => {
                    *secret_access_key = secret;
                }
                _ => {}
            }
        }
        profile
    }

    fn store_secret(&self, profile: &Profile) -> Result<()> {
        match &profile.credential_type {
            CredentialType::Manual {
                secret_access_key, ..
            }
            | CredentialType::CustomEndpoint {
                secret_access_key, ..
            } => {
                if secret_access_key.is_empty() {
                    return Err(AppError::InvalidCredentials(
                        "Enter a secret access key; the stored secret could not be read.".into(),
                    ));
                }
                self.keychain.store(
                    profile.secret_ref.as_deref().unwrap_or(&profile.id),
                    secret_access_key,
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    fn queue_secret_cleanup(&mut self, profile: &Profile) {
        if matches!(
            profile.credential_type,
            CredentialType::Manual { .. } | CredentialType::CustomEndpoint { .. }
        ) {
            self.data.pending_secret_deletions.push(
                profile
                    .secret_ref
                    .clone()
                    .unwrap_or_else(|| profile.id.clone()),
            );
        }
    }

    fn cleanup_pending_secrets(&mut self) {
        if self.data.pending_secret_deletions.is_empty() {
            return;
        }
        self.data.pending_secret_deletions.retain(|key| {
            if let Err(error) = self.keychain.delete(key) {
                log::error!("Secret cleanup pending; will retry on next startup: {error}");
                true
            } else {
                false
            }
        });
        if let Err(error) = self.save() {
            log::warn!("Could not persist secret cleanup progress: {error}");
        }
    }

    fn remove_secret(&self, profile: &Profile) {
        match &profile.credential_type {
            CredentialType::Manual { .. } | CredentialType::CustomEndpoint { .. } => {
                if let Err(error) = self
                    .keychain
                    .delete(profile.secret_ref.as_deref().unwrap_or(&profile.id))
                {
                    log::error!("Profile secret cleanup failed: {error}");
                }
            }
            _ => {}
        }
    }

    pub fn load_secret(&self, profile: &Profile) -> Result<Option<String>> {
        match &profile.credential_type {
            CredentialType::Manual { .. } | CredentialType::CustomEndpoint { .. } => Ok(self
                .keychain
                .get(profile.secret_ref.as_deref().unwrap_or(&profile.id))
                .ok()),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{infer_region_from_endpoint, CredentialType, Profile, ProfileManager};
    use std::collections::HashMap;

    #[tokio::test]
    async fn failed_metadata_commit_preserves_selection_profile_and_secret() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = ProfileManager::new(dir.path().to_path_buf(), true).unwrap();
        let first = manager
            .add_profile(Profile::new(
                "first".into(),
                CredentialType::Manual {
                    access_key_id: "key".into(),
                    secret_access_key: "original".into(),
                },
                None,
            ))
            .await
            .unwrap();
        let second = manager
            .add_profile(Profile::new(
                "second".into(),
                CredentialType::Environment,
                None,
            ))
            .await
            .unwrap();
        // A directory at the metadata filename deterministically fails atomic replacement.
        std::fs::rename(
            dir.path().join("profiles.json"),
            dir.path().join("saved.json"),
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("profiles.json")).unwrap();
        assert!(manager.set_active_profile(&second.id).await.is_err());
        assert_eq!(
            manager.get_active_profile().await.unwrap().unwrap().id,
            first.id
        );
        let mut edited = first.clone();
        edited.name = "changed".into();
        edited.credential_type = CredentialType::Manual {
            access_key_id: "new-key".into(),
            secret_access_key: "new-secret".into(),
        };
        assert!(manager.update_profile(&first.id, edited).await.is_err());
        assert_eq!(manager.get_profile(&first.id).await.unwrap().name, "first");
        assert_eq!(
            manager.load_secret(&first).unwrap().as_deref(),
            Some("original")
        );
        assert!(manager.delete_profile(&first.id).await.is_err());
        assert!(manager.get_profile(&first.id).await.is_ok());
        assert_eq!(
            manager.load_secret(&first).unwrap().as_deref(),
            Some("original")
        );
        assert!(manager
            .add_profile(Profile::new(
                "third".into(),
                CredentialType::Environment,
                None
            ))
            .await
            .is_err());
        assert_eq!(manager.list_profiles().await.unwrap().len(), 2);
    }
    use std::path::PathBuf;

    fn temp_config_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("brows3-test-{}-{}", name, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp config dir should be created");
        dir
    }

    #[test]
    fn legacy_profile_maps_keep_their_entries_and_ids() {
        let json = r#"{"legacy-id":{"name":"Legacy","credential_type":{"type":"Environment"},"region":"us-east-1","is_default":true}}"#;
        let data = ProfileManager::load_profiles_data(json).unwrap();
        assert_eq!(data.profiles.len(), 1);
        assert_eq!(data.profiles["legacy-id"].id, "legacy-id");
        assert_eq!(data.active_profile_id.as_deref(), Some("legacy-id"));
        assert!(ProfileManager::load_profiles_data(r#"{"unexpected":42}"#).is_err());
    }

    #[tokio::test]
    async fn malformed_profiles_are_backed_up_before_new_profiles_are_saved() {
        let directory = temp_config_dir("invalid-profile-backup");
        let original = "{incomplete";
        std::fs::write(directory.join(super::PROFILES_FILE), original).unwrap();
        let mut manager = ProfileManager::new(directory.clone(), true).unwrap();
        manager
            .add_profile(Profile::new(
                "New".into(),
                CredentialType::Environment,
                None,
            ))
            .await
            .unwrap();
        let backup = std::fs::read_dir(&directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("profiles.invalid-")
            })
            .unwrap();
        assert_eq!(std::fs::read_to_string(backup.path()).unwrap(), original);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn manual_profile_deserializes_without_secret_in_json() {
        let json = r#"{
            "id": "manual-1",
            "name": "Manual",
            "credential_type": {
                "type": "Manual",
                "access_key_id": "AKIA123"
            },
            "region": "us-east-1",
            "is_default": true
        }"#;

        let profile: Profile = serde_json::from_str(json).expect("profile should deserialize");
        match profile.credential_type {
            CredentialType::Manual {
                access_key_id,
                secret_access_key,
            } => {
                assert_eq!(access_key_id, "AKIA123");
                assert!(secret_access_key.is_empty());
            }
            _ => panic!("expected manual credentials"),
        }
    }

    #[test]
    fn custom_endpoint_profile_deserializes_without_secret_in_json() {
        let json = r#"{
            "id": "custom-1",
            "name": "MinIO",
            "credential_type": {
                "type": "CustomEndpoint",
                "endpoint_url": "http://localhost:9000",
                "access_key_id": "minio"
            },
            "region": "us-east-1",
            "is_default": false
        }"#;

        let profile: Profile = serde_json::from_str(json).expect("profile should deserialize");
        match profile.credential_type {
            CredentialType::CustomEndpoint {
                endpoint_url,
                access_key_id,
                secret_access_key,
            } => {
                assert_eq!(endpoint_url, "http://localhost:9000");
                assert_eq!(access_key_id, "minio");
                assert!(secret_access_key.is_empty());
            }
            _ => panic!("expected custom endpoint credentials"),
        }
    }

    #[test]
    fn profiles_data_deserializes_without_active_profile_id() {
        let json = r#"{
            "profiles": {
                "profile-1": {
                    "id": "profile-1",
                    "name": "MinIO",
                    "credential_type": {
                        "type": "CustomEndpoint",
                        "endpoint_url": "http://localhost:9000",
                        "access_key_id": "minio"
                    },
                    "region": "us-east-1",
                    "is_default": true
                }
            }
        }"#;

        let data =
            ProfileManager::load_profiles_data(json).expect("profiles data should deserialize");
        assert_eq!(data.active_profile_id.as_deref(), Some("profile-1"));
        assert_eq!(data.profiles.len(), 1);
    }

    #[test]
    fn profiles_data_deserializes_from_legacy_array() {
        let json = r#"[
            {
                "id": "profile-1",
                "name": "Legacy",
                "credential_type": {
                    "type": "Manual",
                    "access_key_id": "AKIA123"
                },
                "region": "us-east-1",
                "is_default": false
            }
        ]"#;

        let data =
            ProfileManager::load_profiles_data(json).expect("legacy array should deserialize");
        assert_eq!(data.active_profile_id.as_deref(), Some("profile-1"));
        assert!(data.profiles.contains_key("profile-1"));
    }

    #[test]
    fn normalize_profiles_data_repairs_missing_ids_and_default_flag() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "legacy-key".to_string(),
            Profile {
                public_urls: Default::default(),
                secret_ref: None,
                id: String::new(),
                name: "Legacy".to_string(),
                credential_type: CredentialType::Environment,
                region: None,
                buckets: Vec::new(),
                is_default: false,
                created_at: None,
                updated_at: None,
            },
        );

        let data = ProfileManager::normalize_profiles_data(super::ProfilesData {
            profiles,
            active_profile_id: None,
            pending_secret_deletions: Vec::new(),
        });

        assert_eq!(data.profiles.len(), 1);
        assert_eq!(data.active_profile_id.as_deref(), Some("legacy-key"));
        let profile = data
            .profiles
            .get("legacy-key")
            .expect("profile should exist");
        assert_eq!(profile.id, "legacy-key");
        assert!(profile.is_default);
    }

    #[tokio::test]
    async fn update_preserves_secret_when_switching_manual_to_custom_endpoint() {
        let config_dir = temp_config_dir("manual-to-custom");
        let mut manager = ProfileManager::new(config_dir, true).expect("manager should initialize");

        let created = manager
            .add_profile(Profile::new(
                "Manual".to_string(),
                CredentialType::Manual {
                    access_key_id: "access".to_string(),
                    secret_access_key: "secret".to_string(),
                },
                Some("us-east-1".to_string()),
            ))
            .await
            .expect("profile should be added");

        let updated = manager
            .update_profile(
                &created.id,
                Profile::new(
                    "Custom".to_string(),
                    CredentialType::CustomEndpoint {
                        endpoint_url: "https://example.com".to_string(),
                        access_key_id: "access".to_string(),
                        secret_access_key: String::new(),
                    },
                    Some("auto".to_string()),
                ),
            )
            .await
            .expect("profile should be updated");

        match updated.credential_type {
            CredentialType::CustomEndpoint {
                secret_access_key, ..
            } => assert_eq!(secret_access_key, "secret"),
            _ => panic!("expected custom endpoint credentials"),
        }
    }

    #[tokio::test]
    async fn update_preserves_secret_when_switching_custom_endpoint_to_manual() {
        let config_dir = temp_config_dir("custom-to-manual");
        let mut manager = ProfileManager::new(config_dir, true).expect("manager should initialize");

        let created = manager
            .add_profile(Profile::new(
                "Custom".to_string(),
                CredentialType::CustomEndpoint {
                    endpoint_url: "https://example.com".to_string(),
                    access_key_id: "access".to_string(),
                    secret_access_key: "secret".to_string(),
                },
                Some("auto".to_string()),
            ))
            .await
            .expect("profile should be added");

        let updated = manager
            .update_profile(
                &created.id,
                Profile::new(
                    "Manual".to_string(),
                    CredentialType::Manual {
                        access_key_id: "access".to_string(),
                        secret_access_key: String::new(),
                    },
                    Some("us-east-1".to_string()),
                ),
            )
            .await
            .expect("profile should be updated");

        match updated.credential_type {
            CredentialType::Manual {
                secret_access_key, ..
            } => assert_eq!(secret_access_key, "secret"),
            _ => panic!("expected manual credentials"),
        }
    }

    #[tokio::test]
    async fn update_removes_secret_when_leaving_keychain_backed_credentials() {
        let config_dir = temp_config_dir("leave-keychain");
        let mut manager = ProfileManager::new(config_dir, true).expect("manager should initialize");

        let created = manager
            .add_profile(Profile::new(
                "Manual".to_string(),
                CredentialType::Manual {
                    access_key_id: "access".to_string(),
                    secret_access_key: "secret".to_string(),
                },
                Some("us-east-1".to_string()),
            ))
            .await
            .expect("profile should be added");

        manager
            .update_profile(
                &created.id,
                Profile::new(
                    "Shared".to_string(),
                    CredentialType::SharedConfig {
                        profile_name: Some("default".to_string()),
                    },
                    Some("us-east-1".to_string()),
                ),
            )
            .await
            .expect("profile should be updated");

        let manual_again = manager
            .update_profile(
                &created.id,
                Profile::new(
                    "Manual Again".to_string(),
                    CredentialType::Manual {
                        access_key_id: "access".to_string(),
                        secret_access_key: String::new(),
                    },
                    Some("us-east-1".to_string()),
                ),
            )
            .await
            .expect_err("a removed secret must not be reused");

        assert!(manual_again
            .to_string()
            .contains("Enter a secret access key"));
        assert!(manager.load_secret(&created).unwrap().is_none());
    }

    #[test]
    fn test_infer_region_from_endpoint() {
        assert_eq!(
            infer_region_from_endpoint("https://s3.us-east-005.backblazeb2.com"),
            Some("us-east-005".to_string())
        );
        assert_eq!(
            infer_region_from_endpoint("https://s3.eu-central-003.backblazeb2.com/"),
            Some("eu-central-003".to_string())
        );
        assert_eq!(
            infer_region_from_endpoint("https://s3.us-west-004.backblazeb2.com:443"),
            Some("us-west-004".to_string())
        );
        assert_eq!(
            infer_region_from_endpoint("https://s3.us-east-2.wasabisys.com"),
            Some("us-east-2".to_string())
        );
        assert_eq!(
            infer_region_from_endpoint("https://nyc3.digitaloceanspaces.com"),
            Some("nyc3".to_string())
        );
        assert_eq!(
            infer_region_from_endpoint("https://us-east-1.linodeobjects.com"),
            Some("us-east-1".to_string())
        );
        assert_eq!(
            infer_region_from_endpoint("https://s3.fr-par.scw.cloud"),
            Some("fr-par".to_string())
        );
        assert_eq!(
            infer_region_from_endpoint("https://ewr1.vultrobjects.com"),
            Some("ewr1".to_string())
        );
        // Cloudflare R2 / MinIO should not infer a region
        assert_eq!(
            infer_region_from_endpoint("https://abc12345.r2.cloudflarestorage.com"),
            None
        );
        assert_eq!(
            infer_region_from_endpoint("http://localhost:9000"),
            None
        );
    }

    #[test]
    fn test_profile_effective_region_auto_inference() {
        // When region is "auto" on Backblaze B2, infer "us-east-005"
        let b2_profile = Profile::new(
            "B2".to_string(),
            CredentialType::CustomEndpoint {
                endpoint_url: "https://s3.us-east-005.backblazeb2.com".to_string(),
                access_key_id: "key".to_string(),
                secret_access_key: "sec".to_string(),
            },
            Some("auto".to_string()),
        );
        assert_eq!(b2_profile.effective_region(), "us-east-005");

        // When region is empty on Backblaze B2, infer "us-east-005"
        let b2_empty = Profile::new(
            "B2".to_string(),
            CredentialType::CustomEndpoint {
                endpoint_url: "https://s3.us-east-005.backblazeb2.com".to_string(),
                access_key_id: "key".to_string(),
                secret_access_key: "sec".to_string(),
            },
            None,
        );
        assert_eq!(b2_empty.effective_region(), "us-east-005");

        // Explicit non-auto region overrides inference
        let b2_explicit = Profile::new(
            "B2".to_string(),
            CredentialType::CustomEndpoint {
                endpoint_url: "https://s3.us-east-005.backblazeb2.com".to_string(),
                access_key_id: "key".to_string(),
                secret_access_key: "sec".to_string(),
            },
            Some("custom-override".to_string()),
        );
        assert_eq!(b2_explicit.effective_region(), "custom-override");

        // Cloudflare R2 with "auto" preserves "auto"
        let r2_profile = Profile::new(
            "R2".to_string(),
            CredentialType::CustomEndpoint {
                endpoint_url: "https://abc.r2.cloudflarestorage.com".to_string(),
                access_key_id: "key".to_string(),
                secret_access_key: "sec".to_string(),
            },
            Some("auto".to_string()),
        );
        assert_eq!(r2_profile.effective_region(), "auto");
    }

    #[test]
    fn test_profile_buckets_serialization_and_legacy_compatibility() {
        // Deserializing legacy profile without "buckets" field defaults to empty Vec
        let legacy_json = r#"{
            "id": "p-1",
            "name": "Legacy Profile",
            "credential_type": { "type": "Environment" },
            "region": "us-east-1",
            "is_default": true
        }"#;

        let profile: Profile = serde_json::from_str(legacy_json).unwrap();
        assert!(profile.buckets.is_empty());

        // Serializing and deserializing profile with buckets
        let mut with_buckets = profile;
        with_buckets.buckets = vec!["bucket-alpha".to_string(), "bucket-beta".to_string()];

        let json = serde_json::to_string(&with_buckets).unwrap();
        let parsed: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.buckets, vec!["bucket-alpha", "bucket-beta"]);
    }
}

