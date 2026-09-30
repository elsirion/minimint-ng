//! CFG-006/007 signed operational endpoint data. These local records never
//! mutate the configured endpoint map or its federation identity commitment.
use crate::{
    codec::{
        ConsensusDecode, ConsensusEncode, DecodeError, Reader, decode_whole,
        text::{hex_decode, hex_encode},
    },
    config::{self, CanonicalUrl},
    crypto::secp::{self, SecretKey},
    json,
    protocol::PeerId,
    storage::{Namespace, Snapshot, Store, StoreError},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};
use std::collections::BTreeMap;
const ANNOUNCEMENT: &[u8] = b"api-announcement/v1/";
const METADATA: &[u8] = b"guardian-metadata/v1/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiAnnouncement {
    pub api_url: CanonicalUrl,
    pub nonce: u64,
}
impl ApiAnnouncement {
    pub fn digest(&self) -> [u8; 32] {
        config::api_announcement_digest(&self.api_url, self.nonce)
    }
    pub fn json(&self) -> Value {
        json!({"api_url":self.api_url.as_str(),"nonce":self.nonce})
    }
    fn from_json(value: &Value) -> Result<Self, AnnouncementError> {
        Ok(Self {
            api_url: url(field(value, "api_url")?)?,
            nonce: uint(field(value, "nonce")?)?,
        })
    }
}
config::record!(ApiAnnouncement, api_url, nonce);
#[derive(Clone, PartialEq, Eq)]
pub struct SignedAnnouncement {
    pub api_announcement: ApiAnnouncement,
    pub signature: [u8; 64],
}
impl SignedAnnouncement {
    pub fn json(&self) -> Value {
        json!({"api_announcement":self.api_announcement.json(),"signature":hex_encode(&self.signature)})
    }
    fn from_json(value: &Value) -> Result<Self, AnnouncementError> {
        Ok(Self {
            api_announcement: ApiAnnouncement::from_json(field(value, "api_announcement")?)?,
            signature: signature(field(value, "signature")?)?,
        })
    }
}
config::record!(SignedAnnouncement, api_announcement, signature);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianMetadata {
    pub api_urls: Vec<CanonicalUrl>,
    pub pkarr_id_z32: String,
    pub timestamp_secs: u64,
    pub iroh_next_endpoint: Option<String>,
}
impl GuardianMetadata {
    pub fn parse(content: &str) -> Result<Self, AnnouncementError> {
        // This parser recursion bound is local API resource policy. Content is
        // retained exactly; unknown JSON fields do not enter a rebuilt message.
        let value = json::parse(content.as_bytes(), content.len(), 64)
            .map_err(|_| AnnouncementError::InvalidParams)?;
        let api_urls = field(&value, "api_urls")?
            .as_array()
            .ok_or(AnnouncementError::InvalidParams)?
            .iter()
            .map(url)
            .collect::<Result<_, _>>()?;
        let pkarr_id_z32 = field(&value, "pkarr_id_z32")?
            .as_str()
            .ok_or(AnnouncementError::InvalidParams)?
            .to_owned();
        let timestamp_secs = uint(field(&value, "timestamp_secs")?)?;
        let iroh_next_endpoint = match value.get("iroh_next_endpoint") {
            None => None,
            Some(value) if value.is_null() => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or(AnnouncementError::InvalidParams)?
                    .to_owned(),
            ),
        };
        Ok(Self {
            api_urls,
            pkarr_id_z32,
            timestamp_secs,
            iroh_next_endpoint,
        })
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct SignedMetadata {
    pub content: String,
    pub signature: [u8; 64],
}
impl SignedMetadata {
    pub fn digest(&self) -> [u8; 32] {
        config::guardian_metadata_digest(&self.content)
    }
    pub fn json(&self) -> Value {
        json!({"content":self.content,"signature":hex_encode(&self.signature)})
    }
    fn from_json(value: &Value) -> Result<Self, AnnouncementError> {
        Ok(Self {
            content: field(value, "content")?
                .as_str()
                .ok_or(AnnouncementError::InvalidParams)?
                .to_owned(),
            signature: signature(field(value, "signature")?)?,
        })
    }
}
config::record!(SignedMetadata, content, signature);
#[derive(Debug)]
pub enum AnnouncementError {
    InvalidConfiguration,
    UnknownPeer,
    InvalidSignature,
    InvalidParams,
    UnsupportedUrl,
    NonceNotIncreasing,
    TimestampNotIncreasing,
    TimestampTooFarAhead,
    CorruptState,
    Storage(StoreError),
    MethodNotFound,
    SchemaUnavailable,
}
impl From<StoreError> for AnnouncementError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}
impl std::fmt::Display for AnnouncementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "Invalid announcement configuration",
            Self::UnknownPeer => "Unknown guardian",
            Self::InvalidSignature => "Invalid announcement signature",
            Self::InvalidParams => "Invalid announcement parameters",
            Self::UnsupportedUrl => "URL outside supported profile",
            Self::NonceNotIncreasing => "Announcement nonce must increase",
            Self::TimestampNotIncreasing => "Metadata timestamp must increase",
            Self::TimestampTooFarAhead => "Metadata timestamp too far ahead",
            Self::CorruptState => "Invalid stored announcement",
            Self::Storage(_) => "Announcement storage failed",
            Self::MethodNotFound => "Method not found",
            Self::SchemaUnavailable => "Signing endpoint schema unavailable",
        })
    }
}
impl std::error::Error for AnnouncementError {}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, AnnouncementError> {
    if !value.is_object() {
        return Err(AnnouncementError::InvalidParams);
    }
    value.get(name).ok_or(AnnouncementError::InvalidParams)
}
fn uint(value: &Value) -> Result<u64, AnnouncementError> {
    json::unsigned(value).map_err(|_| AnnouncementError::InvalidParams)
}
fn url(value: &Value) -> Result<CanonicalUrl, AnnouncementError> {
    CanonicalUrl::simple(value.as_str().ok_or(AnnouncementError::InvalidParams)?)
        .map_err(|_| AnnouncementError::UnsupportedUrl)
}
fn signature(value: &Value) -> Result<[u8; 64], AnnouncementError> {
    let text = value.as_str().ok_or(AnnouncementError::InvalidParams)?;
    if text.len() != 128 {
        return Err(AnnouncementError::InvalidParams);
    }
    hex_decode(text)
        .map_err(|_| AnnouncementError::InvalidParams)?
        .try_into()
        .map_err(|_| AnnouncementError::InvalidParams)
}
fn key(prefix: &[u8], peer: PeerId) -> Vec<u8> {
    [prefix, &peer.0.to_be_bytes()].concat()
}
fn stored_peer(prefix: &[u8], key: &[u8]) -> Result<PeerId, AnnouncementError> {
    Ok(PeerId(u16::from_be_bytes(
        key.get(prefix.len()..)
            .ok_or(AnnouncementError::CorruptState)?
            .try_into()
            .map_err(|_| AnnouncementError::CorruptState)?,
    )))
}
/// Contains the local broadcast secret; no Debug. Administrator authorization is
/// mandatory in the caller of the typed signing methods. Public submit/read
/// methods require only the enclosing transport access policy.
pub struct AnnouncementApi {
    store: Store,
    keys: BTreeMap<PeerId, [u8; 33]>,
    local: PeerId,
    secret: SecretKey,
}
impl AnnouncementApi {
    pub fn new(
        store: Store,
        keys: BTreeMap<PeerId, [u8; 33]>,
        local: PeerId,
        secret: SecretKey,
    ) -> Result<Self, AnnouncementError> {
        if keys.get(&local) != Some(&secret.public_key())
            || keys
                .values()
                .any(|key| secp::validate_public_key(key).is_err())
        {
            return Err(AnnouncementError::InvalidConfiguration);
        }
        Ok(Self {
            store,
            keys,
            local,
            secret,
        })
    }
    pub fn local_peer(&self) -> PeerId {
        self.local
    }
    fn verify(
        &self,
        peer: PeerId,
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), AnnouncementError> {
        let key = self.keys.get(&peer).ok_or(AnnouncementError::UnknownPeer)?;
        let public = secp::x_only(key).map_err(|_| AnnouncementError::InvalidConfiguration)?;
        secp::schnorr_verify(&public, digest, signature)
            .map_err(|_| AnnouncementError::InvalidSignature)
    }
    pub fn sign_announcement(
        &self,
        api_announcement: ApiAnnouncement,
    ) -> Result<SignedAnnouncement, AnnouncementError> {
        let signature = self
            .secret
            .schnorr_sign(&api_announcement.digest())
            .map_err(|_| AnnouncementError::InvalidConfiguration)?;
        Ok(SignedAnnouncement {
            api_announcement,
            signature,
        })
    }
    pub fn sign_metadata(
        &self,
        content: String,
        now: u64,
    ) -> Result<SignedMetadata, AnnouncementError> {
        let metadata = GuardianMetadata::parse(&content)?;
        if metadata.timestamp_secs > now.saturating_add(3600) {
            return Err(AnnouncementError::TimestampTooFarAhead);
        }
        let signature = self
            .secret
            .schnorr_sign(&config::guardian_metadata_digest(&content))
            .map_err(|_| AnnouncementError::InvalidConfiguration)?;
        Ok(SignedMetadata { content, signature })
    }
    fn decode_announcement(
        &self,
        peer: PeerId,
        bytes: &[u8],
    ) -> Result<SignedAnnouncement, AnnouncementError> {
        let signed: SignedAnnouncement =
            decode_whole(bytes).map_err(|_| AnnouncementError::CorruptState)?;
        self.verify(peer, &signed.api_announcement.digest(), &signed.signature)
            .map_err(|_| AnnouncementError::CorruptState)?;
        Ok(signed)
    }
    fn decode_metadata(
        &self,
        peer: PeerId,
        bytes: &[u8],
    ) -> Result<(SignedMetadata, GuardianMetadata), AnnouncementError> {
        let signed: SignedMetadata =
            decode_whole(bytes).map_err(|_| AnnouncementError::CorruptState)?;
        self.verify(peer, &signed.digest(), &signed.signature)
            .map_err(|_| AnnouncementError::CorruptState)?;
        let metadata = GuardianMetadata::parse(&signed.content)
            .map_err(|_| AnnouncementError::CorruptState)?;
        Ok((signed, metadata))
    }
    pub fn submit_announcement(
        &self,
        peer: PeerId,
        signed: &SignedAnnouncement,
    ) -> Result<(), AnnouncementError> {
        self.verify(peer, &signed.api_announcement.digest(), &signed.signature)?;
        let key = key(ANNOUNCEMENT, peer);
        let mut writer = self.store.transaction()?;
        if let Some(bytes) = writer.get(Namespace::Local, &key)? {
            let previous = self.decode_announcement(peer, &bytes)?;
            if previous.api_announcement == signed.api_announcement {
                return Ok(());
            }
            if signed.api_announcement.nonce <= previous.api_announcement.nonce {
                return Err(AnnouncementError::NonceNotIncreasing);
            }
        }
        writer.put(Namespace::Local, &key, &signed.consensus_encode())?;
        writer.commit()?;
        Ok(())
    }
    pub fn submit_metadata(
        &self,
        peer: PeerId,
        signed: &SignedMetadata,
        now: u64,
    ) -> Result<(), AnnouncementError> {
        self.verify(peer, &signed.digest(), &signed.signature)?;
        let metadata = GuardianMetadata::parse(&signed.content)?;
        if metadata.timestamp_secs > now.saturating_add(3600) {
            return Err(AnnouncementError::TimestampTooFarAhead);
        }
        let key = key(METADATA, peer);
        let mut writer = self.store.transaction()?;
        if let Some(bytes) = writer.get(Namespace::Local, &key)? {
            let (previous, previous_metadata) = self.decode_metadata(peer, &bytes)?;
            if previous.content == signed.content {
                return Ok(());
            }
            if metadata.timestamp_secs <= previous_metadata.timestamp_secs {
                return Err(AnnouncementError::TimestampNotIncreasing);
            }
        }
        writer.put(Namespace::Local, &key, &signed.consensus_encode())?;
        writer.commit()?;
        Ok(())
    }
    pub fn announcements(
        &self,
        snapshot: &Snapshot,
    ) -> Result<BTreeMap<PeerId, SignedAnnouncement>, AnnouncementError> {
        snapshot
            .scan_prefix(Namespace::Local, ANNOUNCEMENT)?
            .into_iter()
            .map(|(key, bytes)| {
                let peer = stored_peer(ANNOUNCEMENT, &key)?;
                Ok((peer, self.decode_announcement(peer, &bytes)?))
            })
            .collect()
    }
    pub fn metadata(
        &self,
        snapshot: &Snapshot,
    ) -> Result<BTreeMap<PeerId, SignedMetadata>, AnnouncementError> {
        snapshot
            .scan_prefix(Namespace::Local, METADATA)?
            .into_iter()
            .map(|(key, bytes)| {
                let peer = stored_peer(METADATA, &key)?;
                Ok((peer, self.decode_metadata(peer, &bytes)?.0))
            })
            .collect()
    }
    pub fn operational_api_url(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        configured: &CanonicalUrl,
    ) -> Result<CanonicalUrl, AnnouncementError> {
        if !self.keys.contains_key(&peer) {
            return Err(AnnouncementError::UnknownPeer);
        }
        Ok(
            match snapshot.get(Namespace::Local, &key(ANNOUNCEMENT, peer))? {
                Some(bytes) => {
                    self.decode_announcement(peer, &bytes)?
                        .api_announcement
                        .api_url
                }
                None => configured.clone(),
            },
        )
    }
    pub fn dispatch(
        &self,
        method: &str,
        params: &Value,
        now: u64,
    ) -> Result<Value, AnnouncementError> {
        match method {
            "api_announcements" | "guardian_metadata" => {
                if !params.is_null() {
                    return Err(AnnouncementError::InvalidParams);
                }
                let snapshot = self.store.snapshot()?;
                let map: BTreeMap<String, Value> = if method == "api_announcements" {
                    self.announcements(&snapshot)?
                        .into_iter()
                        .map(|(id, value)| (id.0.to_string(), value.json()))
                        .collect()
                } else {
                    self.metadata(&snapshot)?
                        .into_iter()
                        .map(|(id, value)| (id.0.to_string(), value.json()))
                        .collect()
                };
                Ok(json!(map))
            }
            "submit_api_announcement" | "submit_guardian_metadata" => {
                let peer = PeerId(
                    uint(field(params, "peer_id")?)?
                        .try_into()
                        .map_err(|_| AnnouncementError::InvalidParams)?,
                );
                if method == "submit_api_announcement" {
                    self.submit_announcement(peer, &SignedAnnouncement::from_json(params)?)?;
                } else {
                    self.submit_metadata(peer, &SignedMetadata::from_json(params)?, now)?;
                }
                Ok(json!(null))
            }
            "sign_api_announcement" | "sign_guardian_metadata" => {
                Err(AnnouncementError::SchemaUnavailable)
            }
            _ => Err(AnnouncementError::MethodNotFound),
        }
    }
}
