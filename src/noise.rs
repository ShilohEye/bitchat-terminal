#![allow(dead_code)]

use snow::{Builder, HandshakeState, TransportState, Error as SnowError};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Digest};
use x25519_dalek::{StaticSecret, PublicKey};
use rand::RngCore;
use pbkdf2::pbkdf2_hmac;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

#[derive(Error, Debug)]
pub enum NoiseError {
    #[error("Snow error: {0}")]
    Snow(#[from] SnowError),
    #[error("Handshake not complete")]
    HandshakeNotComplete,
    #[error("Session not found for peer: {0}")]
    SessionNotFound(String),
    #[error("Invalid message format")]
    InvalidMessage,
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid key length")]
    InvalidKeyLength,
}

pub type NoiseResult<T> = Result<T, NoiseError>;

pub struct NoiseSession {
    pub peer_id: String,
    transport: TransportState,
    pub remote_static_key: Vec<u8>,
    pub established_time: SystemTime,
    pub sent_count: u64,
    pub recv_count: u64,
}

impl NoiseSession {
    pub fn new(peer_id: String, transport: TransportState, remote_static_key: Vec<u8>) -> Self {
        Self {
            peer_id,
            transport,
            remote_static_key,
            established_time: SystemTime::now(),
            sent_count: 0,
            recv_count: 0,
        }
    }
    
    pub fn encrypt(&mut self, data: &[u8]) -> NoiseResult<Vec<u8>> {
        let mut buf = vec![0u8; data.len() + 16];
        let len = self.transport.write_message(data, &mut buf)?;
        buf.truncate(len);
        self.sent_count += 1;
        Ok(buf)
    }
    
    pub fn decrypt(&mut self, data: &[u8]) -> NoiseResult<Vec<u8>> {
        let mut buf = vec![0u8; data.len()];
        let len = self.transport.read_message(data, &mut buf)?;
        buf.truncate(len);
        self.recv_count += 1;
        Ok(buf)
    }
    
    pub fn get_fingerprint(&self) -> String {
        let hash = Sha256::digest(&self.remote_static_key);
        hex::encode(&hash[..16])
    }
    
    pub fn age(&self) -> std::time::Duration {
        SystemTime::now().duration_since(self.established_time).unwrap_or_default()
    }
    
    pub fn get_remote_static_key(&self) -> &[u8] {
        &self.remote_static_key
    }
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseSession")
            .field("peer_id", &self.peer_id)
            .field("remote_static_key", &hex::encode(&self.remote_static_key))
            .field("established_time", &self.established_time)
            .field("sent_count", &self.sent_count)
            .field("recv_count", &self.recv_count)
            .finish()
    }
}

pub struct NoiseHandshakeManager {
    handshake: HandshakeState,
    peer_id: String,
    role: HandshakeRole,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

impl NoiseHandshakeManager {
    pub fn new_initiator(peer_id: String, static_key: &[u8; 32]) -> NoiseResult<Self> {
        let builder = Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse()?);
        let handshake = builder
            .local_private_key(static_key)
            .build_initiator()?;
        
        Ok(Self {
            handshake,
            peer_id,
            role: HandshakeRole::Initiator,
        })
    }
    
    pub fn new_responder(peer_id: String, static_key: &[u8; 32]) -> NoiseResult<Self> {
        let builder = Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse()?);
        let handshake = builder
            .local_private_key(static_key)
            .build_responder()?;
        
        Ok(Self {
            handshake,
            peer_id,
            role: HandshakeRole::Responder,
        })
    }
    
    pub fn write_message(&mut self, payload: &[u8]) -> NoiseResult<Vec<u8>> {
        // XX pattern msg can be up to ~100 bytes for handshake
        let mut buf = vec![0u8; 512];
        let len = self.handshake.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
    
    pub fn read_message(&mut self, message: &[u8]) -> NoiseResult<Vec<u8>> {
        let mut buf = vec![0u8; 512];
        let len = self.handshake.read_message(message, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
    
    pub fn is_handshake_finished(&self) -> bool {
        self.handshake.is_handshake_finished()
    }
    
    pub fn get_role(&self) -> HandshakeRole {
        self.role
    }
    
    pub fn into_transport_mode(self) -> NoiseResult<NoiseSession> {
        if !self.is_handshake_finished() {
            return Err(NoiseError::HandshakeNotComplete);
        }
        
        let transport = self.handshake.into_transport_mode()?;
        let remote_static_key = transport.get_remote_static()
            .ok_or(NoiseError::InvalidMessage)?
            .to_vec();
        
        Ok(NoiseSession::new(self.peer_id, transport, remote_static_key))
    }
}

impl std::fmt::Debug for NoiseHandshakeManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseHandshakeManager")
            .field("peer_id", &self.peer_id)
            .field("role", &self.role)
            .field("is_finished", &self.is_handshake_finished())
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NoiseIdentityAnnouncement {
    #[serde(rename = "peerID")]
    pub peer_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String, // base64 encoded
    pub nickname: String,
    pub timestamp: f64,
    pub signature: String, // base64 encoded
    #[serde(rename = "previousPeerID")]
    pub previous_peer_id: Option<String>,
}

pub struct NoiseService {
    static_key: [u8; 32],
    sessions: HashMap<String, NoiseSession>,
    handshake_states: HashMap<String, NoiseHandshakeManager>,
    handshake_attempt_times: HashMap<String, SystemTime>,
    handshake_timeout: std::time::Duration,
    // Callbacks for events
    on_peer_authenticated: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_handshake_required: Option<Box<dyn Fn(&str) + Send + Sync>>,
}

impl NoiseService {
    pub fn new() -> Self {
        let mut static_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut static_key);
        
        Self {
            static_key,
            sessions: HashMap::new(),
            handshake_states: HashMap::new(),
            handshake_attempt_times: HashMap::new(),
            handshake_timeout: std::time::Duration::from_secs(5),
            on_peer_authenticated: None,
            on_handshake_required: None,
        }
    }
    
    pub fn with_static_key(static_key: [u8; 32]) -> Self {
        Self {
            static_key,
            sessions: HashMap::new(),
            handshake_states: HashMap::new(),
            handshake_attempt_times: HashMap::new(),
            handshake_timeout: std::time::Duration::from_secs(5),
            on_peer_authenticated: None,
            on_handshake_required: None,
        }
    }
    
    pub fn set_on_peer_authenticated<F>(&mut self, callback: F)
    where
        F: Fn(&str, &str) + Send + Sync + 'static,
    {
        self.on_peer_authenticated = Some(Box::new(callback));
    }
    
    pub fn set_on_handshake_required<F>(&mut self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.on_handshake_required = Some(Box::new(callback));
    }
    
    pub fn get_public_key(&self) -> Vec<u8> {
        let secret = StaticSecret::from(self.static_key);
        let public = PublicKey::from(&secret);
        public.as_bytes().to_vec()
    }
    
    pub fn get_identity_fingerprint(&self) -> String {
        let public_key = self.get_public_key();
        let hash = Sha256::digest(&public_key);
        hex::encode(&hash[..16])
    }
    
    pub fn should_initiate_handshake(&mut self, peer_id: &str) -> bool {
        let now = SystemTime::now();
        
        if let Some(last_attempt) = self.handshake_attempt_times.get(peer_id) {
            if now.duration_since(*last_attempt).unwrap_or_default() < self.handshake_timeout {
                return false; // Too recent
            }
        }
        
        self.handshake_attempt_times.insert(peer_id.to_string(), now);
        true
    }
    
    pub fn initiate_handshake(&mut self, peer_id: &str) -> NoiseResult<Vec<u8>> {
        // Clean up any existing handshake state and session
        self.handshake_states.remove(peer_id);
        self.sessions.remove(peer_id);
        
        let mut handshake = NoiseHandshakeManager::new_initiator(
            peer_id.to_string(),
            &self.static_key
        )?;
        
        let message = handshake.write_message(&[])?;
        self.handshake_states.insert(peer_id.to_string(), handshake);
        
        Ok(message)
    }
    
    pub fn process_handshake_message(&mut self, peer_id: &str, message: &[u8]) -> NoiseResult<Option<Vec<u8>>> {
        // Validate input
        if message.is_empty() {
            return Err(NoiseError::InvalidMessage);
        }
        
        if message.len() < 32 {
            return Err(NoiseError::HandshakeFailed(
                format!("Handshake message too short: {} bytes", message.len())
            ));
        }
        
        // Check if we have an ongoing handshake
        if let Some(mut handshake) = self.handshake_states.remove(peer_id) {
            // Continue existing handshake
            let _payload = handshake.read_message(message)
                .map_err(|e| NoiseError::HandshakeFailed(format!("Read message failed: {}", e)))?;
            
            let response = if !handshake.is_handshake_finished() {
                Some(handshake.write_message(&[])?)
            } else {
                None
            };
            
            if handshake.is_handshake_finished() {
                // Handshake complete, create session
                let session = handshake.into_transport_mode()?;
                let fingerprint = session.get_fingerprint();
                self.sessions.insert(peer_id.to_string(), session);
                self.handshake_attempt_times.remove(peer_id);
                
                // Notify auth
                if let Some(ref callback) = self.on_peer_authenticated {
                    callback(peer_id, &fingerprint);
                }
            } else {
                // Put handshake back
                self.handshake_states.insert(peer_id.to_string(), handshake);
            }
            
            Ok(response)
        } else {
            // New handshake from peer we are responder
            let mut handshake = NoiseHandshakeManager::new_responder(
                peer_id.to_string(),
                &self.static_key
            )?;
            
            let _payload = handshake.read_message(message)
                .map_err(|e| NoiseError::HandshakeFailed(format!("Initial read failed: {}", e)))?;
            
            let response = handshake.write_message(&[])?;
            
            if handshake.is_handshake_finished() {
                // Handshake complete in one round (shouldn't happen with XX)
                let session = handshake.into_transport_mode()?;
                let fingerprint = session.get_fingerprint();
                self.sessions.insert(peer_id.to_string(), session);
                
                // Notify auth
                if let Some(ref callback) = self.on_peer_authenticated {
                    callback(peer_id, &fingerprint);
                }
            } else {
                self.handshake_states.insert(peer_id.to_string(), handshake);
            }
            
            Ok(Some(response))
        }
    }
    
    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.contains_key(peer_id)
    }
    
    pub fn is_session_established(&self, peer_id: &str) -> bool {
        self.has_session(peer_id)
    }
    
    pub fn encrypt(&mut self, peer_id: &str, data: &[u8]) -> NoiseResult<Vec<u8>> {
        if !self.has_session(peer_id) {
            if let Some(ref callback) = self.on_handshake_required {
                callback(peer_id);
            }
            return Err(NoiseError::SessionNotFound(peer_id.to_string()));
        }
        
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| NoiseError::SessionNotFound(peer_id.to_string()))?;
        session.encrypt(data)
    }
    
    pub fn decrypt(&mut self, peer_id: &str, data: &[u8]) -> NoiseResult<Vec<u8>> {
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| NoiseError::SessionNotFound(peer_id.to_string()))?;
        session.decrypt(data)
    }
    
    pub fn encrypt_for_peer(&mut self, peer_id: &str, data: &[u8]) -> NoiseResult<Vec<u8>> {
        self.encrypt(peer_id, data)
    }
    
    pub fn decrypt_from_peer(&mut self, peer_id: &str, data: &[u8]) -> NoiseResult<Vec<u8>> {
        self.decrypt(peer_id, data)
    }
    
    pub fn get_peer_fingerprint(&self, peer_id: &str) -> Option<String> {
        self.sessions.get(peer_id).map(|s| s.get_fingerprint())
    }
    
    pub fn remove_session(&mut self, peer_id: &str) {
        self.sessions.remove(peer_id);
        self.handshake_states.remove(peer_id);
        self.handshake_attempt_times.remove(peer_id);
    }
    
    pub fn clear_handshake_state(&mut self, peer_id: &str) {
        self.handshake_states.remove(peer_id);
        self.handshake_attempt_times.remove(peer_id);
    }
    
    pub fn cleanup_old_sessions(&mut self, max_age_secs: u64) {
        let cutoff = SystemTime::now() - std::time::Duration::from_secs(max_age_secs);
        
        let expired_peers: Vec<String> = self.sessions
            .iter()
            .filter(|(_, session)| session.established_time < cutoff)
            .map(|(peer_id, _)| peer_id.clone())
            .collect();
        
        for peer_id in expired_peers {
            self.remove_session(&peer_id);
        }
    }
    
    pub fn get_session_count(&self) -> usize {
        self.sessions.len()
    }
    
    pub fn get_pending_handshake_count(&self) -> usize {
        self.handshake_states.len()
    }
    
    pub fn get_active_peers(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }
    
    pub fn get_session_info(&self) -> Vec<(String, SessionInfo)> {
        self.sessions.iter().map(|(peer_id, session)| {
            (peer_id.clone(), SessionInfo {
                fingerprint: session.get_fingerprint(),
                age: session.age(),
                sent_count: session.sent_count,
                recv_count: session.recv_count,
            })
        }).collect()
    }
    
    pub fn get_all_sessions(&self) -> HashMap<String, SessionInfo> {
        self.sessions.iter().map(|(peer_id, session)| {
            (peer_id.clone(), SessionInfo {
                fingerprint: session.get_fingerprint(),
                age: session.age(),
                sent_count: session.sent_count,
                recv_count: session.recv_count,
            })
        }).collect()
    }
    
    pub fn create_identity_announcement(&self, peer_id: &str, nickname: &str) -> NoiseResult<Vec<u8>> {
        let public_key = self.get_public_key();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        // Signature data
        let binding_data = format!("{}{}{}", peer_id, BASE64.encode(&public_key), timestamp);
        let signature = self.sign_data(binding_data.as_bytes());
        
        let announcement = NoiseIdentityAnnouncement {
            peer_id: peer_id.to_string(),
            public_key: BASE64.encode(&public_key),
            nickname: nickname.to_string(),
            timestamp,
            signature: BASE64.encode(&signature),
            previous_peer_id: None, // TODO: Track previous peer ID for rotation
        };
        
        Ok(serde_json::to_vec(&announcement)?)
    }
    
    pub fn verify_identity_announcement(&self, data: &[u8]) -> NoiseResult<NoiseIdentityAnnouncement> {
        let announcement: NoiseIdentityAnnouncement = serde_json::from_slice(data)
            .map_err(|e| NoiseError::Json(e))?;
        
        // Verify signature
        let public_key = BASE64.decode(&announcement.public_key)
            .map_err(|e| NoiseError::Base64(e))?;
        let signature = BASE64.decode(&announcement.signature)
            .map_err(|e| NoiseError::Base64(e))?;
        
        let binding_data = format!("{}{}{}", 
            announcement.peer_id, 
            announcement.public_key, 
            announcement.timestamp
        );
        
        let expected_signature = self.verify_signature(&binding_data, &signature, &public_key);
        if !expected_signature {
            return Err(NoiseError::HandshakeFailed("Invalid signature".to_string()));
        }
        
        Ok(announcement)
    }
    
    fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        // using SHA256 + static key
        // TODO: Ed25519 signatures
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&self.static_key);
        hasher.finalize().to_vec()
    }
    
    fn verify_signature(&self, data: &str, signature: &[u8], _public_key: &[u8]) -> bool {
        // TODO: Ed25519 verification
        let expected = self.sign_data(data.as_bytes());
        signature == expected
    }
    
    // Channel encryption
    pub fn encrypt_with_key(&self, data: &[u8], key: &[u8; 32]) -> NoiseResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| NoiseError::InvalidKeyLength)?;
        
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|_| NoiseError::InvalidMessage)?;
        
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    pub fn decrypt_with_key(&self, data: &[u8], key: &[u8; 32]) -> NoiseResult<Vec<u8>> {
        if data.len() < 12 {
            return Err(NoiseError::InvalidMessage);
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| NoiseError::InvalidKeyLength)?;
        
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| NoiseError::InvalidMessage)?;
        
        Ok(plaintext)
    }
    
    // Channel key derivation
    pub fn derive_channel_key(password: &str, channel: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            channel.as_bytes(),
            100_000,
            &mut key,
        );
        key
    }
}

impl Default for NoiseService {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NoiseService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseService")
            .field("session_count", &self.sessions.len())
            .field("handshake_count", &self.handshake_states.len())
            .field("fingerprint", &self.get_identity_fingerprint())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub fingerprint: String,
    pub age: std::time::Duration,
    pub sent_count: u64,
    pub recv_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake() {
        let mut alice = NoiseService::new();
        let mut bob = NoiseService::new();
        
        // Alice initiates handshake
        let msg1 = alice.initiate_handshake("bob").unwrap();
        assert!(!msg1.is_empty());
        
        // Bob processes and responds
        let msg2 = bob.process_handshake_message("alice", &msg1).unwrap().unwrap();
        assert!(!msg2.is_empty());
        
        // Alice processes response
        let msg3 = alice.process_handshake_message("bob", &msg2).unwrap();
        
        // Bob processes final message if it exists
        if let Some(final_msg) = msg3 {
            bob.process_handshake_message("alice", &final_msg).unwrap();
        }
        
        // Both should have sessions now
        assert!(alice.has_session("bob"));
        assert!(bob.has_session("alice"));
        
        // Test encryption/decryption
        let plaintext = b"Hello, Bob!";
        let encrypted = alice.encrypt("bob", plaintext).unwrap();
        let decrypted = bob.decrypt("alice", &encrypted).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_identity_announcement() {
        let service = NoiseService::new();
        let announcement_data = service.create_identity_announcement("peer123", "Alice").unwrap();
        let announcement = service.verify_identity_announcement(&announcement_data).unwrap();
        
        assert_eq!(announcement.peer_id, "peer123");
        assert_eq!(announcement.nickname, "Alice");
        assert!(!announcement.public_key.is_empty());
        assert!(!announcement.signature.is_empty());
    }
    
    #[test]
    fn test_channel_encryption() {
        let service = NoiseService::new();
        let key = NoiseService::derive_channel_key("password123", "#general");
        
        let plaintext = b"Channel message";
        let encrypted = service.encrypt_with_key(plaintext, &key).unwrap();
        let decrypted = service.decrypt_with_key(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
}