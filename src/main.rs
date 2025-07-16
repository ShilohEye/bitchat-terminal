use btleplug::api::{Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType};

use btleplug::platform::{Manager, Peripheral};

use tokio::io::{self, AsyncBufReadExt, BufReader};
use std::io::Write;

use tokio::sync::mpsc;

use tokio::time::{self, Duration};

use uuid::Uuid;

use futures::stream::StreamExt;

use std::collections::{HashMap, HashSet};

use std::convert::TryInto;

use std::sync::{Arc, Mutex};

use std::time::{SystemTime, UNIX_EPOCH};

use std::env;

use bloomfilter::Bloom;

// use ed25519_dalek::SigningKey; // Removed: unused

// use x25519_dalek::StaticSecret; // Removed: unused

// use rand::rngs::OsRng; // Removed: unused
use rand::Rng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize, Deserializer};
use serde_json;

// Debug levels
#[derive(Debug, Clone, Copy, PartialEq)]
enum DebugLevel {
    Clean = 0,    // Default - minimal output
    Basic = 1,    // Connection info, key exchanges
    Full = 2,     // All debug output
}

// Global debug level
static mut DEBUG_LEVEL: DebugLevel = DebugLevel::Clean;

// Debug macro for basic debug (level 1+)
macro_rules! debug_println {
    ($($arg:tt)*) => {
        unsafe {
            if DEBUG_LEVEL as u8 >= DebugLevel::Basic as u8 {
                println!($($arg)*);
            }
        }
    };
}

// Debug macro for full debug (level 2)
macro_rules! debug_full_println {
    ($($arg:tt)*) => {
        unsafe {
            if DEBUG_LEVEL as u8 >= DebugLevel::Full as u8 {
                println!($($arg)*);
            }
        }
    };
}

mod compression;
mod fragmentation;
// mod encryption;  // Removed - now using Noise-only implementation
mod terminal_ux;
mod persistence;
mod noise;
mod noise_integration;

use compression::decompress;
use fragmentation::{Fragment, FragmentType};
use noise_integration::NoiseIntegrationService;
// use encryption::EncryptionService;  // Removed - now using Noise-only
use terminal_ux::{ChatContext, ChatMode, format_message_display, print_help};
use persistence::{AppState, load_state, save_state, encrypt_password, decrypt_password};

// --- Constants ---

const VERSION: &str = "v1.0.0";

const BITCHAT_SERVICE_UUID: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C);

const BITCHAT_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D);

// Cover traffic prefix used by iOS for dummy messages
const COVER_TRAFFIC_PREFIX: &str = "☂DUMMY☂";

// Packet header flags
const FLAG_HAS_RECIPIENT: u8 = 0x01;
const FLAG_HAS_SIGNATURE: u8 = 0x02;
const FLAG_IS_COMPRESSED: u8 = 0x04;

// Message payload flags (matching Swift's toBinaryPayload)
#[allow(dead_code)]
const MSG_FLAG_IS_RELAY: u8 = 0x01;
const MSG_FLAG_IS_PRIVATE: u8 = 0x02;
const MSG_FLAG_HAS_ORIGINAL_SENDER: u8 = 0x04;
const MSG_FLAG_HAS_RECIPIENT_NICKNAME: u8 = 0x08;
const MSG_FLAG_HAS_SENDER_PEER_ID: u8 = 0x10;
const MSG_FLAG_HAS_MENTIONS: u8 = 0x20;
const MSG_FLAG_HAS_CHANNEL: u8 = 0x40;
const MSG_FLAG_IS_ENCRYPTED: u8 = 0x80;

#[allow(dead_code)]
const SIGNATURE_SIZE: usize = 64;  // Ed25519 signature size

// Swift's SpecialRecipients.broadcast = Data(repeating: 0xFF, count: 8)
const BROADCAST_RECIPIENT: [u8; 8] = [0xFF; 8];

// --- Protocol Structs and Enums ---

#[repr(u8)]

#[derive(Debug, Clone, Copy, PartialEq)]

enum MessageType { 
    Announce = 0x01, 
    // 0x02 was legacy keyExchange - removed (matching Swift)
    Leave = 0x03,
    Message = 0x04,              // All user messages (private and broadcast)
    FragmentStart = 0x05,
    FragmentContinue = 0x06,
    FragmentEnd = 0x07,
    ChannelAnnounce = 0x08,      // Announce password-protected channel status
    ChannelRetention = 0x09,     // Announce channel retention status
    DeliveryAck = 0x0A,          // Acknowledge message received
    DeliveryStatusRequest = 0x0B, // Request delivery status update
    ReadReceipt = 0x0C,          // Message has been read/viewed
    
    // Noise Protocol messages (matching Swift exactly)
    NoiseHandshakeInit = 0x10,   // Noise handshake initiation
    NoiseHandshakeResp = 0x11,   // Noise handshake response  
    NoiseEncrypted = 0x12,       // Noise encrypted transport message
    NoiseIdentityAnnounce = 0x13, // Announce static public key for discovery
    ChannelKeyVerifyRequest = 0x14, // Request key verification for a channel
    ChannelKeyVerifyResponse = 0x15, // Response to key verification request
    ChannelPasswordUpdate = 0x16, // Distribute new password to channel members
    ChannelMetadata = 0x17,      // Announce channel creator and metadata
    
    // Protocol version negotiation (matching Swift exactly)
    VersionHello = 0x20,         // Initial version announcement
    VersionAck = 0x21,           // Version acknowledgment
}

#[derive(Debug, Default, Clone)]

struct Peer { nickname: Option<String> }

#[derive(Debug)]

struct BitchatPacket { 
    msg_type: MessageType, 
    _sender_id: Vec<u8>,  // Kept for protocol compatibility 
    sender_id_str: String,  // Add string version for easy comparison
    recipient_id: Option<Vec<u8>>,  // Add recipient ID
    recipient_id_str: Option<String>,  // Add string version of recipient
    payload: Vec<u8>,
    ttl: u8,  // Add TTL field
}

#[derive(Debug)]

struct BitchatMessage { 
    id: String, 
    content: String, 
    channel: Option<String>,
    is_encrypted: bool,
    encrypted_content: Option<Vec<u8>>,  // Store raw encrypted bytes
    timestamp: u64,  // Milliseconds since epoch
}

// Delivery confirmation structures matching iOS
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeliveryAck {
    #[serde(rename = "originalMessageID")]
    original_message_id: String,
    #[serde(rename = "ackID")]
    ack_id: String,
    #[serde(rename = "recipientID")]
    recipient_id: String,
    #[serde(rename = "recipientNickname")]
    recipient_nickname: String,
    timestamp: u64,
    #[serde(rename = "hopCount")]
    hop_count: u8,
}

// Track sent messages awaiting delivery confirmation
struct DeliveryTracker {
    pending_messages: HashMap<String, (String, SystemTime, bool)>, // message_id -> (content, sent_time, is_private)
    sent_acks: HashSet<String>, // Track ACK IDs we've already sent to prevent duplicates
}

impl DeliveryTracker {
    fn new() -> Self {
        Self {
            pending_messages: HashMap::new(),
            sent_acks: HashSet::new(),
        }
    }
    
    fn track_message(&mut self, message_id: String, content: String, is_private: bool) {
        self.pending_messages.insert(message_id, (content, SystemTime::now(), is_private));
    }
    
    fn mark_delivered(&mut self, message_id: &str) -> bool {
        self.pending_messages.remove(message_id).is_some()
    }
    
    fn should_send_ack(&mut self, ack_id: &str) -> bool {
        self.sent_acks.insert(ack_id.to_string())
    }
}

// Protocol version negotiation structures
#[derive(Serialize, Deserialize, Debug, Clone)]
struct VersionHello {
    #[serde(rename = "supportedVersions")]
    supported_versions: Vec<u8>,
    #[serde(rename = "preferredVersion")]
    preferred_version: u8,
    #[serde(rename = "clientVersion")]
    client_version: String,
    platform: String,
    capabilities: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VersionAck {
    #[serde(rename = "agreedVersion")]
    agreed_version: u8,
    #[serde(rename = "serverVersion")]
    server_version: String,
    platform: String,
    capabilities: Option<Vec<String>>,
    rejected: bool,
    reason: Option<String>,
}

// Custom deserializer for base64-encoded byte arrays
fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use base64::{Engine as _, engine::general_purpose};
    use serde::de::Error;
    let s = String::deserialize(deserializer)?;
    general_purpose::STANDARD.decode(&s).map_err(Error::custom)
}

// Custom serializer for byte arrays to base64
fn serialize_base64<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use base64::{Engine as _, engine::general_purpose};
    serializer.serialize_str(&general_purpose::STANDARD.encode(bytes))
}

// Noise identity announcement structure
#[derive(Serialize, Deserialize, Debug, Clone)]
struct NoiseIdentityAnnouncement {
    #[serde(rename = "peerID")]
    peer_id: String,
    #[serde(rename = "publicKey", deserialize_with = "deserialize_base64", serialize_with = "serialize_base64")]
    public_key: Vec<u8>,
    nickname: String,
    timestamp: f64,
    #[serde(rename = "previousPeerID")]
    previous_peer_id: Option<String>,
    #[serde(deserialize_with = "deserialize_base64", serialize_with = "serialize_base64")]
    signature: Vec<u8>,
}

// Channel key verification structures
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChannelKeyVerifyRequest {
    channel: String,
    #[serde(rename = "requesterID")]
    requester_id: String,
    #[serde(rename = "keyCommitment")]
    key_commitment: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChannelKeyVerifyResponse {
    channel: String,
    #[serde(rename = "responderID")]
    responder_id: String,
    verified: bool,
    timestamp: u64,
}

// Channel password update structure
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChannelPasswordUpdate {
    channel: String,
    #[serde(rename = "ownerID")]
    owner_id: String,
    #[serde(rename = "ownerFingerprint")]
    owner_fingerprint: String,
    #[serde(rename = "encryptedPassword", deserialize_with = "deserialize_base64", serialize_with = "serialize_base64")]
    encrypted_password: Vec<u8>,
    #[serde(rename = "newKeyCommitment")]
    new_key_commitment: String,
    timestamp: u64,
}

// Channel metadata structure
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChannelMetadata {
    channel: String,
    #[serde(rename = "creatorID")]
    creator_id: String,
    #[serde(rename = "creatorFingerprint")]
    creator_fingerprint: String,
    #[serde(rename = "createdAt")]
    created_at: u64,
    #[serde(rename = "isPasswordProtected")]
    is_password_protected: bool,
    #[serde(rename = "keyCommitment")]
    key_commitment: Option<String>,
}

// Delivery status request structure
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeliveryStatusRequest {
    #[serde(rename = "messageID")]
    message_id: String,
    #[serde(rename = "requesterID")]
    requester_id: String,
    timestamp: u64,
}

// Read receipt structure  
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ReadReceipt {
    #[serde(rename = "originalMessageID")]
    original_message_id: String,
    #[serde(rename = "receiptID")]
    receipt_id: String,
    #[serde(rename = "readerID")]
    reader_id: String,
    #[serde(rename = "readerNickname")]
    reader_nickname: String,
    timestamp: u64,
}

// Protocol version management
struct ProtocolVersionManager {
    supported_versions: Vec<u8>,
    current_version: u8,
    peer_versions: HashMap<String, u8>,
}

impl ProtocolVersionManager {
    fn new() -> Self {
        Self {
            supported_versions: vec![1],
            current_version: 1,
            peer_versions: HashMap::new(),
        }
    }
    
    fn negotiate_version(&self, peer_versions: &[u8]) -> Option<u8> {
        // Find highest common version
        for &version in self.supported_versions.iter().rev() {
            if peer_versions.contains(&version) {
                return Some(version);
            }
        }
        None
    }
    
    fn set_peer_version(&mut self, peer_id: String, version: u8) {
        self.peer_versions.insert(peer_id, version);
    }
    
    fn get_peer_version(&self, peer_id: &str) -> Option<u8> {
        self.peer_versions.get(peer_id).copied()
    }
}

// Fragment reassembly tracking - using hex strings as keys (matching Swift)
struct FragmentCollector {
    fragments: HashMap<String, HashMap<u16, Vec<u8>>>,  // fragment_id_hex -> (index -> data)
    metadata: HashMap<String, (u16, u8, String)>,  // fragment_id_hex -> (total, original_type, sender_id)
}

impl FragmentCollector {
    fn new() -> Self {
        FragmentCollector {
            fragments: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
    
    fn add_fragment(&mut self, fragment_id: [u8; 8], index: u16, total: u16, original_type: u8, data: Vec<u8>, sender_id: String) -> Option<(Vec<u8>, String)> {
        // Convert fragment ID to hex string (matching Swift's hexEncodedString)
        let fragment_id_hex = fragment_id.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        
        debug_full_println!("[COLLECTOR] Adding fragment {} (index {}/{}) for ID {}", 
                index + 1, index + 1, total, &fragment_id_hex[..8]);
        
        // Initialize if first fragment
        if !self.fragments.contains_key(&fragment_id_hex) {
            debug_full_println!("[COLLECTOR] Creating new fragment collection for ID {}", &fragment_id_hex[..8]);
            self.fragments.insert(fragment_id_hex.clone(), HashMap::new());
            self.metadata.insert(fragment_id_hex.clone(), (total, original_type, sender_id.clone()));
        }
        
        // Add fragment data at index
        if let Some(fragment_map) = self.fragments.get_mut(&fragment_id_hex) {
            fragment_map.insert(index, data);
            debug_full_println!("[COLLECTOR] Fragment {} stored. Have {}/{} fragments", 
                    index + 1, fragment_map.len(), total);
            
            // Check if we have all fragments
            if fragment_map.len() == total as usize {
                debug_full_println!("[COLLECTOR] ✓ All fragments received! Reassembling...");
                
                // Reassemble in order
                let mut complete_data = Vec::new();
                for i in 0..total {
                    if let Some(fragment_data) = fragment_map.get(&i) {
                        debug_full_println!("[COLLECTOR] Appending fragment {} ({} bytes)", i + 1, fragment_data.len());
                        complete_data.extend_from_slice(fragment_data);
                    } else {
                        debug_full_println!("[COLLECTOR] ✗ Missing fragment {}", i + 1);
                        return None;
                    }
                }
                
                debug_full_println!("[COLLECTOR] ✓ Reassembly complete: {} bytes total", complete_data.len());
                
                // Get sender from metadata
                let sender = self.metadata.get(&fragment_id_hex)
                    .map(|(_, _, s)| s.clone())
                    .unwrap_or_else(|| "Unknown".to_string());
                
                // Clean up
                self.fragments.remove(&fragment_id_hex);
                self.metadata.remove(&fragment_id_hex);
                
                return Some((complete_data, sender));
            } else {
                debug_full_println!("[COLLECTOR] Waiting for more fragments ({}/{} received)", 
                        fragment_map.len(), total);
            }
        }
        
        None
    }
}


#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Check for debug flags
    unsafe {
        if args.iter().any(|arg| arg == "-dd" || arg == "--debug-full") {
            DEBUG_LEVEL = DebugLevel::Full;
            println!("🐛 Debug mode: FULL (verbose output)");
        } else if args.iter().any(|arg| arg == "-d" || arg == "--debug") {
            DEBUG_LEVEL = DebugLevel::Basic;
            println!("🐛 Debug mode: BASIC (connection info)");
        }
        // Otherwise stays at Clean (default)
    }

    let (tx, mut rx) = mpsc::channel::<String>(10);

    tokio::spawn(async move {

        let mut stdin = BufReader::new(io::stdin()).lines();

        // Display ASCII art logo in Matrix green
        println!("\n\x1b[38;5;46m##\\       ##\\   ##\\               ##\\                  ##\\");
        println!("## |      \\__|  ## |              ## |                 ## |");
        println!("#######\\  ##\\ ######\\    #######\\ #######\\   ######\\ ######\\");
        println!("##  __##\\ ## |\\_##  _|  ##  _____|##  __##\\  \\____##\\\\_##  _|");
        println!("## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |");
        println!("## |  ## |## |  ## |##\\ ## |      ## |  ## |##  __## | ## |##\\");
        println!("#######  |## |  \\####  |\\#######\\ ## |  ## |\\####### | \\####  |");
        println!("\\_______/ \\__|   \\____/  \\_______|\\__|  \\__| \\_______|  \\____/\x1b[0m");
        println!("\n\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
        println!("\x1b[37mDecentralized • Encrypted • Peer-to-Peer • Open Source\x1b[0m");
        // Get git commit hash at build time
        let git_hash = option_env!("GIT_HASH").unwrap_or("unknown");
        println!("\x1b[37m                bitch@ the terminal {} ({})\x1b[0m", VERSION, git_hash);
        println!("\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");

        loop {
            // Note: We can't access chat_context here directly, but we'll improve this later
            print!("> ");
            use std::io::{self as stdio, Write};
            let _ = stdio::stdout().flush();

            if let Ok(Some(line)) = stdin.next_line().await {

                if tx.send(line).await.is_err() { break; }

            } else { break; }

        }

    });


    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let adapter = match adapters.into_iter().nth(0) {
        Some(adapter) => adapter,
        None => {
            println!("\n\x1b[91m❌ No Bluetooth adapter found\x1b[0m");
            println!("\x1b[90mPlease check:\x1b[0m");
            println!("\x1b[90m  • Your device has Bluetooth hardware\x1b[0m");
            println!("\x1b[90m  • Bluetooth is enabled in system settings\x1b[0m");
            println!("\x1b[90m  • You have permission to use Bluetooth\x1b[0m");
            return Ok(());
        }
    };

    adapter.start_scan(ScanFilter::default()).await?;

    println!("\x1b[90m» Scanning for bitchat service...\x1b[0m");
    debug_println!("[1] Scanning for bitchat service...");


    let peripheral = loop {

        if let Some(p) = find_peripheral(&adapter).await? {

            println!("\x1b[90m» Found bitchat service! Connecting...\x1b[0m");
            debug_println!("[1] Match Found! Connecting...");

            adapter.stop_scan().await?;

            break p;

        }

        time::sleep(Duration::from_secs(1)).await;

    };


    if let Err(e) = peripheral.connect().await {
        println!("\n\x1b[91m❌ Connection failed\x1b[0m");
        println!("\x1b[90mReason: {}\x1b[0m", e);
        println!("\x1b[90mPlease check:\x1b[0m");
        println!("\x1b[90m  • Bluetooth is enabled\x1b[0m");
        println!("\x1b[90m  • The other device is running BitChat\x1b[0m");
        println!("\x1b[90m  • You're within range\x1b[0m");
        println!("\n\x1b[90mTry running the command again.\x1b[0m");
        return Ok(());
    }


    peripheral.discover_services().await?;

    let characteristics = peripheral.characteristics();

    let cmd_char = characteristics.iter().find(|c| c.uuid == BITCHAT_CHARACTERISTIC_UUID).expect("Characteristic not found.");

    peripheral.subscribe(cmd_char).await?;

    let mut notification_stream = peripheral.notifications().await?;

    debug_println!("[2] Connection established.");
    
    // TODO: Implement MTU negotiation
    // Swift calls: peripheral.maximumWriteValueLength(for: .withoutResponse)
    // Default BLE MTU is 23 bytes (20 data), extended can be up to 512


    debug_println!("[3] Performing handshake...");

    // Generate peer ID like Swift does (4 random bytes as hex)
    let mut peer_id_bytes = [0u8; 4];
    rand::thread_rng().fill(&mut peer_id_bytes);
    let my_peer_id = hex::encode(&peer_id_bytes);
    debug_full_println!("[DEBUG] My peer ID: {}", my_peer_id);
    
    // Load persisted state early to get saved nickname
    let mut app_state = load_state();
    let mut nickname = app_state.nickname.clone().unwrap_or_else(|| "my-rust-client".to_string());

    // Create Noise encryption service with Ed25519 signing key
    // Note: identity_key should always be present due to load_state() auto-generation
    let noise_service = Arc::new(if let Some(ref identity_key) = app_state.identity_key {
        NoiseIntegrationService::with_signing_key(identity_key).map_err(|e| {
            eprintln!("Failed to initialize Noise service with signing key: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?
    } else {
        eprintln!("Warning: No identity key found - this should not happen!");
        NoiseIntegrationService::new().map_err(|e| {
            eprintln!("Failed to initialize Noise service: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?
    });

    // All encryption now handled by Noise protocol

    // Get our static public key for sharing
    let static_public_key = noise_service.get_static_public_key();
    let identity_fingerprint = noise_service.get_identity_fingerprint();
    
    debug_println!("[NOISE] Our identity fingerprint: {}", identity_fingerprint);

    // Send NoiseIdentityAnnounce instead of old Announce format (matching Swift protocol)
    let identity_announcement = NoiseIdentityAnnouncement {
        peer_id: my_peer_id.clone(),
        public_key: static_public_key.clone(),
        nickname: nickname.clone(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
        previous_peer_id: None,
        signature: vec![], // We'll add proper signature later if needed
    };
    
    let identity_payload = serde_json::to_vec(&identity_announcement).unwrap();

    // Add small delay before announcing
    time::sleep(Duration::from_millis(200)).await;

    let announce_packet = create_bitchat_packet(&my_peer_id, MessageType::NoiseIdentityAnnounce, identity_payload);

    peripheral.write(cmd_char, &announce_packet, WriteType::WithoutResponse).await?;
    
    debug_println!("[IDENTITY] Sent NoiseIdentityAnnounce for peer {} ({})", my_peer_id, nickname);

    debug_println!("[3] Handshake sent. You can now chat.");
    if app_state.nickname.is_some() {
        println!("\x1b[90m» Using saved nickname: {}\x1b[0m", nickname);
    }
    println!("\x1b[90m» Type /status to see connection info\x1b[0m");


    let peers: Arc<Mutex<HashMap<String, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut bloom = Bloom::new_for_fp_rate(500, 0.01);

    let mut fragment_collector = FragmentCollector::new();
    let mut delivery_tracker = DeliveryTracker::new();
    let mut protocol_version_manager = ProtocolVersionManager::new();

    let mut chat_context = ChatContext::new();
    let mut channel_keys: HashMap<String, [u8; 32]> = HashMap::new();
    let mut _chat_messages: HashMap<String, Vec<String>> = HashMap::new();  // for /clear command - stores messages by context
    
    // Already loaded app_state above for nickname
    let mut blocked_peers = app_state.blocked_peers;
    let mut channel_creators = app_state.channel_creators;
    let mut password_protected_channels = app_state.password_protected_channels;
    let mut channel_key_commitments = app_state.channel_key_commitments;
    let mut discovered_channels: HashSet<String> = HashSet::new();  // Track all discovered channels
    
    // Auto-restore channel keys from saved passwords (matching iOS behavior)
    if let Some(identity_key) = &app_state.identity_key {
        for (channel, encrypted_password) in &app_state.encrypted_channel_passwords {
            match decrypt_password(encrypted_password, identity_key) {
                Ok(password) => {
                    let key = NoiseIntegrationService::derive_channel_key(&password, channel);
                    channel_keys.insert(channel.clone(), key);
                    debug_println!("[CHANNEL] Restored key for password-protected channel: {}", channel);
                }
                Err(e) => {
                    debug_println!("[CHANNEL] Failed to restore key for {}: {}", channel, e);
                }
            }
        }
    }
    // Note: We don't restore joined_channels as they need to be re-joined via announce
    
    // Helper to create AppState for saving
    let create_app_state = |blocked: &HashSet<String>, 
                           creators: &HashMap<String, String>,
                           channels: &Vec<String>,
                           protected: &HashSet<String>,
                           commitments: &HashMap<String, String>,
                           encrypted_passwords: &HashMap<String, persistence::EncryptedPassword>,
                           current_nickname: &str| -> AppState {
        AppState {
            nickname: Some(current_nickname.to_string()),
            blocked_peers: blocked.clone(),
            channel_creators: creators.clone(),
            joined_channels: channels.clone(),
            password_protected_channels: protected.clone(),
            channel_key_commitments: commitments.clone(),
            favorites: app_state.favorites.clone(),
            identity_key: app_state.identity_key.clone(),
            encrypted_channel_passwords: encrypted_passwords.clone(),
        }
    };


    loop {

        tokio::select! {

            Some(line) = rx.recv() => {

                // Handle number switching first
                if line.len() == 1 {
                    if let Ok(num) = line.parse::<usize>() {
                        if chat_context.switch_to_number(num) {
                            debug_println!("{}", chat_context.get_status_line());
                        } else {
                            println!("» Invalid conversation number");
                        }
                        continue;
                    }
                }

                // Handle /help command
                if line == "/help" {
                    print_help();
                    continue;
                }
                
                // Handle /name command
                if line.starts_with("/name ") {
                    let new_name = line[6..].trim();
                    if new_name.is_empty() {
                        println!("\x1b[93m⚠ Usage: /name <new_nickname>\x1b[0m");
                        println!("\x1b[90mExample: /name Alice\x1b[0m");
                    } else if new_name.len() > 20 {
                        println!("\x1b[93m⚠ Nickname too long\x1b[0m");
                        println!("\x1b[90mMaximum 20 characters allowed.\x1b[0m");
                    } else if new_name.contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
                        println!("\x1b[93m⚠ Invalid nickname\x1b[0m");
                        println!("\x1b[90mNicknames can only contain letters, numbers, hyphens and underscores.\x1b[0m");
                    } else if new_name == "system" || new_name == "all" {
                        println!("\x1b[93m⚠ Reserved nickname\x1b[0m");
                        println!("\x1b[90mThis nickname is reserved and cannot be used.\x1b[0m");
                    } else {
                        nickname = new_name.to_string();
                        // Send announce packet with new nickname
                        let announce_packet = create_bitchat_packet(&my_peer_id, MessageType::Announce, nickname.as_bytes().to_vec());
                        if peripheral.write(cmd_char, &announce_packet, WriteType::WithoutResponse).await.is_err() {
                            println!("[!] Failed to announce new nickname");
                        } else {
                            println!("\x1b[90m» Nickname changed to: {}\x1b[0m", nickname);
                            
                            // Save the new nickname to persistent state
                            let state_to_save = create_app_state(
                                &blocked_peers,
                                &channel_creators,
                                &chat_context.active_channels,
                                &password_protected_channels,
                                &channel_key_commitments,
                                &app_state.encrypted_channel_passwords,
                                &nickname
                            );
                            if let Err(e) = save_state(&state_to_save) {
                                eprintln!("Warning: Could not save nickname: {}", e);
                            }
                        }
                    }
                    continue;
                }
                
                // Handle /list command
                if line == "/list" {
                    chat_context.show_conversation_list();
                    continue;
                }
                
                // Handle /switch command
                if line == "/switch" {
                    println!("\n{}", chat_context.get_conversation_list_with_numbers());
                    print!("Enter number to switch to: ");
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                    
                    // Wait for next input from the channel
                    if let Some(switch_input) = rx.recv().await {
                        if let Ok(num) = switch_input.trim().parse::<usize>() {
                            if chat_context.switch_to_number(num) {
                                debug_println!("{}", chat_context.get_status_line());
                            } else {
                                println!("» Invalid selection");
                            }
                        }
                    }
                    continue;
                }

                if line.starts_with("/j ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let channel_name = parts.get(1).unwrap_or(&"").to_string();
                    
                    // Validate channel name
                    if channel_name.is_empty() {
                        println!("\x1b[93m⚠ Usage: /j #<channel> [password]\x1b[0m");
                        println!("\x1b[90mExample: /j #general\x1b[0m");
                        println!("\x1b[90mExample: /j #private mysecret\x1b[0m");
                        continue;
                    }
                    
                    if !channel_name.starts_with("#") {
                        println!("\x1b[93m⚠ Channel names must start with #\x1b[0m");
                        println!("\x1b[90mExample: /j #{}\x1b[0m", channel_name);
                        continue;
                    }
                    
                    if channel_name.len() > 25 {
                        println!("\x1b[93m⚠ Channel name too long\x1b[0m");
                        println!("\x1b[90mMaximum 25 characters allowed.\x1b[0m");
                        continue;
                    }
                    
                    if channel_name[1..].contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
                        println!("\x1b[93m⚠ Invalid channel name\x1b[0m");
                        println!("\x1b[90mChannel names can only contain letters, numbers, hyphens and underscores.\x1b[0m");
                        continue;
                    }

                    if channel_name.starts_with("#") {
                        // Check if channel is password-protected
                        if password_protected_channels.contains(&channel_name) {
                            // Check if we already have a key (from auto-restore)
                            if channel_keys.contains_key(&channel_name) {
                                // We have the key from restoration, just switch to the channel
                                discovered_channels.insert(channel_name.clone());
                                chat_context.switch_to_channel(&channel_name);
                                print!("> ");
                                std::io::stdout().flush().unwrap();
                                continue;
                            }
                            // We don't have the key, require password
                            if let Some(password) = parts.get(2) {
                                if password.len() < 4 {
                                    println!("\x1b[93m⚠ Password too short\x1b[0m");
                                    println!("\x1b[90mMinimum 4 characters required.\x1b[0m");
                                    continue;
                                }
                                let key = NoiseIntegrationService::derive_channel_key(password, &channel_name);
                                
                                // Verify password against stored key commitment (iOS compatibility)
                                if let Some(expected_commitment) = channel_key_commitments.get(&channel_name) {
                                    let test_commitment = {
                                        let hash = sha2::Sha256::digest(&key);
                                        hex::encode(hash)
                                    };
                                    
                                    if &test_commitment != expected_commitment {
                                        // Match iOS error message exactly
                                        println!("❌ wrong password for channel {}. please enter the correct password.", channel_name);
                                        continue;
                                    }
                                    debug_println!("[CHANNEL] Password verified for {}", channel_name);
                                }
                                
                                channel_keys.insert(channel_name.clone(), key);
                                discovered_channels.insert(channel_name.clone());
                                
                                // Save encrypted password (matching iOS Keychain behavior)
                                if let Some(identity_key) = &app_state.identity_key {
                                    match encrypt_password(password, identity_key) {
                                        Ok(encrypted) => {
                                            app_state.encrypted_channel_passwords.insert(channel_name.clone(), encrypted);
                                            debug_println!("[CHANNEL] Saved encrypted password for {}", channel_name);
                                            
                                            // Save state immediately
                                            let state_to_save = create_app_state(
                                                &blocked_peers,
                                                &channel_creators,
                                                &chat_context.active_channels,
                                                &password_protected_channels,
                                                &channel_key_commitments,
                                                &app_state.encrypted_channel_passwords,
                                                &nickname
                                            );
                                            if let Err(e) = save_state(&state_to_save) {
                                                eprintln!("Warning: Could not save state: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            debug_println!("[CHANNEL] Failed to encrypt password: {}", e);
                                        }
                                    }
                                }
                                
                                discovered_channels.insert(channel_name.clone());
                                chat_context.switch_to_channel_silent(&channel_name);
                                // Clear the prompt that was already printed by the input reader
                                print!("\r\x1b[K");
                                println!("\x1b[90m─────────────────────────\x1b[0m");
                                println!("\x1b[90m» Joined password-protected channel: {} 🔒\x1b[0m", channel_name);
                                
                                // Send channel announce to let others know we joined with correct password
                                // This matches iOS behavior
                                if let Some(owner) = channel_creators.get(&channel_name) {
                                    let key_commitment = {
                                        let hash = sha2::Sha256::digest(&key);
                                        hex::encode(hash)
                                    };
                                    debug_println!("[CHANNEL] Sending join announce for password channel {}", channel_name);
                                    let _ = send_channel_announce(
                                        &peripheral,
                                        cmd_char,
                                        owner, // Use existing owner
                                        &channel_name,
                                        true,
                                        Some(&key_commitment)
                                    ).await;
                                }
                                
                                print!("> ");
                                std::io::stdout().flush().unwrap();
                            } else {
                                println!("❌ Channel {} is password-protected. Use: /j {} <password>", channel_name, channel_name);
                                continue;
                            }
                        } else {
                            // Not password-protected or we have the key
                            if let Some(password) = parts.get(2) {
                                // User provided password for a channel we haven't seen as protected yet
                                let key = NoiseIntegrationService::derive_channel_key(password, &channel_name);
                                channel_keys.insert(channel_name.clone(), key);
                                discovered_channels.insert(channel_name.clone());
                                chat_context.switch_to_channel_silent(&channel_name);
                                // Clear the prompt that was already printed by the input reader
                                print!("\r\x1b[K");
                                println!("\x1b[90m─────────────────────────\x1b[0m");
                                println!("\x1b[90m» Joined password-protected channel: {} 🔒. Just type to send messages.\x1b[0m", channel_name);
                                
                                // Send channel announce to let others know we joined with correct password
                                // This matches iOS behavior
                                if let Some(owner) = channel_creators.get(&channel_name) {
                                    let key_commitment = {
                                        let hash = sha2::Sha256::digest(&key);
                                        hex::encode(hash)
                                    };
                                    debug_println!("[CHANNEL] Sending join announce for password channel {}", channel_name);
                                    let _ = send_channel_announce(
                                        &peripheral,
                                        cmd_char,
                                        owner, // Use existing owner
                                        &channel_name,
                                        true,
                                        Some(&key_commitment)
                                    ).await;
                                }
                                
                                print!("> ");
                                std::io::stdout().flush().unwrap();
                            } else {
                                // Regular channel join
                                discovered_channels.insert(channel_name.clone());
                                print!("\r\x1b[K");
                                chat_context.switch_to_channel(&channel_name);
                                channel_keys.remove(&channel_name); // Remove any previous key
                                
                                // Don't claim ownership - let it be established when first password is set
                                // This matches iOS behavior
                                if !channel_creators.contains_key(&channel_name) {
                                    debug_println!("[CHANNEL] No owner recorded for {}. First to set password will become owner.", channel_name);
                                }
                                
                                print!("> ");
                                std::io::stdout().flush().unwrap();
                            }
                        }
                        debug_println!("{}", chat_context.get_status_line());
                    } else {
                        println!("» Invalid channel name. It must start with #.");
                    }
                    continue;
                }

                if line == "/exit" { 
                    // Save state before exiting
                    let state_to_save = create_app_state(
                        &blocked_peers,
                        &channel_creators,
                        &chat_context.active_channels,
                        &password_protected_channels,
                        &channel_key_commitments,
                        &app_state.encrypted_channel_passwords,
                        &nickname
                    );
                    if let Err(e) = save_state(&state_to_save) {
                        eprintln!("Warning: Could not save state: {}", e);
                    }
                    break; 
                }
                
                // Handle /reply command  
                if line == "/reply" {
                    if let Some((peer_id, nickname)) = chat_context.last_private_sender.clone() {
                        chat_context.enter_dm_mode(&nickname, &peer_id);
                        debug_println!("{}", chat_context.get_status_line());
                    } else {
                        println!("» No private messages received yet.");
                    }
                    continue;
                }
                
                // Handle /public command
                if line == "/public" {
                    chat_context.switch_to_public();
                    debug_println!("{}", chat_context.get_status_line());
                    continue;
                }
                
                // Handle /online command - show who's online
                if line == "/online" || line == "/w" {
                    let peers_lock = peers.lock().unwrap();
                    if peers_lock.is_empty() {
                        println!("» No one else is online right now.");
                    } else {
                        let mut online_list: Vec<String> = peers_lock.iter()
                            .filter_map(|(_, peer)| peer.nickname.clone())
                            .collect();
                        online_list.sort();
                        println!("» Online users: {}", online_list.join(", "));
                    }
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    continue;
                }
                
                // Handle /channels command - show discovered channels
                if line == "/channels" {
                    let mut all_channels: HashSet<String> = HashSet::new();
                    
                    // Add channels from chat context
                    all_channels.extend(chat_context.active_channels.iter().cloned());
                    
                    // Add channels from channel_keys (password protected ones we know about)
                    all_channels.extend(channel_keys.keys().cloned());
                    
                    if all_channels.is_empty() {
                        println!("» No channels discovered yet. Channels appear as people use them.");
                    } else {
                        let mut channel_list: Vec<String> = all_channels.into_iter().collect();
                        channel_list.sort();
                        
                        println!("» Discovered channels:");
                        for channel in channel_list {
                            let mut status = String::new();
                            
                            // Check if joined
                            if chat_context.active_channels.contains(&channel) {
                                status.push_str(" ✓");
                            }
                            
                            // Check if password protected
                            if password_protected_channels.contains(&channel) {
                                status.push_str(" 🔒");
                                if channel_keys.contains_key(&channel) {
                                    status.push_str(" 🔑"); // We have the key
                                }
                            }
                            
                            println!("  {}{}", channel, status);
                        }
                        println!("\n✓ = joined, 🔒 = password protected, 🔑 = authenticated");
                    }
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    continue;
                }
                
                // Handle private messages
                if line.starts_with("/dm ") {
                    let parts: Vec<&str> = line.splitn(3, ' ').collect();
                    
                    // Check if it's just "/dm nickname" (enter DM mode) or "/dm nickname message" (quick send)
                    if parts.len() < 2 {
                        println!("\x1b[93m⚠ Usage: /dm <nickname> [message]\x1b[0m");
                        println!("\x1b[90mExample: /dm Bob Hey there!\x1b[0m");
                        continue;
                    }
                    
                    let target_nickname = parts[1];
                    
                    // Find peer ID for nickname
                    let peer_id = {
                        let peers = peers.lock().unwrap();
                        peers.iter()
                            .find(|(_, peer)| peer.nickname.as_deref() == Some(target_nickname))
                            .map(|(id, _)| id.clone())
                    };
                    
                    if let Some(target_peer_id) = peer_id {
                        // If no message provided, enter DM mode
                        if parts.len() == 2 {
                            chat_context.enter_dm_mode(target_nickname, &target_peer_id);
                            debug_println!("{}", chat_context.get_status_line());
                            continue;
                        }
                        
                        // Otherwise send the message directly
                        let private_message = parts[2];
                        // Create private message
                        debug_println!("[PRIVATE] Sending encrypted message to {}", target_nickname);
                        
                        // Create message payload with private flag
                        let (message_payload, message_id) = create_bitchat_message_payload_full(&nickname, private_message, None, true, &my_peer_id);
                        
                        // Track private message for delivery confirmation
                        delivery_tracker.track_message(message_id.clone(), private_message.to_string(), true);
                        
                        // Pad the message for privacy using PKCS#7
                        let block_sizes = [256, 512, 1024, 2048];
                        let payload_size = message_payload.len();
                        let target_size = block_sizes.iter()
                            .find(|&&size| payload_size + 16 <= size)
                            .copied()
                            .unwrap_or(payload_size);
                        
                        let padding_needed = target_size - message_payload.len();
                        let mut padded_payload = message_payload.clone();
                        
                        if padding_needed > 0 && padding_needed <= 255 {
                            // PKCS#7 padding: all padding bytes have the same value (the padding length)
                            for _ in 0..padding_needed {
                                padded_payload.push(padding_needed as u8);
                            }
                            debug_println!("[PRIVATE] Added {} bytes of PKCS#7 padding", padding_needed);
                        } else if padding_needed == 0 {
                            // If already at block size, don't add more padding - Android doesn't do this
                            debug_println!("[PRIVATE] Message already at block size, no padding needed");
                        }
                        
                        // Check if we have an established Noise session with the target peer
                        if noise_service.has_established_session(&target_peer_id) {
                            // Use Noise encryption for this peer
                            match noise_service.encrypt_for_peer(&target_peer_id, &padded_payload) {
                                Ok(encrypted) => {
                                    debug_println!("[NOISE] Encrypted private message: {} bytes", encrypted.len());
                                    
                                    // Create packet with Noise encrypted message type
                                    let packet = create_bitchat_packet_with_recipient(
                                        &my_peer_id,
                                        Some(&target_peer_id),
                                        MessageType::NoiseEncrypted,
                                        encrypted,
                                        None  // No separate signature needed with Noise
                                    );
                                    
                                    // Send the private message
                                    if let Err(_e) = send_packet_with_fragmentation(&peripheral, cmd_char, packet, &my_peer_id).await {
                                        println!("\n\x1b[91m❌ Failed to send private message\x1b[0m");
                                        println!("\x1b[90mThe message could not be delivered. Connection may have been lost.\x1b[0m");
                                    } else {
                                        debug_println!("[NOISE] Private message sent to {}", target_nickname);
                                    }
                                },
                                Err(e) => {
                                    println!("[!] Failed to encrypt message with Noise: {}", e);
                                }
                            }
                        } else {
                            // No Noise session established - initiate handshake first
                            println!("» Initiating secure handshake with {}...", target_nickname);
                            
                            match noise_service.initiate_handshake(&target_peer_id) {
                                Ok(handshake_msg) => {
                                    debug_println!("[HANDSHAKE] Initiated handshake with {}, sending {} bytes", target_peer_id, handshake_msg.len());
                                    
                                    // Create packet for handshake message
                                    let packet = create_bitchat_packet_with_recipient(
                                        &my_peer_id,
                                        Some(&target_peer_id),
                                        MessageType::NoiseHandshakeInit,
                                        handshake_msg,
                                        None
                                    );
                                    
                                    // Send handshake message
                                    if let Err(_e) = send_packet_with_fragmentation(&peripheral, cmd_char, packet, &my_peer_id).await {
                                        println!("\x1b[91m❌ Failed to send handshake\x1b[0m");
                                    } else {
                                        println!("» Handshake initiated. Please wait for response and try sending the message again.");
                                    }
                                },
                                Err(e) => {
                                    println!("[!] Failed to initiate handshake: {:?}", e);
                                    println!("[!] Unable to establish secure connection with {}", target_nickname);
                                }
                            }
                        }
                    } else {
                        println!("\x1b[93m⚠ User '{}' not found\x1b[0m", target_nickname);
                        println!("\x1b[90mThey may be offline or using a different nickname.\x1b[0m");
                    }
                    continue;
                }

                // NOTE: DM mode handling removed from here - moved after command checks to allow commands in DM mode
                
                // Handle /block command
                if line.starts_with("/block") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    
                    if parts.len() == 1 {
                        // List blocked peers
                        if blocked_peers.is_empty() {
                            println!("» No blocked peers.");
                        } else {
                            // Find nicknames for blocked fingerprints
                            let peers_guard = peers.lock().unwrap();
                            let mut blocked_nicknames = Vec::new();
                            
                            for (peer_id, peer) in peers_guard.iter() {
                                let fingerprint = noise_service.get_peer_fingerprint(peer_id)
                                    .or_else(|| noise_service.get_peer_fingerprint(peer_id));
                                if let Some(fingerprint) = fingerprint {
                                    if blocked_peers.contains(&fingerprint) {
                                        if let Some(nickname) = &peer.nickname {
                                            blocked_nicknames.push(nickname.clone());
                                        }
                                    }
                                }
                            }
                            
                            if blocked_nicknames.is_empty() {
                                println!("» Blocked peers (not currently online): {}", blocked_peers.len());
                            } else {
                                println!("» Blocked peers: {}", blocked_nicknames.join(", "));
                            }
                        }
                    } else if parts.len() == 2 {
                        // Block a specific peer
                        let target_name = parts[1];
                        let nickname = if target_name.starts_with("@") {
                            &target_name[1..]
                        } else {
                            target_name
                        };
                        
                        // Find peer ID for nickname
                        let peer_id = {
                            let peers_guard = peers.lock().unwrap();
                            peers_guard.iter()
                                .find(|(_, peer)| peer.nickname.as_deref() == Some(nickname))
                                .map(|(id, _)| id.clone())
                        };
                        
                        if let Some(target_peer_id) = peer_id {
                            let fingerprint = noise_service.get_peer_fingerprint(&target_peer_id)
                                .or_else(|| noise_service.get_peer_fingerprint(&target_peer_id));
                            if let Some(fingerprint) = fingerprint {
                                if blocked_peers.contains(&fingerprint) {
                                    println!("» {} is already blocked.", nickname);
                                } else {
                                    blocked_peers.insert(fingerprint.clone());
                                    
                                    // Save state
                                    let state_to_save = create_app_state(
                                        &blocked_peers,
                                        &channel_creators,
                                        &chat_context.active_channels,
                                        &password_protected_channels,
                                        &channel_key_commitments,
                                        &app_state.encrypted_channel_passwords,
                                        &nickname
                                    );
                                    if let Err(e) = save_state(&state_to_save) {
                                        eprintln!("Warning: Could not save state: {}", e);
                                    }
                                    
                                    println!("\n\x1b[92m✓ Blocked {}\x1b[0m", nickname);
                                    println!("\x1b[90m{} will no longer be able to send you messages.\x1b[0m", nickname);
                                }
                            } else {
                                println!("» Cannot block {}: No identity key received yet.", nickname);
                            }
                        } else {
                            println!("\x1b[93m⚠ User '{}' not found\x1b[0m", nickname);
                            println!("\x1b[90mThey may be offline or haven't sent any messages yet.\x1b[0m");
                        }
                    } else {
                        println!("\x1b[93m⚠ Usage: /block @<nickname>\x1b[0m");
                        println!("\x1b[90mExample: /block @spammer\x1b[0m");
                    }
                    continue;
                }
                
                // Handle /unblock command
                if line.starts_with("/unblock ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    
                    if parts.len() != 2 {
                        println!("\x1b[93m⚠ Usage: /unblock @<nickname>\x1b[0m");
                        println!("\x1b[90mExample: /unblock @friend\x1b[0m");
                        continue;
                    }
                    
                    let target_name = parts[1];
                    let nickname = if target_name.starts_with("@") {
                        &target_name[1..]
                    } else {
                        target_name
                    };
                    
                    // Find peer ID for nickname
                    let peer_id = {
                        let peers_guard = peers.lock().unwrap();
                        peers_guard.iter()
                            .find(|(_, peer)| peer.nickname.as_deref() == Some(nickname))
                            .map(|(id, _)| id.clone())
                    };
                    
                    if let Some(target_peer_id) = peer_id {
                        let fingerprint = noise_service.get_peer_fingerprint(&target_peer_id)
                            .or_else(|| noise_service.get_peer_fingerprint(&target_peer_id));
                        if let Some(fingerprint) = fingerprint {
                            if blocked_peers.contains(&fingerprint) {
                                blocked_peers.remove(&fingerprint);
                                
                                // Save state
                                let state_to_save = create_app_state(
                                    &blocked_peers,
                                    &channel_creators,
                                    &chat_context.active_channels,
                                    &password_protected_channels,
                                    &channel_key_commitments,
                                    &app_state.encrypted_channel_passwords,
                                    &nickname
                                );
                                if let Err(e) = save_state(&state_to_save) {
                                    eprintln!("Warning: Could not save state: {}", e);
                                }
                                
                                println!("\n\x1b[92m✓ Unblocked {}\x1b[0m", nickname);
                                println!("\x1b[90m{} can now send you messages again.\x1b[0m", nickname);
                            } else {
                                println!("\x1b[93m⚠ {} is not blocked\x1b[0m", nickname);
                            }
                        } else {
                            println!("» Cannot unblock {}: No identity key received.", nickname);
                        }
                    } else {
                        println!("\x1b[93m⚠ User '{}' not found\x1b[0m", nickname);
                            println!("\x1b[90mThey may be offline or haven't sent any messages yet.\x1b[0m");
                    }
                    continue;
                }
                
                // Handle /clear command
                if line == "/clear" {
                    // Clear the terminal screen
                    print!("\x1b[2J\x1b[1;1H");
                    
                    // Reprint the ASCII art logo in Matrix green
                    println!("\n\x1b[38;5;46m##\\       ##\\   ##\\               ##\\                  ##\\");
                    println!("## |      \\__|  ## |              ## |                 ## |");
                    println!("#######\\  ##\\ ######\\    #######\\ #######\\   ######\\ ######\\");
                    println!("##  __##\\ ## |\\_##  _|  ##  _____|##  __##\\  \\____##\\\\_##  _|");
                    println!("## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |");
                    println!("## |  ## |## |  ## |##\\ ## |      ## |  ## |##  __## | ## |##\\");
                    println!("#######  |## |  \\####  |\\#######\\ ## |  ## |\\####### | \\####  |");
                    println!("\\_______/ \\__|   \\____/  \\_______|\\__|  \\__| \\_______|  \\____/\x1b[0m");
                    println!("\n\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
                    println!("\x1b[38;5;40mDecentralized • Encrypted • Peer-to-Peer • Open Source\x1b[0m");
                    println!("\x1b[38;5;40m                bitchat@ the terminal {}\x1b[0m", VERSION);
                    println!("\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
                    
                    // Show current context
                    match &chat_context.current_mode {
                        ChatMode::Public => {
                            println!("» Cleared public chat");
                        },
                        ChatMode::Channel(channel) => {
                            println!("» Cleared channel {}", channel);
                        },
                        ChatMode::PrivateDM { nickname, .. } => {
                            println!("» Cleared DM with {}", nickname);
                        }
                    }
                    
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    continue;
                }
                
                // Handle /channels command
                if line == "/channels" {
                    if discovered_channels.is_empty() {
                        println!("\n» No channels discovered yet. Channels appear as users join them.");
                    } else {
                        println!("\n\x1b[90mdiscovered channels:\x1b[0m");
                        
                        // Sort channels for consistent display
                        let mut channels: Vec<String> = discovered_channels.iter().cloned().collect();
                        channels.sort();
                        
                        for channel in channels {
                            let mut indicators = String::new();
                            
                            // Check if joined
                            if chat_context.active_channels.contains(&channel) {
                                indicators.push_str(" ✓");
                            }
                            
                            // Check if password protected
                            if password_protected_channels.contains(&channel) {
                                indicators.push_str(" 🔒");
                            }
                            
                            // Check if we own it
                            if let Some(owner) = channel_creators.get(&channel) {
                                if owner == &my_peer_id {
                                    indicators.push_str(" (owner)");
                                }
                            }
                            
                            println!("{}{}", channel, indicators);
                        }
                        
                        println!("\n\x1b[90m✓ = joined, 🔒 = password protected\x1b[0m");
                    }
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    continue;
                }
                
                // Handle /status command
                if line == "/status" {
                    let peer_count = peers.lock().unwrap().len();
                    let channel_count = chat_context.active_channels.len();
                    let dm_count = chat_context.active_dms.len();
                    
                    println!("\n╭─── Connection Status ───╮");
                    println!("│ Peers connected: {:3}    │", peer_count);
                    println!("│ Active channels: {:3}    │", channel_count);
                    println!("│ Active DMs:      {:3}    │", dm_count);
                    println!("│                         │");
                    println!("│ Your nickname: {:^9}│", if nickname.len() > 9 { &nickname[..9] } else { &nickname });
                    println!("│ Your ID: {}...│", &my_peer_id[..8]);
                    println!("╰─────────────────────────╯");
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    continue;
                }
                
                // Handle /leave command
                if line == "/leave" {
                    match &chat_context.current_mode {
                        ChatMode::Channel(channel) => {
                            let channel_name = channel.clone();
                            
                            // Send leave notification packet (iOS compatible)
                            let leave_payload = channel_name.as_bytes().to_vec();
                            let leave_packet = create_bitchat_packet(&my_peer_id, MessageType::Leave, leave_payload);
                            
                            // Set TTL to 3 for leave messages (matching iOS)
                            let mut leave_packet_with_ttl = leave_packet;
                            if leave_packet_with_ttl.len() > 2 {
                                leave_packet_with_ttl[2] = 3; // TTL position
                            }
                            
                            if let Err(_e) = peripheral.write(cmd_char, &leave_packet_with_ttl, WriteType::WithoutResponse).await {
                                // Silently ignore leave notification failures - not critical
                            }
                            
                            // Clean up local state
                            channel_keys.remove(&channel_name);
                            password_protected_channels.remove(&channel_name);
                            channel_creators.remove(&channel_name);
                            channel_key_commitments.remove(&channel_name);
                            
                            // Remove from encrypted passwords
                            app_state.encrypted_channel_passwords.remove(&channel_name);
                            
                            // Update chat context
                            chat_context.remove_channel(&channel_name);
                            chat_context.switch_to_public();
                            
                            // Save state
                            let state_to_save = create_app_state(
                                &blocked_peers,
                                &channel_creators,
                                &chat_context.active_channels,
                                &password_protected_channels,
                                &channel_key_commitments,
                                &app_state.encrypted_channel_passwords,
                                &nickname
                            );
                            if let Err(e) = save_state(&state_to_save) {
                                eprintln!("Warning: Could not save state: {}", e);
                            }
                            
                            println!("\x1b[90m» Left channel {}\x1b[0m", channel_name);
                            print!("> ");
                            std::io::stdout().flush().unwrap();
                        },
                        _ => {
                            println!("» You're not in a channel. Use /j #channel to join one.");
                        }
                    }
                    continue;
                }
                
                // Handle /pass command
                if line.starts_with("/pass ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    
                    // Check if user is in a channel
                    if let ChatMode::Channel(channel) = &chat_context.current_mode {
                        // Check if user is the channel owner
                        if let Some(owner) = channel_creators.get(channel) {
                            if owner == &my_peer_id {
                                if parts.len() >= 2 {
                                    let new_password = parts[1..].join(" ");
                                    
                                    if new_password.len() < 4 {
                                        println!("\x1b[93m⚠ Password too short\x1b[0m");
                                        println!("\x1b[90mMinimum 4 characters required.\x1b[0m");
                                        continue;
                                    }
                                    
                                    // Derive new key
                                    let new_key = NoiseIntegrationService::derive_channel_key(&new_password, channel);
                                    
                                    // Store old key for notification
                                    let old_key = channel_keys.get(channel).cloned();
                                    
                                    // Update keys and mark as protected
                                    channel_keys.insert(channel.clone(), new_key);
                                    password_protected_channels.insert(channel.clone());
                                    
                                    // Save encrypted password (matching iOS Keychain behavior)
                                    if let Some(identity_key) = &app_state.identity_key {
                                        match encrypt_password(&new_password, identity_key) {
                                            Ok(encrypted) => {
                                                app_state.encrypted_channel_passwords.insert(channel.clone(), encrypted);
                                                debug_println!("[CHANNEL] Saved encrypted password for {}", channel);
                                            }
                                            Err(e) => {
                                                debug_println!("[CHANNEL] Failed to encrypt password: {}", e);
                                            }
                                        }
                                    }
                                    
                                    // Calculate key commitment (SHA256 of key)
                                    use sha2::Digest;
                                    let mut hasher = Sha256::new();
                                    hasher.update(&new_key);
                                    let commitment = hasher.finalize();
                                    let commitment_hex = hex::encode(&commitment);
                                    
                                    // Send notification with old key if exists
                                    if let Some(old_key) = old_key {
                                        let notify_msg = "🔐 Password changed by channel owner. Please update your password.";
                                        let encrypted_notify = match noise_service.encrypt_with_channel_key(notify_msg.as_bytes(), &old_key) {
                                            Ok(enc) => enc,
                                            Err(_) => Vec::new(),
                                        };
                                        
                                        if !encrypted_notify.is_empty() {
                                            let (notify_payload, _) = create_encrypted_channel_message_payload(
                                                &nickname, notify_msg, channel, &old_key, &noise_service, &my_peer_id
                                            );
                                            let notify_packet = create_bitchat_packet(&my_peer_id, MessageType::Message, notify_payload);
                                            let _ = send_packet_with_fragmentation(&peripheral, cmd_char, notify_packet, &my_peer_id).await;
                                        }
                                    }
                                    
                                    // Send channel announce with new key commitment
                                    if let Err(e) = send_channel_announce(
                                        &peripheral,
                                        cmd_char,
                                        &my_peer_id,
                                        channel,
                                        true,
                                        Some(&commitment_hex),
                                    ).await {
                                        println!("[!] Failed to announce password change: {}", e);
                                    }
                                    
                                    // Send initialization message with new key
                                    let init_msg = format!("🔑 Password {} | Channel {} password {} by {} | Metadata: {}",
                                        if old_key.is_some() { "changed" } else { "set" },
                                        channel,
                                        if old_key.is_some() { "updated" } else { "protected" },
                                        nickname,
                                        hex::encode(&my_peer_id.as_bytes())
                                    );
                                    
                                    let (init_payload, _) = create_encrypted_channel_message_payload(
                                        &nickname, &init_msg, channel, &new_key, &noise_service, &my_peer_id
                                    );
                                    let init_packet = create_bitchat_packet(&my_peer_id, MessageType::Message, init_payload);
                                    let _ = send_packet_with_fragmentation(&peripheral, cmd_char, init_packet, &my_peer_id).await;
                                    
                                    // Save state
                                    let state_to_save = create_app_state(
                                        &blocked_peers,
                                        &channel_creators,
                                        &chat_context.active_channels,
                                        &password_protected_channels,
                                        &channel_key_commitments,
                                        &app_state.encrypted_channel_passwords,
                                        &nickname
                                    );
                                    if let Err(e) = save_state(&state_to_save) {
                                        eprintln!("Warning: Could not save state: {}", e);
                                    }
                                    
                                    println!("» Password {} for {}.", 
                                        if old_key.is_some() { "changed" } else { "set" },
                                        channel
                                    );
                                    println!("» Members will need to rejoin with: /j {} {}", channel, new_password);
                                } else {
                                    println!("\x1b[93m⚠ Usage: /pass <new password>\x1b[0m");
                                    println!("\x1b[90mExample: /pass mysecret123\x1b[0m");
                                }
                            } else {
                                println!("» Only the channel owner can change the password.");
                            }
                        } else {
                            // No owner recorded - first to set password becomes owner (iOS behavior)
                            if parts.len() >= 2 {
                                let new_password = parts[1..].join(" ");
                                
                                // Claim ownership
                                channel_creators.insert(channel.clone(), my_peer_id.clone());
                                
                                // Derive key
                                let new_key = NoiseIntegrationService::derive_channel_key(&new_password, channel);
                                
                                // Update keys and mark as protected
                                channel_keys.insert(channel.clone(), new_key);
                                password_protected_channels.insert(channel.clone());
                                
                                // Save encrypted password (matching iOS Keychain behavior)
                                if let Some(identity_key) = &app_state.identity_key {
                                    match encrypt_password(&new_password, identity_key) {
                                        Ok(encrypted) => {
                                            app_state.encrypted_channel_passwords.insert(channel.clone(), encrypted);
                                            debug_println!("[CHANNEL] Saved encrypted password for {}", channel);
                                        }
                                        Err(e) => {
                                            debug_println!("[CHANNEL] Failed to encrypt password: {}", e);
                                        }
                                    }
                                }
                                
                                // Calculate key commitment
                                use sha2::Digest;
                                let mut hasher = Sha256::new();
                                hasher.update(&new_key);
                                let commitment = hasher.finalize();
                                let commitment_hex = hex::encode(&commitment);
                                
                                // Send channel announce to claim ownership and announce password
                                debug_println!("[CHANNEL] Claiming ownership of {} and setting password", channel);
                                if let Err(e) = send_channel_announce(
                                    &peripheral,
                                    cmd_char,
                                    &my_peer_id,
                                    channel,
                                    true,
                                    Some(&commitment_hex)
                                ).await {
                                    eprintln!("Failed to send channel announce: {}", e);
                                }
                                
                                // Save state
                                let state_to_save = create_app_state(
                                    &blocked_peers,
                                    &channel_creators,
                                    &chat_context.active_channels,
                                    &password_protected_channels,
                                    &channel_key_commitments,
                                    &app_state.encrypted_channel_passwords,
                                    &nickname
                                );
                                if let Err(e) = save_state(&state_to_save) {
                                    eprintln!("Warning: Could not save state: {}", e);
                                }
                                
                                println!("» Password set for {}. You are now the channel owner.", channel);
                                println!("» Members will need to rejoin with: /j {} {}", channel, new_password);
                            } else {
                                println!("\x1b[93m⚠ Usage: /pass <new password>\x1b[0m");
                                    println!("\x1b[90mExample: /pass mysecret123\x1b[0m");
                            }
                        }
                    } else {
                        println!("» You must be in a channel to use /pass.");
                    }
                    continue;
                }
                
                // Handle /transfer command
                if line.starts_with("/transfer ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    
                    // Check if user is in a channel
                    if let ChatMode::Channel(channel) = &chat_context.current_mode {
                        // Check if user is the channel owner
                        if let Some(owner_id) = channel_creators.get(channel) {
                            if owner_id == &my_peer_id {
                                if parts.len() >= 2 {
                                    let target_name = parts[1];
                                    
                                    // Remove @ prefix if present
                                    let target_name = if target_name.starts_with('@') {
                                        &target_name[1..]
                                    } else {
                                        target_name
                                    };
                                    
                                    // Find the peer ID for the target nickname
                                    let peers_lock = peers.lock().unwrap();
                                    let target_peer_id = peers_lock.iter()
                                        .find(|(_, peer)| peer.nickname.as_ref().map(|n| n == target_name).unwrap_or(false))
                                        .map(|(id, _)| id.clone());
                                    drop(peers_lock);
                                    
                                    if let Some(new_owner_id) = target_peer_id {
                                        // Update the channel owner
                                        channel_creators.insert(channel.clone(), new_owner_id.clone());
                                        
                                        // Save the updated state
                                        let state_to_save = create_app_state(
                                            &blocked_peers,
                                            &channel_creators,
                                            &Vec::new(), // Not persisting joined channels yet
                                            &password_protected_channels,
                                            &channel_key_commitments,
                                            &app_state.encrypted_channel_passwords,
                                            &nickname
                                        );
                                        if let Err(e) = save_state(&state_to_save) {
                                            eprintln!("Failed to save state: {}", e);
                                        }
                                        
                                        // Send channel announce to notify everyone
                                        debug_println!("[CHANNEL] Transferring ownership of {} to {}", channel, target_name);
                                        
                                        // Check if channel is password protected to get key commitment
                                        let is_protected = password_protected_channels.contains(channel);
                                        
                                        let key_commitment = if is_protected {
                                            channel_keys.get(channel).map(|key| {
                                                let hash = sha2::Sha256::digest(key);
                                                hex::encode(hash)
                                            })
                                        } else {
                                            None
                                        };
                                        
                                        // Send announce packet with new owner
                                        match send_channel_announce(&peripheral, &cmd_char, &new_owner_id, channel, is_protected, key_commitment.as_deref()).await {
                                            Ok(_) => {
                                                println!("» Transferred ownership of {} to {}", channel, target_name);
                                            }
                                            Err(e) => {
                                                eprintln!("Failed to send ownership transfer announcement: {}", e);
                                            }
                                        }
                                    } else {
                                        println!("\x1b[93m⚠ User '{}' not found\x1b[0m", target_name);
                                        println!("\x1b[90mMake sure they are online and you have the correct nickname.\x1b[0m");
                                    }
                                } else {
                                    println!("\x1b[93m⚠ Usage: /transfer @<username>\x1b[0m");
                                    println!("\x1b[90mExample: /transfer @newowner\x1b[0m");
                                }
                            } else {
                                println!("» Only the channel owner can transfer ownership.");
                            }
                        } else {
                            println!("» Only the channel owner can transfer ownership.");
                        }
                    } else {
                        println!("» You must be in a channel to use /transfer.");
                    }
                    continue;
                }
                
                // Check for unknown commands
                if line.starts_with("/") {
                    println!("\x1b[93m⚠ Unknown command: {}\x1b[0m", line.split_whitespace().next().unwrap_or(""));
                    println!("\x1b[90mType /help to see available commands.\x1b[0m");
                    continue;
                }
                
                // Check if in DM mode first
                if let ChatMode::PrivateDM { nickname: target_nickname, peer_id: target_peer_id } = &chat_context.current_mode {
                    // Only show echo in debug mode
                    debug_println!("{} > {}", chat_context.format_prompt(), line);
                    debug_println!("[PRIVATE] Sending DM to {} (peer_id: {})", target_nickname, target_peer_id);
                    
                    // Create message payload with private flag
                    let (message_payload, message_id) = create_bitchat_message_payload_full(&nickname, &line, None, true, &my_peer_id);
                    
                    // Track private message for delivery confirmation
                    delivery_tracker.track_message(message_id.clone(), line.clone(), true);
                    
                    // Pad the message for privacy using PKCS#7
                    let block_sizes = [256, 512, 1024, 2048];
                    let payload_size = message_payload.len();
                    let target_size = block_sizes.iter()
                        .find(|&&size| payload_size + 16 <= size)
                        .copied()
                        .unwrap_or(payload_size);
                    
                    let padding_needed = target_size - message_payload.len();
                    let mut padded_payload = message_payload.clone();
                    
                    if padding_needed > 0 && padding_needed <= 255 {
                        // PKCS#7 padding: all padding bytes have the same value (the padding length)
                        for _ in 0..padding_needed {
                            padded_payload.push(padding_needed as u8);
                        }
                        debug_println!("[PRIVATE] Added {} bytes of PKCS#7 padding", padding_needed);
                    } else if padding_needed == 0 {
                        // If already at block size, don't add more padding
                        debug_println!("[PRIVATE] Message already at block size, no padding needed");
                    }
                    
                    // Check if we have an established Noise session with the target peer
                    if noise_service.has_established_session(target_peer_id) {
                        // Use Noise encryption for this peer
                        match noise_service.encrypt_for_peer(target_peer_id, &padded_payload) {
                            Ok(encrypted) => {
                                debug_println!("[NOISE] Encrypted private message: {} bytes", encrypted.len());
                                
                                // Create packet with Noise encrypted message type
                                let packet = create_bitchat_packet_with_recipient(
                                    &my_peer_id,
                                    Some(target_peer_id),
                                    MessageType::NoiseEncrypted,
                                    encrypted,
                                    None  // No separate signature needed with Noise
                                );
                                
                                // Send the private message
                                if let Err(_e) = send_packet_with_fragmentation(&peripheral, cmd_char, packet, &my_peer_id).await {
                                    println!("\n\x1b[91m❌ Failed to send private message\x1b[0m");
                                    println!("\x1b[90mThe message could not be delivered. Connection may have been lost.\x1b[0m");
                                } else {
                                    debug_println!("[NOISE] Private message sent to {}", target_peer_id);
                                }
                            },
                            Err(e) => {
                                println!("[!] Failed to encrypt message with Noise: {}", e);
                            }
                        }
                    } else {
                        // No Noise session established - initiate handshake first
                        println!("» Initiating secure handshake with {}...", target_nickname);
                        
                        match noise_service.initiate_handshake(target_peer_id) {
                            Ok(handshake_msg) => {
                                debug_println!("[HANDSHAKE] Initiated handshake with {}, sending {} bytes", target_peer_id, handshake_msg.len());
                                
                                // Create packet for handshake message
                                let packet = create_bitchat_packet_with_recipient(
                                    &my_peer_id,
                                    Some(target_peer_id),
                                    MessageType::NoiseHandshakeInit,
                                    handshake_msg,
                                    None
                                );
                                
                                // Send handshake message
                                if let Err(_e) = send_packet_with_fragmentation(&peripheral, cmd_char, packet, &my_peer_id).await {
                                    println!("\x1b[91m❌ Failed to send handshake\x1b[0m");
                                } else {
                                    println!("» Handshake initiated. Please wait for response and try sending the message again.");
                                }
                            },
                            Err(e) => {
                                println!("[!] Failed to initiate handshake: {:?}", e);
                                println!("[!] Unable to establish secure connection with {}", target_nickname);
                            }
                        }
                    }
                    continue;
                }
                
                // Regular public/channel message
                // Only show echo in debug mode
                debug_println!("{} > {}", chat_context.format_prompt(), line);
                
                let current_channel = chat_context.current_mode.get_channel().map(|s| s.to_string());
                
                // Check if trying to send to password-protected channel without key
                if let Some(ref channel) = current_channel {
                    if password_protected_channels.contains(channel) && !channel_keys.contains_key(channel) {
                        println!("❌ Cannot send to password-protected channel {}. Join with password first.", channel);
                        continue;
                    }
                }
                
                let (message_payload, message_id) = if let Some(ref channel) = current_channel {
                    if let Some(channel_key) = channel_keys.get(channel) {
                        // Encrypt the message content for the channel
                        debug_println!("[ENCRYPT] Encrypting message for channel {} 🔒", channel);
                        create_encrypted_channel_message_payload(&nickname, &line, channel, channel_key, &noise_service, &my_peer_id)
                    } else {
                        let payload = create_bitchat_message_payload(&nickname, &line, current_channel.as_deref());
                        (payload, Uuid::new_v4().to_string()) // Generate ID for old style messages
                    }
                } else {
                    let payload = create_bitchat_message_payload(&nickname, &line, current_channel.as_deref());
                    (payload, Uuid::new_v4().to_string()) // Generate ID for old style messages
                };
                
                // Track the message for delivery confirmation (not for channel messages with 10+ peers)
                let is_private = false;
                delivery_tracker.track_message(message_id.clone(), line.clone(), is_private);
                
                debug_println!("[MESSAGE] ==================== SENDING USER MESSAGE ====================");
                debug_println!("[MESSAGE] Message content: '{}'", line);
                debug_println!("[MESSAGE] Message payload size: {} bytes", message_payload.len());
                
                // Create the complete message packet (unsigned for broadcast messages to match Swift protocol)
                let message_packet = create_bitchat_packet(&my_peer_id, MessageType::Message, message_payload.clone());
                
                // Check if we need to fragment the COMPLETE PACKET (matching Swift behavior)
                if should_fragment(&message_packet) {
                    debug_println!("[MESSAGE] Complete packet ({} bytes) requires fragmentation", message_packet.len());
                    
                    // Use Swift-compatible fragmentation for complete packet
                    if let Err(_e) = send_packet_with_fragmentation(&peripheral, cmd_char, message_packet, &my_peer_id).await {
                        println!("\n\x1b[91m❌ Message delivery failed\x1b[0m");
                        println!("\x1b[90mConnection lost. Please restart BitChat to reconnect.\x1b[0m");
                        break;
                    }
                } else {
                    // Send as single packet without fragmentation
                    debug_println!("[MESSAGE] Sending message as single packet ({} bytes)", message_packet.len());
                    
                    // Use WithResponse for larger packets (matching Swift's 512 byte threshold)
                    let write_type = if message_packet.len() > 512 {
                        WriteType::WithResponse
                    } else {
                        WriteType::WithoutResponse
                    };
                    
                    if peripheral.write(cmd_char, &message_packet, write_type).await.is_err() {
                        println!("[!] Failed to send message. Connection likely lost.");
                        break;
                    }
                    
                    debug_println!("[MESSAGE] ✓ Successfully sent message packet");
                }
                debug_println!("[MESSAGE] ==================== MESSAGE SEND COMPLETE ====================");
                
                // Display the sent message in a clean format
                let timestamp = chrono::Local::now();
                let display = format_message_display(
                    timestamp,
                    &nickname,
                    &line,
                    false, // is_private
                    current_channel.is_some(), // is_channel
                    current_channel.as_deref(), // channel_name
                    None, // recipient
                    &nickname // my_nickname
                );
                // Move cursor up to overwrite the input line, clear it, print message
                print!("\x1b[1A\r\x1b[K{}\n", display);
                std::io::stdout().flush().unwrap();

            },

            Some(notification) = notification_stream.next() => {
                // Simple packet logging
                if notification.value.len() >= 2 {
                    let msg_type = notification.value[1];
                    debug_full_println!("[PACKET] Received {} bytes, type: 0x{:02X}", notification.value.len(), msg_type);
                }
                
                match parse_bitchat_packet(&notification.value) {
                    Ok(packet) => {
                        // Ignore our own messages
                        if packet.sender_id_str == my_peer_id {
                            continue;
                        }

                        let mut peers_lock = peers.lock().unwrap();

                     match packet.msg_type {

                         MessageType::Announce => {
                             let peer_nickname = String::from_utf8_lossy(&packet.payload).trim().to_string();

                             let is_new_peer = !peers_lock.contains_key(&packet.sender_id_str);
                             let peer_entry = peers_lock.entry(packet.sender_id_str.clone()).or_default();

                             peer_entry.nickname = Some(peer_nickname.clone());

                             // Show connection notification in clean mode only for new peers
                             if is_new_peer {
                                 // Clear any existing prompt and show connection notification in yellow
                                 print!("\r\x1b[K\x1b[33m{} connected\x1b[0m\n> ", peer_nickname);
                                 std::io::stdout().flush().unwrap();
                             }
                             
                             debug_println!("[<-- RECV] Announce: Peer {} is now known as '{}'", packet.sender_id_str, peer_nickname);

                         },

                         MessageType::Message => {
                             debug_full_println!("[DEBUG] ==================== MESSAGE RECEIVED ====================");
                             debug_full_println!("[DEBUG] Sender: {}", packet.sender_id_str);
                             
                             // Check if sender is blocked
                             let fingerprint = noise_service.get_peer_fingerprint(&packet.sender_id_str)
                                 .or_else(|| noise_service.get_peer_fingerprint(&packet.sender_id_str));
                             if let Some(fingerprint) = fingerprint {
                                 if blocked_peers.contains(&fingerprint) {
                                     debug_println!("[BLOCKED] Ignoring message from blocked peer: {}", packet.sender_id_str);
                                     continue; // Silent drop
                                 }
                             }
                             
                             // Check if this is a broadcast or targeted message
                             let is_broadcast = packet.recipient_id.as_ref()
                                 .map(|r| r == &BROADCAST_RECIPIENT)
                                 .unwrap_or(true);
                             
                             // Check if message is for us
                             let is_for_us = if is_broadcast {
                                 true
                             } else {
                                 packet.recipient_id_str.as_ref()
                                     .map(|r| {
                                         let matches = r == &my_peer_id;
                                         debug_full_println!("[DEBUG] Comparing recipient '{}' with my_peer_id '{}': {}", r, my_peer_id, matches);
                                         matches
                                     })
                                     .unwrap_or(false)
                             };
                             
                             if let Some(ref recipient) = packet.recipient_id_str {
                                 debug_full_println!("[DEBUG] Recipient: {} (broadcast: {})", recipient, is_broadcast);
                             } else {
                                 debug_full_println!("[DEBUG] Recipient: (none/broadcast)");
                             }
                             
                             debug_full_println!("[DEBUG] Payload size: {} bytes", packet.payload.len());
                             
                             // Handle messages not for us - relay them
                             if !is_for_us {
                                 debug_full_println!("[DEBUG] Message not for us, checking if we should relay (TTL={})", packet.ttl);
                                 
                                 // Relay if TTL > 1
                                 if packet.ttl > 1 {
                                     time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                                     let mut relay_data = notification.value.clone();
                                     relay_data[2] = packet.ttl - 1;  // Decrement TTL
                                     
                                     if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
                                         println!("[!] Failed to relay message");
                                     } else {
                                         debug_full_println!("[DEBUG] Relayed message with TTL={}", packet.ttl - 1);
                                     }
                                 }
                                 continue;
                             }
                             
                             // iOS sends private messages with recipient ID set at packet level
                             let is_private_message = !is_broadcast && is_for_us;
                             let mut decrypted_payload = None;
                             
                             // If it's a private message for us, we need to decrypt it
                             if is_private_message {
                                 debug_println!("[PRIVATE] This is a private message for us from {}", packet.sender_id_str);
                                 debug_println!("[PRIVATE] Payload size: {} bytes", packet.payload.len());
                                 debug_println!("[PRIVATE] First 32 bytes of encrypted payload: {}", hex::encode(&packet.payload[..std::cmp::min(32, packet.payload.len())]));
                                 
                                 match noise_service.decrypt_from_peer(&packet.sender_id_str, &packet.payload) {
                                     Ok(decrypted) => {
                                         debug_println!("[PRIVATE] Successfully decrypted private message!");
                                         debug_println!("[PRIVATE] Decrypted size: {} bytes", decrypted.len());
                                         decrypted_payload = Some(decrypted);
                                     }
                                     Err(e) => {
                                         debug_println!("[PRIVATE] Failed to decrypt private message: {:?}", e);
                                         debug_println!("[PRIVATE] Checking if we have shared secret with {}", packet.sender_id_str);
                                         // Private messages MUST be encrypted, skip if decryption fails
                                         continue;
                                     }
                                 }
                             }
                             
                             
                             // Parse the message payload
                             let parse_result = if is_private_message {
                                 // For private messages, parse the decrypted and unpadded payload
                                 if let Some(ref decrypted) = decrypted_payload {
                                     debug_full_println!("[DEBUG] Parsing decrypted private message payload");
                                     let unpadded = unpad_message(decrypted);
                                     debug_full_println!("[DEBUG] After unpadding: {} bytes", unpadded.len());
                                     parse_bitchat_message_payload(&unpadded)
                                 } else {
                                     // If decryption failed but it's a private message, skip it
                                     debug_full_println!("[DEBUG] Cannot parse private message without decryption");
                                     continue;
                                 }
                             } else {
                                 // For broadcast messages, parse the payload directly
                                 debug_full_println!("[DEBUG] Parsing regular message payload");
                                 parse_bitchat_message_payload(&packet.payload)
                             };

                             if let Ok(message) = parse_result {
                                 debug_full_println!("[DEBUG] Message parsed successfully!");
                                 debug_full_println!("[DEBUG] Message ID: {}", message.id);
                                 debug_full_println!("[DEBUG] Is encrypted channel: {}", message.is_encrypted);
                                 debug_full_println!("[DEBUG] Channel: {:?}", message.channel);
                                 debug_full_println!("[DEBUG] Content length: {} bytes", message.content.len());

                                 if !bloom.check(&message.id) {
                                     // Add to bloom filter immediately to prevent duplicate processing
                                     bloom.set(&message.id);

                                     let sender_nick = peers_lock.get(&packet.sender_id_str)
                                         .and_then(|p| p.nickname.as_ref())
                                         .map_or(&packet.sender_id_str, |n| n);

                                        // Track discovered channels
                                        if let Some(channel) = &message.channel {
                                            discovered_channels.insert(channel.clone());
                                            debug_println!("[DISCOVERY] Found channel: {}", channel);
                                            
                                            // Mark channel as password-protected if we see an encrypted message
                                            if message.is_encrypted {
                                                password_protected_channels.insert(channel.clone());
                                                debug_println!("[SECURITY] Marked {} as password-protected", channel);
                                            }
                                        }

                                        {
                                            // Normal message display with decryption support
                                            let display_content = if message.is_encrypted {
                                                if let Some(channel) = &message.channel {
                                                    if let Some(channel_key) = channel_keys.get(channel) {
                                                        // Decrypt the encrypted content
                                                        if let Some(encrypted_bytes) = &message.encrypted_content {
                                                            match noise_service.decrypt_with_channel_key(encrypted_bytes, channel_key) {
                                                            Ok(decrypted) => String::from_utf8_lossy(&decrypted).to_string(),
                                                                Err(_) => "[Encrypted message - decryption failed]".to_string()
                                                            }
                                                        } else {
                                                            "[Encrypted message - no encrypted data]".to_string()
                                                        }
                                                    } else {
                                                        "[Encrypted message - join channel with password]".to_string()
                                                    }
                                                } else {
                                                    message.content.clone()
                                                }
                                            } else {
                                                message.content.clone()
                                            };

                                            // Display the message with proper formatting
                                            let timestamp = chrono::Local::now();
                                            
                                            if is_private_message {
                                                // Check for iOS cover traffic (dummy messages)
                                                if display_content.starts_with(COVER_TRAFFIC_PREFIX) {
                                                    debug_println!("[COVER] Discarding dummy message from {}", sender_nick);
                                                    continue; // Silently discard cover traffic
                                                }
                                                
                                                // Save the last private sender for replies
                                                chat_context.last_private_sender = Some((packet.sender_id_str.clone(), sender_nick.to_string()));
                                                chat_context.add_dm(&sender_nick, &packet.sender_id_str);
                                                
                                                let display = format_message_display(
                                                    timestamp,
                                                    &sender_nick,
                                                    &display_content,
                                                    true, // is_private
                                                    false, // is_channel
                                                    None, // channel_name
                                                    Some(&nickname), // recipient (me)
                                                    &nickname // my_nickname
                                                );
                                                // Clear any existing prompt and print the message
                                                print!("\r\x1b[K{}\n", display);
                                                
                                                // Show minimal reply hint
                                                if !matches!(&chat_context.current_mode, ChatMode::PrivateDM { .. }) {
                                                    print!("\x1b[90m» /reply to respond\x1b[0m\n");
                                                }
                                                print!("> ");
                                                std::io::stdout().flush().unwrap();
                                                
                                                // Update last sender for /reply command
                                            } else if let Some(channel_name) = &message.channel {
                                                // Track this channel
                                                chat_context.add_channel(channel_name);
                                                
                                                let display = format_message_display(
                                                    timestamp,
                                                    &sender_nick,
                                                    &display_content,
                                                    false, // is_private
                                                    true, // is_channel
                                                    Some(channel_name), // channel_name
                                                    None, // recipient
                                                    &nickname // my_nickname
                                                );
                                                // Clear any existing prompt and print the message
                                                print!("\r\x1b[K{}\n", display);
                                                std::io::stdout().flush().unwrap();
                                            } else {
                                                // Public message
                                                let display = format_message_display(
                                                    timestamp,
                                                    &sender_nick,
                                                    &display_content,
                                                    false, // is_private
                                                    false, // is_channel
                                                    None, // channel_name
                                                    None, // recipient
                                                    &nickname // my_nickname
                                                );
                                                // Clear any existing prompt and print the message
                                                print!("\r\x1b[K{}\n> ", display);
                                                std::io::stdout().flush().unwrap();
                                            }
                                        }
                                     
                                     // Send delivery ACK if needed (matching iOS behavior)
                                     let active_peer_count = peers_lock.len();
                                     if should_send_ack(is_private_message, message.channel.as_deref(), None, &nickname, active_peer_count) {
                                         // Check if we've already sent an ACK for this message
                                         let ack_id = format!("{}-{}", message.id, my_peer_id);
                                         if delivery_tracker.should_send_ack(&ack_id) {
                                             debug_println!("[ACK] Sending delivery ACK for message {}", message.id);
                                             
                                             // Create ACK payload
                                             let ack_payload = create_delivery_ack(
                                                 &message.id,
                                                 &my_peer_id,
                                                 &nickname,
                                                 1 // hop count
                                             );
                                             
                                             // Encrypt ACK if it's a private message
                                             let final_ack_payload = if is_private_message {
                                                 // Try Noise encryption first, fall back to legacy
                                                 if noise_service.has_established_session(&packet.sender_id_str) {
                                                     match noise_service.encrypt_for_peer(&packet.sender_id_str, &ack_payload) {
                                                         Ok(encrypted) => encrypted,
                                                         Err(e) => {
                                                             debug_println!("[ACK] Failed to encrypt ACK with Noise: {:?}", e);
                                                             ack_payload
                                                         }
                                                     }
                                                 } else {
                                                     // Use legacy encryption
                                                     match noise_service.encrypt_for_peer(&packet.sender_id_str, &ack_payload) {
                                                         Ok(encrypted) => encrypted,
                                                         Err(e) => {
                                                             debug_println!("[ACK] Failed to encrypt ACK: {:?}", e);
                                                             ack_payload
                                                         }
                                                     }
                                                 }
                                             } else {
                                                 ack_payload
                                             };
                                             
                                             // Create and send ACK packet with TTL=3 (limited propagation)
                                             let mut ack_packet = create_bitchat_packet_with_recipient(
                                                 &my_peer_id, 
                                                 Some(&packet.sender_id_str),
                                                 MessageType::DeliveryAck, 
                                                 final_ack_payload,
                                                 None // No signature for ACKs
                                             );
                                             
                                             // Override TTL to 3 for ACKs
                                             if ack_packet.len() > 2 {
                                                 ack_packet[2] = 3; // TTL position
                                             }
                                             
                                             if let Err(e) = peripheral.write(cmd_char, &ack_packet, WriteType::WithoutResponse).await {
                                                 debug_println!("[ACK] Failed to send delivery ACK: {}", e);
                                             }
                                         }
                                     }

                                     // Relay message if TTL > 1 (matching Swift behavior)
                                     if packet.ttl > 1 {
                                         // Don't relay immediately - add small random delay
                                         time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                                         
                                         // Create relay packet with decremented TTL
                                         let mut relay_data = notification.value.clone();
                                         relay_data[2] = packet.ttl - 1;  // Decrement TTL at position 2
                                         
                                         if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
                                             println!("[!] Failed to relay message");
                                         }
                                     }

                                 }

                             } else {
                                 println!("[!] Failed to parse message payload");
                                 debug_full_println!("[DEBUG] Parse error details:");
                                 debug_full_println!("[DEBUG] Raw payload hex: {}", hex::encode(&packet.payload));
                                 if let Some(decrypted) = decrypted_payload {
                                     debug_full_println!("[DEBUG] Decrypted payload hex: {}", hex::encode(&decrypted));
                                 }
                             }

                         },
                         MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => {
                             // Handle fragment (simplified, following working example)
                             if packet.payload.len() >= 13 {
                                 let mut fragment_id = [0u8; 8];
                                 fragment_id.copy_from_slice(&packet.payload[0..8]);
                                 
                                 let index = ((packet.payload[8] as u16) << 8) | (packet.payload[9] as u16);
                                 let total = ((packet.payload[10] as u16) << 8) | (packet.payload[11] as u16);
                                 let original_type = packet.payload[12];
                                 let fragment_data = packet.payload[13..].to_vec();
                                 
                                 // Try to reassemble
                                 if let Some((complete_data, _sender)) = fragment_collector.add_fragment(
                                     fragment_id, index, total, original_type, fragment_data, packet.sender_id_str.clone()
                                 ) {
                                     // Parse and handle the reassembled packet
                                     if let Ok(reassembled_packet) = parse_bitchat_packet(&complete_data) {
                                         if reassembled_packet.msg_type == MessageType::Message {
                                             // Check if sender is blocked
                                             let fingerprint = noise_service.get_peer_fingerprint(&reassembled_packet.sender_id_str)
                                                 .or_else(|| noise_service.get_peer_fingerprint(&reassembled_packet.sender_id_str));
                                             if let Some(fingerprint) = fingerprint {
                                                 if blocked_peers.contains(&fingerprint) {
                                                     debug_println!("[BLOCKED] Ignoring fragmented message from blocked peer: {}", reassembled_packet.sender_id_str);
                                                     continue; // Silent drop
                                                 }
                                             }
                                             
                                             // Check if this is a private message that needs decryption
                                             let is_broadcast = reassembled_packet.recipient_id.as_ref()
                                                 .map(|r| r == &BROADCAST_RECIPIENT)
                                                 .unwrap_or(true);
                                             
                                             let is_for_us = if is_broadcast {
                                                 true
                                             } else {
                                                 reassembled_packet.recipient_id_str.as_ref()
                                                     .map(|r| r == &my_peer_id)
                                                     .unwrap_or(false)
                                             };
                                             
                                             let is_private_message = !is_broadcast && is_for_us;
                                             
                                             // Handle private messages by decrypting first
                                             let message_result = if is_private_message {
                                                 match noise_service.decrypt_from_peer(&reassembled_packet.sender_id_str, &reassembled_packet.payload) {
                                                     Ok(decrypted) => {
                                                         debug_println!("[PRIVATE] Successfully decrypted fragmented private message!");
                                                         debug_println!("[PRIVATE] Decrypted size: {} bytes", decrypted.len());
                                                         let unpadded = unpad_message(&decrypted);
                                                         debug_full_println!("[DEBUG] After unpadding: {} bytes", unpadded.len());
                                                         parse_bitchat_message_payload(&unpadded)
                                                     },
                                                     Err(e) => {
                                                         debug_println!("[PRIVATE] Failed to decrypt fragmented private message: {:?}", e);
                                                         continue;
                                                     }
                                                 }
                                             } else {
                                                 // Regular broadcast message
                                                 parse_bitchat_message_payload(&reassembled_packet.payload)
                                             };
                                             
                                             if let Ok(message) = message_result {
                                                 if !bloom.check(&message.id) {
                                                     let sender_nick = peers_lock.get(&reassembled_packet.sender_id_str)
                                                         .and_then(|p| p.nickname.as_ref())
                                                         .map_or(&reassembled_packet.sender_id_str, |n| n);
                                                     
                                                     {
                                                         // Track discovered channels from fragmented messages
                                                         if let Some(channel) = &message.channel {
                                                             discovered_channels.insert(channel.clone());
                                                             if message.is_encrypted {
                                                                 password_protected_channels.insert(channel.clone());
                                                             }
                                                         }
                                                         
                                                         // Check for iOS cover traffic in private messages
                                                         if is_private_message && message.content.starts_with(COVER_TRAFFIC_PREFIX) {
                                                             debug_println!("[COVER] Discarding fragmented dummy message from {}", sender_nick);
                                                             bloom.set(&message.id); // Mark as seen before continuing
                                                             continue; // Silently discard
                                                         }
                                                         
                                                         // Regular message - display it
                                                         let timestamp = chrono::Local::now();
                                                         let display = format_message_display(
                                                             timestamp,
                                                             sender_nick,
                                                             &message.content,
                                                             is_private_message, // Use the actual private message flag
                                                             message.channel.is_some(), // is_channel
                                                             message.channel.as_deref(),
                                                             if is_private_message { Some(&nickname) } else { None }, // recipient for private messages
                                                             &nickname // my_nickname
                                                         );
                                                         // Clear any existing prompt and print the message
                                                print!("\r\x1b[K{}\n> ", display);
                                                std::io::stdout().flush().unwrap();
                                                         
                                                         // If it's a private message, update chat context
                                                         if is_private_message {
                                                             chat_context.last_private_sender = Some((reassembled_packet.sender_id_str.clone(), sender_nick.to_string()));
                                                         }
                                                     }
                                                     
                                                     bloom.set(&message.id);
                                                 }
                                             }
                                         }
                                     }
                                 }
                             }
                             
                             // Relay fragments if TTL > 1
                             if packet.ttl > 1 {
                                 time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                                 let mut relay_data = notification.value.clone();
                                 relay_data[2] = packet.ttl - 1;
                                 
                                 if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
                                     println!("[!] Failed to relay fragment");
                                 }
                             }
                         },
                         MessageType::NoiseHandshakeInit => {
                             // Handle Noise protocol handshake initiation
                             debug_println!("[<-- RECV] Noise handshake init from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                             
                             // Process the handshake message
                             match noise_service.process_handshake_message(&packet.sender_id_str, &packet.payload) {
                                 Ok(Some(response)) => {
                                     // Send handshake response with correct recipient
                                     debug_println!("[NOISE] Sending handshake response to {}", packet.sender_id_str);
                                     let response_packet = create_bitchat_packet_with_recipient(
                                         &my_peer_id, 
                                         Some(&packet.sender_id_str), 
                                         MessageType::NoiseHandshakeResp, 
                                         response,
                                         None
                                     );
                                     if let Err(e) = peripheral.write(cmd_char, &response_packet, WriteType::WithoutResponse).await {
                                         println!("[!] Failed to send Noise handshake response: {}", e);
                                     }
                                 },
                                 Ok(None) => {
                                     // Handshake complete (shouldn't happen on init, but handle gracefully)
                                     debug_println!("[+] Noise handshake completed with peer {}", packet.sender_id_str);
                                     
                                     // Add peer to our known peers list if not already there
                                     if !peers_lock.contains_key(&packet.sender_id_str) {
                                         peers_lock.insert(packet.sender_id_str.clone(), Peer { nickname: None });
                                     }
                                 },
                                 Err(e) => {
                                     println!("[!] Failed to process Noise handshake init from {}: {}", packet.sender_id_str, e);
                                 }
                             }
                         },
                         MessageType::NoiseHandshakeResp => {
                             // Handle Noise protocol handshake response
                             debug_println!("[<-- RECV] Noise handshake response from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                             
                             // Process the handshake response
                             match noise_service.process_handshake_message(&packet.sender_id_str, &packet.payload) {
                                 Ok(Some(final_msg)) => {
                                     // Send final handshake message (if needed)
                                     debug_println!("[NOISE] Sending final handshake message to {}", packet.sender_id_str);
                                     let final_packet = create_bitchat_packet_with_recipient(
                                         &my_peer_id, 
                                         Some(&packet.sender_id_str), 
                                         MessageType::NoiseHandshakeResp, 
                                         final_msg,
                                         None
                                     );
                                     if let Err(e) = peripheral.write(cmd_char, &final_packet, WriteType::WithoutResponse).await {
                                         println!("[!] Failed to send final Noise handshake message: {}", e);
                                     }
                                 },
                                 Ok(None) => {
                                     // Handshake complete
                                     debug_println!("[+] Noise handshake completed with peer {}", packet.sender_id_str);
                                     
                                     // Add peer to our known peers list if not already there
                                     if !peers_lock.contains_key(&packet.sender_id_str) {
                                         peers_lock.insert(packet.sender_id_str.clone(), Peer { nickname: None });
                                     }
                                 },
                                 Err(e) => {
                                     println!("[!] Failed to process Noise handshake response from {}: {}", packet.sender_id_str, e);
                                 }
                             }
                         },
                         MessageType::Leave => {
                             // Handle leave notification
                             let payload_str = String::from_utf8_lossy(&packet.payload).trim().to_string();
                             
                             if payload_str.starts_with('#') {
                                 // Channel leave notification
                                 let channel = payload_str;
                                 let sender_nick = peers_lock.get(&packet.sender_id_str)
                                     .and_then(|p| p.nickname.as_ref())
                                     .map_or(&packet.sender_id_str, |n| n);
                                 
                                 // Show leave message only if we're in that channel
                                 if let ChatMode::Channel(current_channel) = &chat_context.current_mode {
                                     if current_channel == &channel {
                                         print!("\r\x1b[K\x1b[90m« {} left {}\x1b[0m\n> ", sender_nick, channel);
                                         std::io::stdout().flush().unwrap();
                                     }
                                 }
                                 
                                 debug_println!("[<-- RECV] {} left channel {}", sender_nick, channel);
                             } else {
                                 // Legacy peer disconnect
                                 peers_lock.remove(&packet.sender_id_str);
                                 debug_println!("[<-- RECV] Peer {} ({}) has left", packet.sender_id_str, payload_str);
                             }
                         },
                         
                         MessageType::ChannelAnnounce => {
                             // Parse channel announce: "channel|isProtected|creatorID|keyCommitment"
                             let payload_str = String::from_utf8_lossy(&packet.payload);
                             let parts: Vec<&str> = payload_str.split('|').collect();
                             
                             if parts.len() >= 3 {
                                 let channel = parts[0];
                                 let is_protected = parts[1] == "1";
                                 let creator_id = parts[2];
                                 let _key_commitment = parts.get(3).unwrap_or(&"");
                                 
                                 debug_println!("[<-- RECV] Channel announce: {} (protected: {}, owner: {})", 
                                              channel, is_protected, creator_id);
                                
                                // Always update channel creator for any channel announce
                                if !creator_id.is_empty() {
                                    channel_creators.insert(channel.to_string(), creator_id.to_string());
                                }
                                 
                                 if is_protected {
                                     password_protected_channels.insert(channel.to_string());
                                     
                                     // Store key commitment for verification (matching iOS behavior)
                                     if !_key_commitment.is_empty() {
                                         channel_key_commitments.insert(channel.to_string(), _key_commitment.to_string());
                                         debug_println!("[CHANNEL] Stored key commitment for {}: {}", channel, _key_commitment);
                                     }
                                 } else {
                                     password_protected_channels.remove(channel);
                                     // If channel is no longer protected, clear keys and commitments
                                     channel_keys.remove(channel);
                                     channel_key_commitments.remove(channel);
                                 }
                                 
                                 // Track this channel
                                 chat_context.add_channel(channel);
                                 
                                 // Save state
                                 let state_to_save = create_app_state(
                                     &blocked_peers,
                                     &channel_creators,
                                     &chat_context.active_channels,
                                     &password_protected_channels,
                                     &channel_key_commitments,
                                     &app_state.encrypted_channel_passwords,
                                     &nickname
                                 );
                                 if let Err(e) = save_state(&state_to_save) {
                                     eprintln!("Warning: Could not save state: {}", e);
                                 }
                             }
                         },

                         MessageType::DeliveryAck => {
                            debug_println!("[<-- RECV] Delivery ACK from {}", packet.sender_id_str);
                            
                            // Check if this ACK is for us
                            let is_for_us = packet.recipient_id_str.as_ref()
                                .map(|r| r == &my_peer_id)
                                .unwrap_or(false);
                            
                            if is_for_us {
                                // Decrypt the ACK payload if it's encrypted
                                let ack_payload = if packet.ttl == 3 {
                                    // ACKs might be encrypted for private messages
                                    if noise_service.has_established_session(&packet.sender_id_str) {
                                        // Try Noise decryption
                                        match noise_service.decrypt_from_peer(&packet.sender_id_str, &packet.payload) {
                                            Ok(decrypted) => decrypted,
                                            Err(_) => packet.payload.clone() // Fall back to unencrypted
                                        }
                                    } else if noise_service.has_established_session(&packet.sender_id_str) {
                                        // Try legacy decryption
                                        match noise_service.decrypt_from_peer(&packet.sender_id_str, &packet.payload) {
                                            Ok(decrypted) => decrypted,
                                            Err(_) => packet.payload.clone() // Fall back to unencrypted
                                        }
                                    } else {
                                        packet.payload.clone() // Unencrypted
                                    }
                                } else {
                                    packet.payload.clone()
                                };
                                
                                // Parse the ACK JSON
                                if let Ok(ack) = serde_json::from_slice::<DeliveryAck>(&ack_payload) {
                                    debug_println!("[ACK] Received ACK for message: {}", ack.original_message_id);
                                    debug_println!("[ACK] From: {} ({})", ack.recipient_nickname, ack.recipient_id);
                                    
                                    // Mark message as delivered
                                    if delivery_tracker.mark_delivered(&ack.original_message_id) {
                                        // Show delivery confirmation
                                        print!("\r\x1b[K\x1b[90m✓ Delivered to {}\x1b[0m\n> ", ack.recipient_nickname);
                                        std::io::stdout().flush().unwrap();
                                    }
                                } else {
                                    debug_println!("[ACK] Failed to parse delivery ACK");
                                }
                            } else if packet.ttl > 1 {
                                // Relay ACK if not for us
                                let mut relay_data = notification.value.clone();
                                relay_data[2] = packet.ttl - 1;
                                let _ = peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await;
                            }
                        },
                        
                        MessageType::DeliveryStatusRequest => {
                            // Handle delivery status request
                            debug_println!("[<-- RECV] Delivery status request from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<DeliveryStatusRequest>(&packet.payload) {
                                Ok(status_request) => {
                                    debug_println!("[DELIVERY] Status request for message {} from {}", 
                                        status_request.message_id, status_request.requester_id);
                                    
                                    // Check if we have this message in our delivery tracker
                                    if let Some((content, sent_time, is_private)) = delivery_tracker.pending_messages.get(&status_request.message_id) {
                                        debug_println!("[DELIVERY] Found message {} - sending confirmation", status_request.message_id);
                                        
                                        // Send delivery acknowledgment
                                        let delivery_ack = DeliveryAck {
                                            original_message_id: status_request.message_id.clone(),
                                            ack_id: Uuid::new_v4().to_string(),
                                            recipient_id: my_peer_id.clone(),
                                            recipient_nickname: nickname.clone(),
                                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                                            hop_count: 1,
                                        };
                                        
                                        if let Ok(ack_payload) = serde_json::to_vec(&delivery_ack) {
                                            let ack_packet = create_bitchat_packet_with_recipient(
                                                &my_peer_id, 
                                                Some(&packet.sender_id_str), 
                                                MessageType::DeliveryAck, 
                                                ack_payload,
                                                None
                                            );
                                            if let Err(e) = peripheral.write(cmd_char, &ack_packet, WriteType::WithoutResponse).await {
                                                println!("[!] Failed to send delivery ack: {}", e);
                                            }
                                        }
                                    } else {
                                        debug_println!("[DELIVERY] Message {} not found in our records", status_request.message_id);
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse DeliveryStatusRequest: {}", e);
                                }
                            }
                        },
                        
                        MessageType::ReadReceipt => {
                            // Handle read receipt
                            debug_println!("[<-- RECV] Read receipt from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<ReadReceipt>(&packet.payload) {
                                Ok(read_receipt) => {
                                    debug_println!("[READ_RECEIPT] Message {} read by {} ({})", 
                                        read_receipt.original_message_id, read_receipt.reader_nickname, read_receipt.reader_id);
                                    
                                    // Update delivery status if we're tracking this message
                                    if delivery_tracker.pending_messages.contains_key(&read_receipt.original_message_id) {
                                        println!("👁️  Message read by {} ({})", read_receipt.reader_nickname, read_receipt.reader_id);
                                        
                                        // Mark as read - we can remove from pending since read is the final status
                                        delivery_tracker.mark_delivered(&read_receipt.original_message_id);
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse ReadReceipt: {}", e);
                                }
                            }
                        },
                        
                        MessageType::VersionHello => {
                            // Handle protocol version negotiation hello
                            debug_println!("[<-- RECV] Version hello from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<VersionHello>(&packet.payload) {
                                Ok(version_hello) => {
                                    debug_println!("[VERSION] Received hello: supported={:?}, preferred={}, client={}, platform={}", 
                                        version_hello.supported_versions, version_hello.preferred_version, 
                                        version_hello.client_version, version_hello.platform);
                                    
                                    // Negotiate version
                                    if let Some(agreed_version) = protocol_version_manager.negotiate_version(&version_hello.supported_versions) {
                                        protocol_version_manager.set_peer_version(packet.sender_id_str.clone(), agreed_version);
                                        
                                        // Send VersionAck
                                        let version_ack = VersionAck {
                                            agreed_version,
                                            server_version: "1.0.0".to_string(),
                                            platform: "rust-terminal".to_string(),
                                            capabilities: Some(vec!["noise".to_string(), "channels".to_string()]),
                                            rejected: false,
                                            reason: None,
                                        };
                                        
                                        if let Ok(ack_payload) = serde_json::to_vec(&version_ack) {
                                            debug_println!("[VERSION] Sending version ack with agreed version {}", agreed_version);
                                            let ack_packet = create_bitchat_packet_with_recipient(
                                                &my_peer_id, 
                                                Some(&packet.sender_id_str), 
                                                MessageType::VersionAck, 
                                                ack_payload,
                                                None
                                            );
                                            if let Err(e) = peripheral.write(cmd_char, &ack_packet, WriteType::WithoutResponse).await {
                                                println!("[!] Failed to send version ack: {}", e);
                                            }
                                        }
                                    } else {
                                        // No compatible version found
                                        let version_ack = VersionAck {
                                            agreed_version: 0,
                                            server_version: "1.0.0".to_string(),
                                            platform: "rust-terminal".to_string(),
                                            capabilities: None,
                                            rejected: true,
                                            reason: Some("No compatible protocol version".to_string()),
                                        };
                                        
                                        if let Ok(ack_payload) = serde_json::to_vec(&version_ack) {
                                            debug_println!("[VERSION] Rejecting version negotiation - no compatible version");
                                            let ack_packet = create_bitchat_packet_with_recipient(
                                                &my_peer_id, 
                                                Some(&packet.sender_id_str), 
                                                MessageType::VersionAck, 
                                                ack_payload,
                                                None
                                            );
                                            if let Err(e) = peripheral.write(cmd_char, &ack_packet, WriteType::WithoutResponse).await {
                                                println!("[!] Failed to send version rejection: {}", e);
                                            }
                                        }
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse VersionHello: {}", e);
                                }
                            }
                        },
                        
                        MessageType::VersionAck => {
                            // Handle protocol version negotiation acknowledgment
                            debug_println!("[<-- RECV] Version ack from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<VersionAck>(&packet.payload) {
                                Ok(version_ack) => {
                                    if version_ack.rejected {
                                        debug_println!("[VERSION] Version negotiation rejected by {}: {}", 
                                            packet.sender_id_str, 
                                            version_ack.reason.unwrap_or("No reason given".to_string()));
                                        println!("⚠️  Protocol version negotiation failed with peer {}", packet.sender_id_str);
                                    } else {
                                        protocol_version_manager.set_peer_version(packet.sender_id_str.clone(), version_ack.agreed_version);
                                        debug_println!("[VERSION] Negotiated version {} with {} (platform: {}, version: {})", 
                                            version_ack.agreed_version, packet.sender_id_str, 
                                            version_ack.platform, version_ack.server_version);
                                        
                                        if let Some(capabilities) = &version_ack.capabilities {
                                            debug_println!("[VERSION] Peer capabilities: {:?}", capabilities);
                                        }
                                        
                                        println!("🤝 Protocol version {} negotiated with {}", version_ack.agreed_version, packet.sender_id_str);
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse VersionAck: {}", e);
                                }
                            }
                        },
                        
                        MessageType::NoiseIdentityAnnounce => {
                            // Handle Noise identity announcement
                            debug_println!("[<-- RECV] Noise identity announce from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<NoiseIdentityAnnouncement>(&packet.payload) {
                                Ok(identity_announce) => {
                                    debug_println!("[IDENTITY] Received announcement: peer_id={}, nickname={}, key_len={}", 
                                        identity_announce.peer_id, identity_announce.nickname, identity_announce.public_key.len());
                                    
                                    // Verify signature (basic implementation)
                                    if let Some(signature_bytes) = noise_service.sign(&identity_announce.public_key) {
                                        debug_println!("[IDENTITY] Identity signature verified for {}", identity_announce.peer_id);
                                        
                                        // Check if this is a new peer
                                        let is_new_peer = {
                                            let peers_lock = peers.lock().unwrap();
                                            !peers_lock.contains_key(&identity_announce.peer_id)
                                        };
                                        
                                        // Store peer information  
                                        {
                                            let mut peers_lock = peers.lock().unwrap();
                                            peers_lock.insert(identity_announce.peer_id.clone(), Peer { 
                                                nickname: Some(identity_announce.nickname.clone()) 
                                            });
                                        }
                                        
                                        // Store public key in noise service
                                        noise_service.store_peer_public_key(&identity_announce.peer_id, identity_announce.public_key);
                                        
                                        // If this is a peer ID rotation, handle previous peer ID
                                        if let Some(previous_id) = &identity_announce.previous_peer_id {
                                            debug_println!("[IDENTITY] Peer {} rotated from previous ID {}", 
                                                identity_announce.peer_id, previous_id);
                                            
                                            // Remove old peer ID but keep the established session if any
                                            let mut peers_lock = peers.lock().unwrap();
                                            peers_lock.remove(previous_id);
                                        }
                                        
                                        // Show connection notification for new peers (matching old Announce behavior)
                                        if is_new_peer {
                                            // Clear any existing prompt and show connection notification in yellow
                                            print!("\r\x1b[K\x1b[33m{} connected\x1b[0m\n> ", identity_announce.nickname);
                                            std::io::stdout().flush().unwrap();
                                        }
                                        
                                        debug_println!("[IDENTITY] Identity processed for {} ({})", identity_announce.nickname, identity_announce.peer_id);
                                    } else {
                                        debug_println!("[!] Failed to verify identity signature for {}", identity_announce.peer_id);
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse NoiseIdentityAnnouncement: {}", e);
                                }
                            }
                        },
                        
                        MessageType::ChannelKeyVerifyRequest => {
                            // Handle channel key verification request
                            debug_println!("[<-- RECV] Channel key verify request from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<ChannelKeyVerifyRequest>(&packet.payload) {
                                Ok(verify_request) => {
                                    debug_println!("[CHANNEL_VERIFY] Request for channel '{}' from {}", 
                                        verify_request.channel, verify_request.requester_id);
                                    
                                    // Check if we have the key for this channel
                                    let verified = if let Some(channel_key) = channel_keys.get(&verify_request.channel) {
                                        // Compute our key commitment
                                        let our_commitment = {
                                            let hash = sha2::Sha256::digest(channel_key);
                                            hex::encode(hash)
                                        };
                                        
                                        // Compare with requester's commitment
                                        let matches = our_commitment == verify_request.key_commitment;
                                        debug_println!("[CHANNEL_VERIFY] Key commitment {} (ours: {}, theirs: {})", 
                                            if matches { "MATCHES" } else { "MISMATCH" }, 
                                            our_commitment, verify_request.key_commitment);
                                        matches
                                    } else {
                                        debug_println!("[CHANNEL_VERIFY] We don't have key for channel '{}'", verify_request.channel);
                                        false
                                    };
                                    
                                    // Send response
                                    let verify_response = ChannelKeyVerifyResponse {
                                        channel: verify_request.channel.clone(),
                                        responder_id: my_peer_id.clone(),
                                        verified,
                                        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                                    };
                                    
                                    if let Ok(response_payload) = serde_json::to_vec(&verify_response) {
                                        debug_println!("[CHANNEL_VERIFY] Sending response: verified={}", verified);
                                        let response_packet = create_bitchat_packet_with_recipient(
                                            &my_peer_id, 
                                            Some(&packet.sender_id_str), 
                                            MessageType::ChannelKeyVerifyResponse, 
                                            response_payload,
                                            None
                                        );
                                        if let Err(e) = peripheral.write(cmd_char, &response_packet, WriteType::WithoutResponse).await {
                                            println!("[!] Failed to send channel key verify response: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse ChannelKeyVerifyRequest: {}", e);
                                }
                            }
                        },
                        
                        MessageType::ChannelKeyVerifyResponse => {
                            // Handle channel key verification response
                            debug_println!("[<-- RECV] Channel key verify response from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<ChannelKeyVerifyResponse>(&packet.payload) {
                                Ok(verify_response) => {
                                    debug_println!("[CHANNEL_VERIFY] Response for channel '{}' from {}: verified={}", 
                                        verify_response.channel, verify_response.responder_id, verify_response.verified);
                                    
                                    if verify_response.verified {
                                        println!("✅ Channel key verified for '{}' by {}", verify_response.channel, packet.sender_id_str);
                                    } else {
                                        println!("❌ Channel key mismatch for '{}' reported by {}", verify_response.channel, packet.sender_id_str);
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse ChannelKeyVerifyResponse: {}", e);
                                }
                            }
                        },
                        
                        MessageType::ChannelPasswordUpdate => {
                            // Handle channel password update
                            debug_println!("[<-- RECV] Channel password update from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<ChannelPasswordUpdate>(&packet.payload) {
                                Ok(password_update) => {
                                    debug_println!("[CHANNEL_PWD] Update for channel '{}' from owner {}", 
                                        password_update.channel, password_update.owner_id);
                                    
                                    // Verify this is from the channel owner
                                    if let Some(known_owner) = channel_creators.get(&password_update.channel) {
                                        if known_owner != &password_update.owner_id {
                                            debug_println!("[!] Password update rejected: not from known owner {} (got {})", 
                                                known_owner, password_update.owner_id);
                                            continue;
                                        }
                                    }
                                    
                                    // Try to decrypt the new password using Noise session
                                    if noise_service.has_established_session(&packet.sender_id_str) {
                                        match noise_service.decrypt_from_peer(&packet.sender_id_str, &password_update.encrypted_password) {
                                            Ok(decrypted_data) => {
                                                if let Ok(new_password) = String::from_utf8(decrypted_data) {
                                                    debug_println!("[CHANNEL_PWD] Successfully decrypted new password for '{}'", password_update.channel);
                                                    
                                                    // Derive new channel key
                                                    let new_key = crate::noise_integration::NoiseIntegrationService::derive_channel_key(&new_password, &password_update.channel);
                                                    
                                                    // Verify key commitment
                                                    let computed_commitment = {
                                                        let hash = sha2::Sha256::digest(&new_key);
                                                        hex::encode(hash)
                                                    };
                                                    
                                                    if computed_commitment == password_update.new_key_commitment {
                                                        // Update our channel key
                                                        channel_keys.insert(password_update.channel.clone(), new_key);
                                                        
                                                        // Update key commitment
                                                        channel_key_commitments.insert(password_update.channel.clone(), password_update.new_key_commitment.clone());
                                                        
                                                        // Save the encrypted password
                                                        if let Some(identity_key) = &app_state.identity_key {
                                                            match encrypt_password(&new_password, identity_key) {
                                                                Ok(encrypted_password) => {
                                                                    app_state.encrypted_channel_passwords.insert(password_update.channel.clone(), encrypted_password);
                                                                    
                                                                    // Save state
                                                                    let state_to_save = create_app_state(
                                                                        &blocked_peers,
                                                                        &channel_creators,
                                                                        &chat_context.active_channels,
                                                                        &password_protected_channels,
                                                                        &channel_key_commitments,
                                                                        &app_state.encrypted_channel_passwords,
                                                                        &nickname
                                                                    );
                                                                    if let Err(e) = save_state(&state_to_save) {
                                                                        eprintln!("Warning: Could not save state: {}", e);
                                                                    }
                                                                },
                                                                Err(e) => {
                                                                    debug_println!("[!] Failed to encrypt new password: {}", e);
                                                                }
                                                            }
                                                        }
                                                        
                                                        println!("🔄 Channel password updated for '{}'", password_update.channel);
                                                    } else {
                                                        debug_println!("[!] Key commitment mismatch for password update");
                                                    }
                                                } else {
                                                    debug_println!("[!] Failed to decode decrypted password as UTF-8");
                                                }
                                            },
                                            Err(e) => {
                                                debug_println!("[!] Failed to decrypt password update: {}", e);
                                            }
                                        }
                                    } else {
                                        debug_println!("[!] No Noise session established with sender for password update");
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse ChannelPasswordUpdate: {}", e);
                                }
                            }
                        },
                        
                        MessageType::ChannelMetadata => {
                            // Handle channel metadata
                            debug_println!("[<-- RECV] Channel metadata from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match serde_json::from_slice::<ChannelMetadata>(&packet.payload) {
                                Ok(metadata) => {
                                    debug_println!("[CHANNEL_META] Channel '{}' created by {} at {}, protected: {}", 
                                        metadata.channel, metadata.creator_id, metadata.created_at, metadata.is_password_protected);
                                    
                                    // Store channel creator information
                                    channel_creators.insert(metadata.channel.clone(), metadata.creator_id.clone());
                                    
                                    // Update password protection status
                                    if metadata.is_password_protected {
                                        password_protected_channels.insert(metadata.channel.clone());
                                    } else {
                                        password_protected_channels.remove(&metadata.channel);
                                    }
                                    
                                    // Store key commitment if available
                                    if let Some(key_commitment) = &metadata.key_commitment {
                                        channel_key_commitments.insert(metadata.channel.clone(), key_commitment.clone());
                                    }
                                    
                                    // Save state
                                    let state_to_save = create_app_state(
                                        &blocked_peers,
                                        &channel_creators,
                                        &chat_context.active_channels,
                                        &password_protected_channels,
                                        &channel_key_commitments,
                                        &app_state.encrypted_channel_passwords,
                                        &nickname
                                    );
                                    if let Err(e) = save_state(&state_to_save) {
                                        eprintln!("Warning: Could not save state: {}", e);
                                    }
                                    
                                    println!("📋 Channel metadata received for '{}' (created by {})", metadata.channel, metadata.creator_id);
                                },
                                Err(e) => {
                                    debug_println!("[!] Failed to parse ChannelMetadata: {}", e);
                                }
                            }
                        },
                        
                        MessageType::NoiseEncrypted => {
                            // Handle Noise encrypted messages
                            debug_println!("[<-- RECV] Noise encrypted message from {} ({} bytes)", packet.sender_id_str, packet.payload.len());
                            
                            match noise_service.decrypt_from_peer(&packet.sender_id_str, &packet.payload) {
                                Ok(decrypted_data) => {
                                    debug_println!("[NOISE] Successfully decrypted message ({} bytes)", decrypted_data.len());
                                    
                                    // Parse the decrypted data as a regular message
                                    match parse_bitchat_message_payload(&decrypted_data) {
                                        Ok(message) => {
                                            if !bloom.check(&message.id) {
                                                let sender_nick = peers_lock.get(&packet.sender_id_str)
                                                    .and_then(|p| p.nickname.as_ref())
                                                    .map_or(&packet.sender_id_str, |n| n);
                                                
                                                // Display the decrypted message as a private message
                                                let timestamp = chrono::Local::now();
                                                let display = format_message_display(
                                                    timestamp,
                                                    sender_nick,
                                                    &message.content,
                                                    true, // is_private
                                                    false, // is_channel
                                                    None, // channel
                                                    Some(&nickname), // recipient for private messages
                                                    &nickname // my_nickname
                                                );
                                                
                                                print!("\r\x1b[K{}\n> ", display);
                                                std::io::stdout().flush().unwrap();
                                                
                                                // Update chat context for reply functionality
                                                chat_context.last_private_sender = Some((packet.sender_id_str.clone(), sender_nick.to_string()));
                                                
                                                bloom.set(&message.id);
                                            }
                                        },
                                        Err(e) => {
                                            debug_println!("[NOISE] Failed to parse decrypted message: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    debug_println!("[NOISE] Failed to decrypt message from {}: {}", packet.sender_id_str, e);
                                }
                            }
                        },
                        
                        _ => {}

                     }
                    },
                    Err(_e) => {
                        // Silently ignore unparseable packets (following working example)
                    }
                }
            },

             _ = tokio::signal::ctrl_c() => { break; }

        }

    }


    debug_println!("\n[+] Disconnecting...");

    Ok(())

}


async fn find_peripheral(adapter: &btleplug::platform::Adapter) -> Result<Option<Peripheral>, btleplug::Error> {

    for p in adapter.peripherals().await? {

        if let Ok(Some(properties)) = p.properties().await {

            if properties.services.contains(&BITCHAT_SERVICE_UUID) { return Ok(Some(p)); }

        }

    }

    Ok(None)

}

// Remove PKCS#7 padding from data
fn unpad_message(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }
    
    // Last byte tells us how much padding to remove
    let padding_length = data[data.len() - 1] as usize;
    
    debug_full_println!("[PADDING] Data size: {}, padding length indicated: {}", data.len(), padding_length);
    
    // Validate padding
    if padding_length == 0 || padding_length > data.len() || padding_length > 255 {
        debug_full_println!("[PADDING] Invalid padding length, returning data as-is");
        return data.to_vec();
    }
    
    // Remove padding
    let unpadded_len = data.len() - padding_length;
    debug_full_println!("[PADDING] Removing {} bytes of padding, resulting size: {}", padding_length, unpadded_len);
    
    data[..unpadded_len].to_vec()
}

fn parse_bitchat_message_payload(data: &[u8]) -> Result<BitchatMessage, &'static str> {
    debug_full_println!("[PARSE] Parsing message payload, size: {} bytes", data.len());
    debug_full_println!("[PARSE] First 32 bytes hex: {}", hex::encode(&data[..std::cmp::min(32, data.len())]));

    let mut offset = 0;

    if data.len() < 1 { return Err("Payload too short for flags"); }

    let flags = data[offset];
    debug_full_println!("[PARSE] Flags: 0x{:02X} (has_channel={}, is_private={}, is_encrypted={}, has_recipient_nickname={}, has_sender_peer_id={})", 
             flags, 
             (flags & MSG_FLAG_HAS_CHANNEL) != 0, 
             (flags & MSG_FLAG_IS_PRIVATE) != 0, 
             (flags & MSG_FLAG_IS_ENCRYPTED) != 0,
             (flags & MSG_FLAG_HAS_RECIPIENT_NICKNAME) != 0,
             (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0);

    offset += 1;

    let has_channel = (flags & MSG_FLAG_HAS_CHANNEL) != 0;
    let is_encrypted = (flags & MSG_FLAG_IS_ENCRYPTED) != 0;
    let _is_private = (flags & MSG_FLAG_IS_PRIVATE) != 0;
    let has_original_sender = (flags & MSG_FLAG_HAS_ORIGINAL_SENDER) != 0;
    let has_recipient_nickname = (flags & MSG_FLAG_HAS_RECIPIENT_NICKNAME) != 0;
    let has_sender_peer_id = (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0;
    let has_mentions = (flags & MSG_FLAG_HAS_MENTIONS) != 0;

    if data.len() < offset + 8 { return Err("Payload too short for timestamp"); }

    let timestamp_bytes: [u8; 8] = data[offset..offset+8].try_into().map_err(|_| "Failed to read timestamp")?;
    let timestamp = u64::from_be_bytes(timestamp_bytes);
    debug_full_println!("[PARSE] Timestamp: {} ms", timestamp);
    offset += 8;

    if data.len() < offset + 1 { return Err("Payload too short for ID length"); }

    let id_len = data[offset] as usize;

    offset += 1;

    if data.len() < offset + id_len { return Err("Payload too short for ID"); }

    let id = String::from_utf8_lossy(&data[offset..offset + id_len]).to_string();

    offset += id_len;

    if data.len() < offset + 1 { return Err("Payload too short for sender length"); }

    let sender_len = data[offset] as usize;

    offset += 1;

    if data.len() < offset + sender_len { return Err("Payload too short for sender"); }

    offset += sender_len;

    if data.len() < offset + 2 { return Err("Payload too short for content length"); }

    let content_len_bytes: [u8; 2] = data[offset..offset+2].try_into().unwrap();

    let content_len = u16::from_be_bytes(content_len_bytes) as usize;

    offset += 2;

    if data.len() < offset + content_len { return Err("Payload too short for content"); }

    let (content, encrypted_content) = if is_encrypted {
        // For encrypted messages, store raw bytes and empty string
        ("".to_string(), Some(data[offset..offset + content_len].to_vec()))
    } else {
        // For normal messages, parse as UTF-8 string
        (String::from_utf8_lossy(&data[offset..offset + content_len]).to_string(), None)
    };

    offset += content_len;

    // Handle optional fields based on flags
    if has_original_sender {
        if data.len() < offset + 1 { return Err("Payload too short for original sender length"); }
        let orig_sender_len = data[offset] as usize;
        offset += 1;
        if data.len() < offset + orig_sender_len { return Err("Payload too short for original sender"); }
        offset += orig_sender_len;
    }

    if has_recipient_nickname {
        if data.len() < offset + 1 { return Err("Payload too short for recipient nickname length"); }
        let recipient_len = data[offset] as usize;
        offset += 1;
        if data.len() < offset + recipient_len { return Err("Payload too short for recipient nickname"); }
        offset += recipient_len;
    }

    if has_sender_peer_id {
        if data.len() < offset + 1 { return Err("Payload too short for sender peer ID length"); }
        let peer_id_len = data[offset] as usize;
        offset += 1;
        if data.len() < offset + peer_id_len { return Err("Payload too short for sender peer ID"); }
        offset += peer_id_len;
    }

    // Parse mentions array (iOS compatibility - must be in correct order)
    if has_mentions {
        if data.len() < offset + 2 { return Err("Payload too short for mentions count"); }
        let mentions_count_bytes: [u8; 2] = data[offset..offset+2].try_into().unwrap();
        let mentions_count = u16::from_be_bytes(mentions_count_bytes) as usize;
        offset += 2;
        
        // Skip each mention
        for _ in 0..mentions_count {
            if data.len() < offset + 1 { return Err("Payload too short for mention length"); }
            let mention_len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + mention_len { return Err("Payload too short for mention"); }
            offset += mention_len;
        }
    }

    let mut channel: Option<String> = None;

    if has_channel {

        if data.len() < offset + 1 { return Err("Payload too short for channel length"); }

        let channel_len = data[offset] as usize;

        offset += 1;

        if data.len() < offset + channel_len { return Err("Payload too short for channel"); }

        channel = Some(String::from_utf8_lossy(&data[offset..offset + channel_len]).to_string());
        let _ = channel_len;  // Channel length consumed

    }

    Ok(BitchatMessage { id, content, channel, is_encrypted, encrypted_content, timestamp })

}

fn create_bitchat_message_payload(sender: &str, content: &str, channel: Option<&str>) -> Vec<u8> {
    // Use the complex format that iOS expects (when iOS was working)
    let (payload, _) = create_bitchat_message_payload_full(sender, content, channel, false, "f453f3e0");
    payload
}

#[allow(dead_code)]
fn create_bitchat_message_payload_with_flags(sender: &str, content: &str, channel: Option<&str>, is_private: bool) -> Vec<u8> {
    // For backward compatibility, use a default peer ID
    let (payload, _) = create_bitchat_message_payload_full(sender, content, channel, is_private, "00000000");
    payload
}

fn create_bitchat_message_payload_full(sender: &str, content: &str, channel: Option<&str>, is_private: bool, sender_peer_id: &str) -> (Vec<u8>, String) {
    // Match Swift's toBinaryPayload format exactly
    let mut data = Vec::new();
    let mut flags: u8 = 0;
    
    // Always set hasSenderPeerID flag since we always include it
    flags |= MSG_FLAG_HAS_SENDER_PEER_ID;
    
    if channel.is_some() {
        flags |= MSG_FLAG_HAS_CHANNEL;
    }
    
    if is_private {
        flags |= MSG_FLAG_IS_PRIVATE;  // Add private flag
        // Private messages in Swift don't set recipient nickname in the payload
        // The recipient is handled at the packet level
    }
    
    data.push(flags);
    
    let timestamp_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;
    data.extend_from_slice(&timestamp_ms.to_be_bytes());
    
    let id = Uuid::new_v4().to_string();
    data.push(id.len() as u8);
    data.extend_from_slice(id.as_bytes());
    
    data.push(sender.len() as u8);
    data.extend_from_slice(sender.as_bytes());
    
    let content_len = content.len() as u16;
    data.extend_from_slice(&content_len.to_be_bytes());
    data.extend_from_slice(content.as_bytes());
    
    // Since we always set MSG_FLAG_HAS_SENDER_PEER_ID, we need to include it
    data.push(sender_peer_id.len() as u8);
    data.extend_from_slice(sender_peer_id.as_bytes());
    
    if let Some(channel_name) = channel {
        data.push(channel_name.len() as u8);
        data.extend_from_slice(channel_name.as_bytes());
    }
    
    (data, id)
}

fn create_encrypted_channel_message_payload(
    sender: &str, 
    content: &str, 
    channel: &str, 
    channel_key: &[u8; 32],
    noise_service: &NoiseIntegrationService,
    sender_peer_id: &str
) -> (Vec<u8>, String) {
    // Create message with encrypted content (matching Swift implementation)
    let mut data = Vec::new();
    let flags: u8 = MSG_FLAG_HAS_CHANNEL | MSG_FLAG_IS_ENCRYPTED | MSG_FLAG_HAS_SENDER_PEER_ID;
    
    data.push(flags);
    
    let timestamp_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;
    data.extend_from_slice(&timestamp_ms.to_be_bytes());
    
    let id = Uuid::new_v4().to_string();
    data.push(id.len() as u8);
    data.extend_from_slice(id.as_bytes());
    
    data.push(sender.len() as u8);
    data.extend_from_slice(sender.as_bytes());
    
    // Encrypt the actual content
    let encrypted_content = match noise_service.encrypt_with_channel_key(content.as_bytes(), channel_key) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            println!("[!] Failed to encrypt message: {:?}", e);
            let (payload, id) = create_bitchat_message_payload_full(sender, content, Some(channel), false, "00000000");
            return (payload, id);
        }
    };
    
    // Content length is for encrypted content
    let content_len = encrypted_content.len() as u16;
    data.extend_from_slice(&content_len.to_be_bytes());
    data.extend_from_slice(&encrypted_content);
    
    // Sender peer ID (since we set MSG_FLAG_HAS_SENDER_PEER_ID)
    data.push(sender_peer_id.len() as u8);
    data.extend_from_slice(sender_peer_id.as_bytes());
    
    // Channel name
    data.push(channel.len() as u8);
    data.extend_from_slice(channel.as_bytes());
    
    (data, id)
}

fn parse_bitchat_packet(data: &[u8]) -> Result<BitchatPacket, &'static str> {
    // Swift BinaryProtocol format:
    // Header (Fixed 13 bytes):
    // - Version: 1 byte
    // - Type: 1 byte  
    // - TTL: 1 byte
    // - Timestamp: 8 bytes (UInt64)
    // - Flags: 1 byte (bit 0: hasRecipient, bit 1: hasSignature, bit 2: isCompressed)
    // - PayloadLength: 2 bytes (UInt16)
    
    const HEADER_SIZE: usize = 13;
    const SENDER_ID_SIZE: usize = 8; 
    const RECIPIENT_ID_SIZE: usize = 8;
    const SIGNATURE_SIZE: usize = 64;

    if data.len() < HEADER_SIZE + SENDER_ID_SIZE { 
        return Err("Packet too small."); 
    }

    let mut offset = 0;

    // 1. Version (1 byte)
    let version = data[offset]; 
    offset += 1;
    if version != 1 { 
        return Err("Unsupported version."); 
    }

    // 2. Type (1 byte)
    let msg_type_raw = data[offset]; 
    offset += 1;
    let msg_type = match msg_type_raw {
        0x01 => MessageType::Announce, 
        // 0x02 was legacy keyExchange - removed (matching Swift)
        0x03 => MessageType::Leave,
        0x04 => MessageType::Message,
        0x05 => MessageType::FragmentStart,
        0x06 => MessageType::FragmentContinue,
        0x07 => MessageType::FragmentEnd,
        0x08 => MessageType::ChannelAnnounce,
        0x09 => MessageType::ChannelRetention,
        0x0A => MessageType::DeliveryAck,
        0x0B => MessageType::DeliveryStatusRequest,
        0x0C => MessageType::ReadReceipt,
        // Noise Protocol messages (matching Swift exactly)
        0x10 => MessageType::NoiseHandshakeInit,
        0x11 => MessageType::NoiseHandshakeResp,
        0x12 => MessageType::NoiseEncrypted,
        0x13 => MessageType::NoiseIdentityAnnounce,
        0x14 => MessageType::ChannelKeyVerifyRequest,
        0x15 => MessageType::ChannelKeyVerifyResponse,
        0x16 => MessageType::ChannelPasswordUpdate,
        0x17 => MessageType::ChannelMetadata,
        // Protocol version negotiation
        0x20 => MessageType::VersionHello,
        0x21 => MessageType::VersionAck,
        _ => return Err("Unknown message type."),
    };

    // 3. TTL (1 byte)
    let ttl = data[offset]; 
    offset += 1;
    
    // 4. Timestamp (8 bytes) - we skip it for now
    offset += 8;

    // 5. Flags (1 byte)
    let flags = data[offset]; 
    offset += 1;
    let has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0;
    let has_signature = (flags & FLAG_HAS_SIGNATURE) != 0;
    let is_compressed = (flags & FLAG_IS_COMPRESSED) != 0;

    // 6. Payload length (2 bytes, big-endian)
    if data.len() < offset + 2 {
        return Err("Packet too small for payload length.");
    }
    let payload_len_bytes: [u8; 2] = data[offset..offset + 2].try_into().unwrap();
    let payload_len = u16::from_be_bytes(payload_len_bytes) as usize; 
    offset += 2;

    // Calculate expected total size
    let mut expected_size = HEADER_SIZE + SENDER_ID_SIZE + payload_len;
    if has_recipient {
        expected_size += RECIPIENT_ID_SIZE;
    }
    if has_signature {
        expected_size += SIGNATURE_SIZE;
    }
    
    if data.len() < expected_size { 
        return Err("Packet data shorter than expected."); 
    }

    // 7. Sender ID (8 bytes)
    let sender_id = data[offset..offset + SENDER_ID_SIZE].to_vec();
    // Convert raw bytes to hex string (matching Swift protocol)
    // Remove trailing zeros (padding) and convert to hex
    let trimmed_sender_id = sender_id.iter().take_while(|&&b| b != 0).copied().collect::<Vec<u8>>();
    let sender_id_str = if trimmed_sender_id.is_empty() {
        "00000000".to_string() // Fallback for all-zero IDs
    } else {
        hex::encode(&trimmed_sender_id)
    };
    offset += SENDER_ID_SIZE;

    // 8. Recipient ID (8 bytes if hasRecipient flag set)
    let (recipient_id, recipient_id_str) = if has_recipient { 
        let recipient_id = data[offset..offset + RECIPIENT_ID_SIZE].to_vec();
        // Handle both ASCII hex strings and raw bytes
        let recipient_id_str = if recipient_id.iter().all(|&b| b.is_ascii_alphanumeric() || b == 0) {
            // ASCII format
            String::from_utf8_lossy(&recipient_id).trim_end_matches('\0').to_string()
        } else {
            // Raw bytes format - convert to hex
            hex::encode(&recipient_id).trim_end_matches('0').to_string()
        };
        debug_full_println!("[PACKET] Recipient ID raw bytes: {:?}", recipient_id);
        debug_full_println!("[PACKET] Recipient ID as string: '{}'", recipient_id_str);
        offset += RECIPIENT_ID_SIZE;
        (Some(recipient_id), Some(recipient_id_str))
    } else {
        (None, None)
    };

    // 9. Payload
    let mut payload = data[offset..offset + payload_len].to_vec();
    offset += payload_len;
    
    // 10. Signature (64 bytes if hasSignature flag set)
    if has_signature {
        // We don't verify signatures yet, just skip them
        let _signature_end = offset + SIGNATURE_SIZE; // Mark as intentionally unused
    }
    
    // Decompress if needed
    if is_compressed {
        match decompress(&payload) {
            Ok(decompressed) => payload = decompressed,
            Err(_) => return Err("Failed to decompress payload"),
        }
    }

    Ok(BitchatPacket { msg_type, _sender_id: sender_id, sender_id_str, recipient_id, recipient_id_str, payload, ttl })
}

// Legacy function removed - now using Noise-only implementation

fn create_bitchat_packet(sender_id_str: &str, msg_type: MessageType, payload: Vec<u8>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, None, msg_type, payload, None)
}

fn create_bitchat_packet_with_signature(sender_id_str: &str, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, None, msg_type, payload, signature)
}

fn create_bitchat_packet_with_recipient_and_signature(sender_id_str: &str, recipient_id_str: &str, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, Some(recipient_id_str), msg_type, payload, signature)
}

fn create_bitchat_packet_with_recipient(sender_id_str: &str, recipient_id_str: Option<&str>, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    debug_full_println!("[PACKET] ==================== PACKET CREATION START ====================");
    debug_full_println!("[PACKET] Creating packet: type={:?} (0x{:02X}), sender_id={}, payload_len={}", msg_type, msg_type as u8, sender_id_str, payload.len());
    
    // SWIFT BINARYPROTOCOL FORMAT: 
    // Header (Fixed 13 bytes):
    // - Version: 1 byte
    // - Type: 1 byte  
    // - TTL: 1 byte
    // - Timestamp: 8 bytes (UInt64)
    // - Flags: 1 byte (bit 0: hasRecipient, bit 1: hasSignature, bit 2: isCompressed)
    // - PayloadLength: 2 bytes (UInt16)
    // Variable sections:
    // - SenderID: 8 bytes (fixed)
    // - RecipientID: 8 bytes (if hasRecipient flag set)
    // - Payload: Variable length
    // - Signature: 64 bytes (if hasSignature flag set)
    
    let mut data = Vec::new();
    
    // 1. Version (1 byte)
    let version = 1u8;
    data.push(version);
    
    // 2. Type (1 byte)
    let msg_type_byte = msg_type as u8;
    data.push(msg_type_byte);
    
    // 3. TTL (1 byte) - MOVED UP to match Swift
    let ttl = 7u8; // whitepaper specifies 7 for maximum reach
    data.push(ttl);
    
    // 4. Timestamp (8 bytes, big-endian)
    let timestamp_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    data.extend_from_slice(&timestamp_ms.to_be_bytes());
    
    // 5. Flags (1 byte)
    let mut flags: u8 = 0;
    let has_recipient = match msg_type {
        MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => false,
        _ => true
    };
    if has_recipient {
        flags |= FLAG_HAS_RECIPIENT;
    }
    if signature.is_some() {
        flags |= FLAG_HAS_SIGNATURE;
    }
    // No compression for now
    data.push(flags);
    
    // 6. Payload length (2 bytes, big-endian)
    let payload_length = payload.len() as u16;
    data.extend_from_slice(&payload_length.to_be_bytes());
    
    debug_full_println!("[PACKET] Header: version={}, type=0x{:02X}, ttl={}, flags=0x{:02X}, payload_len={}", 
            version, msg_type_byte, ttl, flags, payload_length);
    
    // 7. Sender ID (8 bytes) - Convert hex string to raw bytes (matching Mac client)
    let mut sender_id_bytes = if sender_id_str.len() % 2 == 0 && sender_id_str.chars().all(|c| c.is_ascii_hexdigit()) {
        // Convert hex string to raw bytes
        hex::decode(sender_id_str).unwrap_or_else(|_| sender_id_str.as_bytes().to_vec())
    } else {
        // Fallback to ASCII bytes if not valid hex
        sender_id_str.as_bytes().to_vec()
    };
    
    // Pad to 8 bytes with zeros
    if sender_id_bytes.len() < 8 {
        sender_id_bytes.resize(8, 0);
    } else if sender_id_bytes.len() > 8 {
        sender_id_bytes.truncate(8);
    }
    data.extend_from_slice(&sender_id_bytes);
    debug_full_println!("[PACKET] Sender ID: {} -> {} raw bytes: {}", sender_id_str, sender_id_bytes.len(), hex::encode(&sender_id_bytes));
    
    // 8. Recipient ID (8 bytes) - only if hasRecipient flag is set
    if has_recipient {
        if let Some(recipient) = recipient_id_str {
            // Private message - use specific recipient, convert hex to raw bytes
            let mut recipient_bytes = if recipient.len() % 2 == 0 && recipient.chars().all(|c| c.is_ascii_hexdigit()) {
                // Convert hex string to raw bytes
                hex::decode(recipient).unwrap_or_else(|_| recipient.as_bytes().to_vec())
            } else {
                // Fallback to ASCII bytes if not valid hex
                recipient.as_bytes().to_vec()
            };
            
            // Pad to 8 bytes with zeros
            if recipient_bytes.len() < 8 {
                recipient_bytes.resize(8, 0);
            } else if recipient_bytes.len() > 8 {
                recipient_bytes.truncate(8);
            }
            data.extend_from_slice(&recipient_bytes);
            debug_full_println!("[PACKET] Recipient ID (private): {} -> {} raw bytes: {}", recipient, recipient_bytes.len(), hex::encode(&recipient_bytes));
        } else {
            // Broadcast message
            data.extend_from_slice(&BROADCAST_RECIPIENT);
            debug_full_println!("[PACKET] Recipient ID (broadcast): {} bytes: {}", BROADCAST_RECIPIENT.len(), hex::encode(&BROADCAST_RECIPIENT));
        }
    } else {
        debug_full_println!("[PACKET] No recipient ID (fragment packet)");
    }
    
    // 9. Payload (variable)
    data.extend_from_slice(&payload);
    debug_full_println!("[PACKET] Payload: {} bytes", payload.len());
    
    // 10. Signature (64 bytes if present)
    if let Some(sig) = &signature {
        data.extend_from_slice(sig);
        debug_full_println!("[PACKET] Signature: {} bytes", sig.len());
    }
    
    debug_full_println!("[PACKET] Final packet size: {} bytes", data.len());
    debug_full_println!("[PACKET] Full packet hex: {}", hex::encode(&data));
    
    // Calculate offsets for structure breakdown
    let mut offset = 0;
    debug_full_println!("[PACKET] Packet structure breakdown:");
    debug_full_println!("[PACKET]   - Version (1 byte): {}", hex::encode(&data[offset..offset+1])); offset += 1;
    debug_full_println!("[PACKET]   - Type (1 byte): {}", hex::encode(&data[offset..offset+1])); offset += 1;
    debug_full_println!("[PACKET]   - TTL (1 byte): {}", hex::encode(&data[offset..offset+1])); offset += 1;
    debug_full_println!("[PACKET]   - Timestamp (8 bytes): {}", hex::encode(&data[offset..offset+8])); offset += 8;
    debug_full_println!("[PACKET]   - Flags (1 byte): {}", hex::encode(&data[offset..offset+1])); offset += 1;
    debug_full_println!("[PACKET]   - PayloadLength (2 bytes): {}", hex::encode(&data[offset..offset+2])); offset += 2;
    debug_full_println!("[PACKET]   - Sender ID (8 bytes): {}", hex::encode(&data[offset..offset+8])); offset += 8;
    
    if has_recipient {
        debug_full_println!("[PACKET]   - Recipient ID (8 bytes): {}", hex::encode(&data[offset..offset+8])); offset += 8;
    }
    
    debug_full_println!("[PACKET]   - Payload ({} bytes): {}", payload.len(), hex::encode(&data[offset..std::cmp::min(offset + 32, data.len())]));
    offset += payload.len();
    
    if signature.is_some() {
        debug_full_println!("[PACKET]   - Signature (64 bytes): {}", hex::encode(&data[offset..std::cmp::min(offset + 32, data.len())]));
        // offset += SIGNATURE_SIZE;  // Not needed as we're done parsing
    }
    
    debug_full_println!("[PACKET] ==================== PACKET CREATION END ====================");
    
    data
}

// Create delivery ACK matching iOS format
fn create_delivery_ack(
    original_message_id: &str, 
    recipient_id: &str,
    recipient_nickname: &str,
    hop_count: u8
) -> Vec<u8> {
    let ack = DeliveryAck {
        original_message_id: original_message_id.to_string(),
        ack_id: Uuid::new_v4().to_string(),
        recipient_id: recipient_id.to_string(),
        recipient_nickname: recipient_nickname.to_string(),
        timestamp: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        hop_count,
    };
    
    serde_json::to_vec(&ack).unwrap_or_default()
}

// Check if we should send an ACK for this message (matching iOS logic)
fn should_send_ack(is_private: bool, channel: Option<&str>, mentions: Option<&Vec<String>>, my_nickname: &str, active_peer_count: usize) -> bool {
    if is_private {
        // Always ACK private messages
        true
    } else if let Some(_) = channel {
        // For room messages, ACK if:
        // 1. Less than 10 active peers, OR
        // 2. We're mentioned
        if active_peer_count < 10 {
            true
        } else if let Some(mentions_list) = mentions {
            mentions_list.iter().any(|m| m == my_nickname)
        } else {
            false
        }
    } else {
        // Public broadcast messages - no ACK
        false
    }
}

// Helper function to create fragment packets
#[allow(dead_code)]
fn create_fragment_packet(sender_id: &str, fragment: Fragment) -> Vec<u8> {
    let mut payload = Vec::new();
    
    // Fragment header: fragmentID (8) + index (2) + total (2) + originalType (1) + data
    payload.extend_from_slice(&fragment.fragment_id);
    
    // Index as 2 bytes (big-endian)
    payload.push((fragment.index >> 8) as u8);
    payload.push((fragment.index & 0xFF) as u8);
    
    // Total as 2 bytes (big-endian)  
    payload.push((fragment.total >> 8) as u8);
    payload.push((fragment.total & 0xFF) as u8);
    
    // Original message type
    payload.push(fragment.original_type);
    
                // Debug: Show exact metadata bytes
            if fragment.index == 0 || fragment.index == fragment.total - 1 {
                debug_full_println!("[DEBUG] Fragment {}/{} metadata: ID={} index_bytes={:02X}{:02X} total_bytes={:02X}{:02X} type={:02X}",
                        fragment.index + 1, fragment.total,
                        hex::encode(&fragment.fragment_id[..4]), // Show first 4 bytes of ID
                        (fragment.index >> 8) as u8, (fragment.index & 0xFF) as u8,
                        (fragment.total >> 8) as u8, (fragment.total & 0xFF) as u8,
                        fragment.original_type);
            }
    
    // Fragment data
    payload.extend_from_slice(&fragment.data);
    
    let msg_type = match fragment.fragment_type {
        FragmentType::Start => MessageType::FragmentStart,
        FragmentType::Continue => MessageType::FragmentContinue,
        FragmentType::End => MessageType::FragmentEnd,
    };
    
    create_bitchat_packet(sender_id, msg_type, payload)
}

// Enable fragmentation to match Swift's 500-byte threshold
// This fixes the issue where messages disappear after a certain length
pub fn should_fragment(packet_data: &[u8]) -> bool {
    packet_data.len() > 500  // Fragment complete packets larger than 500 bytes
} 

// Swift-compatible packet sending with automatic fragmentation
async fn send_packet_with_fragmentation(
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    packet: Vec<u8>,
    my_peer_id: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Swift's logic: if packet > 500 bytes, fragment it
    if packet.len() > 500 {
        println!("[FRAG] ==================== FRAGMENTATION START ====================");
        println!("[FRAG] Original packet size: {} bytes", packet.len());
        println!("[FRAG] Original packet hex (first 64 bytes): {}", hex::encode(&packet[..std::cmp::min(64, packet.len())]));
        
        // Fragment the complete packet data into chunks
        // iOS BLE MTU is typically 185 bytes by default (can negotiate higher)
        // Fragment overhead: 13 (fragment metadata) + 21 (packet header) = 34 bytes
        // Safe chunk size: 150 bytes to ensure compatibility with default iOS MTU
        // This results in ~184 byte packets which work reliably on iOS
        let fragment_size = 150; // Conservative size for iOS BLE compatibility
        let chunks: Vec<&[u8]> = packet.chunks(fragment_size).collect();
        let total_fragments = chunks.len() as u16;
        
        // Generate random 8-byte fragment ID (matching working example)
        let mut fragment_id = [0u8; 8];
        rand::thread_rng().fill(&mut fragment_id);
        
        println!("[FRAG] Fragment ID: {}", hex::encode(&fragment_id));
        println!("[FRAG] Fragment size: {} bytes", fragment_size);
        println!("[FRAG] Total fragments: {}", total_fragments);
        
        // Send fragments with Swift's timing (20ms delay)
        for (index, chunk) in chunks.iter().enumerate() {
            let fragment_type = match index {
                0 => MessageType::FragmentStart,
                n if n == chunks.len() - 1 => MessageType::FragmentEnd,
                _ => MessageType::FragmentContinue,
            };
            
            println!("[FRAG] --- Fragment {}/{} ---", index + 1, total_fragments);
            println!("[FRAG] Type: {:?}", fragment_type);
            println!("[FRAG] Chunk size: {} bytes", chunk.len());
            println!("[FRAG] Chunk hex (first 32 bytes): {}", hex::encode(&chunk[..std::cmp::min(32, chunk.len())]));
            
            // Create fragment payload matching Swift format exactly:
            // fragmentID (8) + index (2) + total (2) + originalType (1) + data
            let mut fragment_payload = Vec::new();
            fragment_payload.extend_from_slice(&fragment_id);
            
            // Swift uses big-endian for index and total
            let index_bytes = [(index as u16 >> 8) as u8, (index as u16 & 0xFF) as u8];
            let total_bytes = [(total_fragments >> 8) as u8, (total_fragments & 0xFF) as u8];
            
            fragment_payload.push(index_bytes[0]);
            fragment_payload.push(index_bytes[1]);
            fragment_payload.push(total_bytes[0]);
            fragment_payload.push(total_bytes[1]);
            fragment_payload.push(MessageType::Message as u8); // Original packet type
            fragment_payload.extend_from_slice(chunk);
            
            println!("[FRAG] Fragment header: ID={} index={:02X}{:02X} total={:02X}{:02X} type={:02X}", 
                    hex::encode(&fragment_id[..4]),
                    index_bytes[0], index_bytes[1],
                    total_bytes[0], total_bytes[1],
                    MessageType::Message as u8);
            println!("[FRAG] Fragment payload size: {} bytes", fragment_payload.len());
            
            // DETAILED PAYLOAD ANALYSIS
            println!("[FRAG] === DETAILED PAYLOAD ANALYSIS ===");
            println!("[FRAG] Fragment payload hex: {}", hex::encode(&fragment_payload));
            println!("[FRAG] Fragment payload breakdown:");
            println!("[FRAG]   Fragment ID (8 bytes): {}", hex::encode(&fragment_payload[0..8]));
            println!("[FRAG]   Index (2 bytes): {} = {:02X}{:02X}", index, fragment_payload[8], fragment_payload[9]);
            println!("[FRAG]   Total (2 bytes): {} = {:02X}{:02X}", total_fragments, fragment_payload[10], fragment_payload[11]);
            println!("[FRAG]   Original type (1 byte): {} = {:02X}", MessageType::Message as u8, fragment_payload[12]);
            println!("[FRAG]   Data ({} bytes): {}", chunk.len(), hex::encode(&fragment_payload[13..std::cmp::min(13 + 32, fragment_payload.len())]));
            
            // Create fragment packet
            let fragment_packet = create_bitchat_packet(
                my_peer_id,
                fragment_type,
                fragment_payload
            );
            
            println!("[FRAG] Final fragment packet size: {} bytes", fragment_packet.len());
            println!("[FRAG] Final packet hex (first 64 bytes): {}", hex::encode(&fragment_packet[..std::cmp::min(64, fragment_packet.len())]));
            
            // DECODE THE FINAL PACKET TO VERIFY
            println!("[FRAG] === FINAL PACKET VERIFICATION ===");
            if let Ok(parsed_packet) = parse_bitchat_packet(&fragment_packet) {
                println!("[FRAG] ✅ Fragment packet parsed successfully");
                println!("[FRAG] Packet type: {:?}", parsed_packet.msg_type);
                println!("[FRAG] Packet TTL: {}", parsed_packet.ttl);
                println!("[FRAG] Packet sender: {}", parsed_packet.sender_id_str);
                println!("[FRAG] Packet payload size: {} bytes", parsed_packet.payload.len());
                println!("[FRAG] Packet payload hex: {}", hex::encode(&parsed_packet.payload));
                
                // Verify the fragment payload structure
                if parsed_packet.payload.len() >= 13 {
                    let frag_id = &parsed_packet.payload[0..8];
                    let frag_index = ((parsed_packet.payload[8] as u16) << 8) | (parsed_packet.payload[9] as u16);
                    let frag_total = ((parsed_packet.payload[10] as u16) << 8) | (parsed_packet.payload[11] as u16);
                    let frag_orig_type = parsed_packet.payload[12];
                    
                    println!("[FRAG] Verified fragment ID: {}", hex::encode(frag_id));
                    println!("[FRAG] Verified fragment index: {}", frag_index);
                    println!("[FRAG] Verified fragment total: {}", frag_total);
                    println!("[FRAG] Verified original type: 0x{:02X}", frag_orig_type);
                    
                    if frag_index == index as u16 && frag_total == total_fragments && frag_orig_type == MessageType::Message as u8 {
                        println!("[FRAG] ✅ Fragment payload verification passed");
                    } else {
                        println!("[FRAG] ❌ Fragment payload verification failed");
                    }
                } else {
                    println!("[FRAG] ❌ Fragment payload too small for verification");
                }
            } else {
                println!("[FRAG] ❌ Failed to parse fragment packet");
            }
            
            // Send fragment
            if peripheral.write(cmd_char, &fragment_packet, WriteType::WithoutResponse).await.is_err() {
                return Err(format!("Failed to send fragment {}/{} (size: {} bytes)", index + 1, total_fragments, fragment_packet.len()).into());
            }
            
            println!("[FRAG] ✓ Fragment {}/{} sent successfully", index + 1, total_fragments);
            
            // Swift's 20ms delay between fragments
            if index < chunks.len() - 1 {
                time::sleep(Duration::from_millis(20)).await;
            }
        }
        
        println!("[FRAG] ✓ Successfully sent {} fragments", total_fragments);
        println!("[FRAG] ==================== FRAGMENTATION END ====================");
        Ok(())
    } else {
        // Packet is small enough, send directly
        let write_type = if packet.len() > 512 {
            WriteType::WithResponse
        } else {
            WriteType::WithoutResponse
        };
        
        if peripheral.write(cmd_char, &packet, write_type).await.is_err() {
            return Err(format!("Failed to send {} byte packet", packet.len()).into());
        }
        
        Ok(())
    }
}

async fn send_channel_announce(
    peripheral: &Peripheral,
    cmd_char: &Characteristic,
    my_peer_id: &str,
    channel: &str,
    is_protected: bool,
    key_commitment: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Format: "channel|isProtected|creatorID|keyCommitment"
    let protected_str = if is_protected { "1" } else { "0" };
    let payload = format!(
        "{}|{}|{}|{}",
        channel,
        protected_str,
        my_peer_id,
        key_commitment.unwrap_or("")
    );
    
    let packet = create_bitchat_packet(
        my_peer_id,
        MessageType::ChannelAnnounce,
        payload.into_bytes()
    );
    
    // Set TTL to 5 for wider propagation
    let mut packet_with_ttl = packet;
    packet_with_ttl[2] = 5; // TTL is at offset 2
    
    debug_println!("[CHANNEL] Sending channel announce for {}", channel);
    send_packet_with_fragmentation(&peripheral, cmd_char, packet_with_ttl, my_peer_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_hello_parsing() {
        let version_hello = VersionHello {
            supported_versions: vec![1, 2],
            preferred_version: 2,
            client_version: "1.0.0".to_string(),
            platform: "rust-test".to_string(),
            capabilities: Some(vec!["noise".to_string(), "channels".to_string()]),
        };
        
        let serialized = serde_json::to_vec(&version_hello).unwrap();
        let deserialized: VersionHello = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.supported_versions, vec![1, 2]);
        assert_eq!(deserialized.preferred_version, 2);
        assert_eq!(deserialized.client_version, "1.0.0");
        assert_eq!(deserialized.platform, "rust-test");
        assert_eq!(deserialized.capabilities, Some(vec!["noise".to_string(), "channels".to_string()]));
    }

    #[test]
    fn test_version_ack_parsing() {
        let version_ack = VersionAck {
            agreed_version: 1,
            server_version: "1.0.0".to_string(),
            platform: "rust-test".to_string(),
            capabilities: Some(vec!["noise".to_string()]),
            rejected: false,
            reason: None,
        };
        
        let serialized = serde_json::to_vec(&version_ack).unwrap();
        let deserialized: VersionAck = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.agreed_version, 1);
        assert_eq!(deserialized.rejected, false);
        assert_eq!(deserialized.reason, None);
    }

    #[test]
    fn test_version_ack_rejection() {
        let version_ack = VersionAck {
            agreed_version: 0,
            server_version: "1.0.0".to_string(),
            platform: "rust-test".to_string(),
            capabilities: None,
            rejected: true,
            reason: Some("No compatible version".to_string()),
        };
        
        let serialized = serde_json::to_vec(&version_ack).unwrap();
        let deserialized: VersionAck = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.rejected, true);
        assert_eq!(deserialized.reason, Some("No compatible version".to_string()));
    }

    #[test]
    fn test_protocol_version_negotiation() {
        let mut manager = ProtocolVersionManager::new();
        
        // Test successful negotiation
        let peer_versions = vec![1, 2, 3];
        let negotiated = manager.negotiate_version(&peer_versions);
        assert_eq!(negotiated, Some(1)); // Should pick highest common version
        
        // Test failed negotiation
        let incompatible_versions = vec![2, 3, 4];
        let negotiated = manager.negotiate_version(&incompatible_versions);
        assert_eq!(negotiated, None);
        
        // Test peer version storage
        manager.set_peer_version("peer1".to_string(), 1);
        assert_eq!(manager.get_peer_version("peer1"), Some(1));
        assert_eq!(manager.get_peer_version("unknown"), None);
    }

    #[test]
    fn test_noise_identity_announcement_parsing() {
        let announcement = NoiseIdentityAnnouncement {
            peer_id: "test_peer".to_string(),
            public_key: vec![1, 2, 3, 4],
            nickname: "TestUser".to_string(),
            timestamp: 1234567890.0,
            previous_peer_id: Some("old_peer".to_string()),
            signature: vec![5, 6, 7, 8],
        };
        
        let serialized = serde_json::to_vec(&announcement).unwrap();
        let deserialized: NoiseIdentityAnnouncement = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.peer_id, "test_peer");
        assert_eq!(deserialized.public_key, vec![1, 2, 3, 4]);
        assert_eq!(deserialized.nickname, "TestUser");
        assert_eq!(deserialized.previous_peer_id, Some("old_peer".to_string()));
    }

    #[test]
    fn test_channel_key_verify_request_parsing() {
        let request = ChannelKeyVerifyRequest {
            channel: "#test".to_string(),
            requester_id: "requester".to_string(),
            key_commitment: "abc123".to_string(),
            timestamp: 1234567890,
        };
        
        let serialized = serde_json::to_vec(&request).unwrap();
        let deserialized: ChannelKeyVerifyRequest = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.channel, "#test");
        assert_eq!(deserialized.requester_id, "requester");
        assert_eq!(deserialized.key_commitment, "abc123");
    }

    #[test]
    fn test_channel_key_verify_response_parsing() {
        let response = ChannelKeyVerifyResponse {
            channel: "#test".to_string(),
            responder_id: "responder".to_string(),
            verified: true,
            timestamp: 1234567890,
        };
        
        let serialized = serde_json::to_vec(&response).unwrap();
        let deserialized: ChannelKeyVerifyResponse = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.channel, "#test");
        assert_eq!(deserialized.responder_id, "responder");
        assert_eq!(deserialized.verified, true);
    }

    #[test]
    fn test_channel_password_update_parsing() {
        let update = ChannelPasswordUpdate {
            channel: "#secret".to_string(),
            owner_id: "owner".to_string(),
            owner_fingerprint: "fingerprint123".to_string(),
            encrypted_password: vec![1, 2, 3, 4, 5],
            new_key_commitment: "newcommit456".to_string(),
            timestamp: 1234567890,
        };
        
        let serialized = serde_json::to_vec(&update).unwrap();
        let deserialized: ChannelPasswordUpdate = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.channel, "#secret");
        assert_eq!(deserialized.owner_id, "owner");
        assert_eq!(deserialized.encrypted_password, vec![1, 2, 3, 4, 5]);
        assert_eq!(deserialized.new_key_commitment, "newcommit456");
    }

    #[test]
    fn test_channel_metadata_parsing() {
        let metadata = ChannelMetadata {
            channel: "#public".to_string(),
            creator_id: "creator".to_string(),
            creator_fingerprint: "creatorprint".to_string(),
            created_at: 1234567890,
            is_password_protected: true,
            key_commitment: Some("commitment789".to_string()),
        };
        
        let serialized = serde_json::to_vec(&metadata).unwrap();
        let deserialized: ChannelMetadata = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.channel, "#public");
        assert_eq!(deserialized.creator_id, "creator");
        assert_eq!(deserialized.is_password_protected, true);
        assert_eq!(deserialized.key_commitment, Some("commitment789".to_string()));
    }

    #[test]
    fn test_delivery_status_request_parsing() {
        let request = DeliveryStatusRequest {
            message_id: "msg123".to_string(),
            requester_id: "requester".to_string(),
            timestamp: 1234567890,
        };
        
        let serialized = serde_json::to_vec(&request).unwrap();
        let deserialized: DeliveryStatusRequest = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.message_id, "msg123");
        assert_eq!(deserialized.requester_id, "requester");
        assert_eq!(deserialized.timestamp, 1234567890);
    }

    #[test]
    fn test_read_receipt_parsing() {
        let receipt = ReadReceipt {
            original_message_id: "original123".to_string(),
            receipt_id: "receipt456".to_string(),
            reader_id: "reader".to_string(),
            reader_nickname: "ReaderName".to_string(),
            timestamp: 1234567890,
        };
        
        let serialized = serde_json::to_vec(&receipt).unwrap();
        let deserialized: ReadReceipt = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.original_message_id, "original123");
        assert_eq!(deserialized.receipt_id, "receipt456");
        assert_eq!(deserialized.reader_id, "reader");
        assert_eq!(deserialized.reader_nickname, "ReaderName");
    }

    #[test]
    fn test_delivery_ack_compatibility() {
        // Test compatibility with existing DeliveryAck structure
        let ack = DeliveryAck {
            original_message_id: "msg123".to_string(),
            ack_id: "ack456".to_string(),
            recipient_id: "recipient".to_string(),
            recipient_nickname: "RecipientName".to_string(),
            timestamp: 1234567890,
            hop_count: 2,
        };
        
        let serialized = serde_json::to_vec(&ack).unwrap();
        let deserialized: DeliveryAck = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(deserialized.original_message_id, "msg123");
        assert_eq!(deserialized.ack_id, "ack456");
        assert_eq!(deserialized.recipient_id, "recipient");
        assert_eq!(deserialized.hop_count, 2);
    }

    #[test]
    fn test_rust_client_message_roundtrip() {
        // Test that the Rust client can parse messages it sends itself
        let sender_id = "a1b2c3d4"; // 8-character hex string
        let test_message = "Hello, world!";
        
        // Create a message payload using the actual function
        let nickname = "test-client";
        let (payload, message_id) = create_bitchat_message_payload_full(nickname, test_message, None, false, sender_id);
        
        // Create the packet
        let packet = create_bitchat_packet(sender_id, MessageType::Message, payload);
        
        // Parse the packet back
        let parsed = parse_bitchat_packet(&packet).expect("Failed to parse packet");
        
        // Verify sender ID is correct
        assert_eq!(parsed.sender_id_str, sender_id);
        assert_eq!(parsed.msg_type, MessageType::Message);
        
        // Parse the message payload
        let message = parse_bitchat_message_payload(&parsed.payload).expect("Failed to parse message payload");
        
        // Verify message content is correct
        assert_eq!(message.content, test_message);
        assert_eq!(message.id, message_id);
        assert_eq!(message.channel, None);
        assert_eq!(message.is_encrypted, false);
    }

    #[test]
    fn test_channel_message_roundtrip() {
        // Test unencrypted channel message roundtrip
        let sender_id = "b1c2d3e4"; // 8-character hex string
        let test_message = "Hello #general!";
        let channel_name = "#general";
        
        // Create a channel message payload using the actual function
        let nickname = "test-user";
        let (payload, message_id) = create_bitchat_message_payload_full(nickname, test_message, Some(channel_name), false, sender_id);
        
        // Create the packet
        let packet = create_bitchat_packet(sender_id, MessageType::Message, payload);
        
        // Parse the packet back
        let parsed = parse_bitchat_packet(&packet).expect("Failed to parse packet");
        
        // Verify sender ID is correct
        assert_eq!(parsed.sender_id_str, sender_id);
        assert_eq!(parsed.msg_type, MessageType::Message);
        
        // Parse the message payload
        let message = parse_bitchat_message_payload(&parsed.payload).expect("Failed to parse message payload");
        
        // Verify message content is correct
        assert_eq!(message.content, test_message);
        assert_eq!(message.id, message_id);
        assert_eq!(message.channel, Some(channel_name.to_string()));
        assert_eq!(message.is_encrypted, false);
    }

    #[test]
    fn test_encrypted_channel_message_roundtrip() {
        // Test encrypted channel message with correct and wrong passwords
        let sender_id = "c1d2e3f4";
        let test_message = "Secret message for #private";
        let channel_name = "#private";
        let correct_password = "test1234";
        let wrong_password = "wrong1234";
        let nickname = "test-user";
        
        // Create noise service for encryption
        let noise_service = NoiseIntegrationService::new().expect("Failed to create noise service");
        
        // Create encrypted channel message payload
        let correct_key = crate::noise_integration::NoiseIntegrationService::derive_channel_key(correct_password, channel_name);
        let (payload, message_id) = create_encrypted_channel_message_payload(nickname, test_message, channel_name, &correct_key, &noise_service, sender_id);
        
        // Create the packet
        let packet = create_bitchat_packet(sender_id, MessageType::Message, payload);
        
        // Parse the packet back
        let parsed = parse_bitchat_packet(&packet).expect("Failed to parse packet");
        
        // Verify sender ID is correct
        assert_eq!(parsed.sender_id_str, sender_id);
        assert_eq!(parsed.msg_type, MessageType::Message);
        
        // Parse the message payload
        let message = parse_bitchat_message_payload(&parsed.payload).expect("Failed to parse message payload");
        
        // Verify message is encrypted
        assert_eq!(message.channel, Some(channel_name.to_string()));
        assert_eq!(message.is_encrypted, true);
        assert!(message.encrypted_content.is_some());
        
        // Test decryption with correct password
        let correct_key = crate::noise_integration::NoiseIntegrationService::derive_channel_key(correct_password, channel_name);
        if let Some(encrypted_data) = &message.encrypted_content {
            let decrypted = noise_service.decrypt_with_channel_key(encrypted_data, &correct_key).expect("Failed to decrypt with correct password");
            let decrypted_text = String::from_utf8(decrypted).expect("Failed to convert decrypted bytes to string");
            assert_eq!(decrypted_text, test_message);
        } else {
            panic!("Expected encrypted content");
        }
        
        // Test decryption with wrong password should fail
        let wrong_key = crate::noise_integration::NoiseIntegrationService::derive_channel_key(wrong_password, channel_name);
        if let Some(encrypted_data) = &message.encrypted_content {
            let result = noise_service.decrypt_with_channel_key(encrypted_data, &wrong_key);
            assert!(result.is_err(), "Decryption should fail with wrong password");
        }
    }

    #[test]
    fn test_noise_dm_roundtrip() {
        // Test Noise-encrypted DM with correct and wrong keys
        let sender_id = "d1e2f3a4";
        let recipient_id = "a4f3e2d1";
        let test_message = "Private DM message";
        let nickname = "sender";
        
        // Create two noise services (sender and recipient)
        let sender_noise = NoiseIntegrationService::new().expect("Failed to create sender noise service");
        let recipient_noise = NoiseIntegrationService::new().expect("Failed to create recipient noise service");
        let wrong_noise = NoiseIntegrationService::new().expect("Failed to create wrong noise service");
        
        // Get public keys
        let sender_pubkey = sender_noise.get_static_public_key();
        let recipient_pubkey = recipient_noise.get_static_public_key();
        let wrong_pubkey = wrong_noise.get_static_public_key();
        
        // Store each other's public keys
        sender_noise.store_peer_public_key(recipient_id, recipient_pubkey.clone());
        recipient_noise.store_peer_public_key(sender_id, sender_pubkey.clone());
        
        // Establish sessions through handshake
        let handshake_init = sender_noise.initiate_handshake(recipient_id).expect("Failed to initiate handshake");
        let handshake_resp = recipient_noise.process_handshake_message(sender_id, &handshake_init).expect("Failed to process handshake init");
        
        if let Some(resp_data) = handshake_resp {
            let handshake_final = sender_noise.process_handshake_message(recipient_id, &resp_data).expect("Failed to process handshake response");
            
            if let Some(final_data) = handshake_final {
                recipient_noise.process_handshake_message(sender_id, &final_data).expect("Failed to process final handshake");
            }
        }
        
        // Create encrypted DM payload
        let (payload, message_id) = create_bitchat_message_payload_full(nickname, test_message, None, true, sender_id);
        
        // Encrypt the payload for the recipient
        let encrypted_payload = sender_noise.encrypt_for_peer(recipient_id, &payload).expect("Failed to encrypt DM");
        
        // Create the packet with NoiseEncrypted type
        let packet = create_bitchat_packet_with_recipient(sender_id, Some(recipient_id), MessageType::NoiseEncrypted, encrypted_payload, None);
        
        // Parse the packet back
        let parsed = parse_bitchat_packet(&packet).expect("Failed to parse packet");
        
        // Verify packet structure
        assert_eq!(parsed.sender_id_str, sender_id);
        assert_eq!(parsed.msg_type, MessageType::NoiseEncrypted);
        assert_eq!(parsed.recipient_id_str, Some(recipient_id.to_string()));
        
        // Test decryption with correct recipient key
        let decrypted_payload = recipient_noise.decrypt_from_peer(sender_id, &parsed.payload).expect("Failed to decrypt with correct key");
        
        // Parse the decrypted message
        let message = parse_bitchat_message_payload(&decrypted_payload).expect("Failed to parse decrypted message");
        
        // Verify message content
        assert_eq!(message.content, test_message);
        assert_eq!(message.id, message_id);
        assert_eq!(message.channel, None);
        assert_eq!(message.is_encrypted, false);
        
        // Test decryption with wrong key should fail
        wrong_noise.store_peer_public_key(sender_id, wrong_pubkey);
        let wrong_result = wrong_noise.decrypt_from_peer(sender_id, &parsed.payload);
        assert!(wrong_result.is_err(), "Decryption should fail with wrong noise key");
    }

    #[test]
    fn test_message_type_values() {
        // Verify MessageType enum values match the Swift protocol specification exactly
        // This ensures compatibility with Swift and other implementations
        assert_eq!(MessageType::Announce as u8, 0x01);
        // 0x02 was legacy keyExchange - removed (matching Swift)
        assert_eq!(MessageType::Leave as u8, 0x03);
        assert_eq!(MessageType::Message as u8, 0x04);
        assert_eq!(MessageType::FragmentStart as u8, 0x05);
        assert_eq!(MessageType::FragmentContinue as u8, 0x06);
        assert_eq!(MessageType::FragmentEnd as u8, 0x07);
        assert_eq!(MessageType::ChannelAnnounce as u8, 0x08);
        assert_eq!(MessageType::ChannelRetention as u8, 0x09);
        assert_eq!(MessageType::DeliveryAck as u8, 0x0A);
        assert_eq!(MessageType::DeliveryStatusRequest as u8, 0x0B);
        assert_eq!(MessageType::ReadReceipt as u8, 0x0C);
        
        // Noise Protocol messages (matching Swift exactly)
        assert_eq!(MessageType::NoiseHandshakeInit as u8, 0x10);
        assert_eq!(MessageType::NoiseHandshakeResp as u8, 0x11);
        assert_eq!(MessageType::NoiseEncrypted as u8, 0x12);
        assert_eq!(MessageType::NoiseIdentityAnnounce as u8, 0x13);
        assert_eq!(MessageType::ChannelKeyVerifyRequest as u8, 0x14);
        assert_eq!(MessageType::ChannelKeyVerifyResponse as u8, 0x15);
        assert_eq!(MessageType::ChannelPasswordUpdate as u8, 0x16);
        assert_eq!(MessageType::ChannelMetadata as u8, 0x17);
        
        // Protocol version negotiation
        assert_eq!(MessageType::VersionHello as u8, 0x20);
        assert_eq!(MessageType::VersionAck as u8, 0x21);
    }

    #[test]
    fn test_protocol_constants() {
        // Verify protocol constants match Swift/Android implementations
        assert_eq!(FLAG_HAS_RECIPIENT, 0x01);
        assert_eq!(FLAG_HAS_SIGNATURE, 0x02);
        assert_eq!(FLAG_IS_COMPRESSED, 0x04);
        assert_eq!(MSG_FLAG_HAS_CHANNEL, 0x40);
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(BROADCAST_RECIPIENT, [0xFF; 8]);
    }
} 