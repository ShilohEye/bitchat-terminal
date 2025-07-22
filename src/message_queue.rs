#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

// Custom timestamp type that can be serialized
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Timestamp {
    secs_since_epoch: u64,
}

impl Timestamp {
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            secs_since_epoch: duration.as_secs(),
        }
    }
    
    pub fn elapsed(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Duration::from_secs(now.saturating_sub(self.secs_since_epoch))
    }
    
    pub fn duration_since(&self, earlier: Timestamp) -> Duration {
        Duration::from_secs(self.secs_since_epoch.saturating_sub(earlier.secs_since_epoch))
    }
    
    pub fn add_duration(&self, duration: Duration) -> Self {
        Self {
            secs_since_epoch: self.secs_since_epoch + duration.as_secs(),
        }
    }
}

impl From<SystemTime> for Timestamp {
    fn from(time: SystemTime) -> Self {
        let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        Self {
            secs_since_epoch: duration.as_secs(),
        }
    }
}

impl Into<SystemTime> for Timestamp {
    fn into(self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.secs_since_epoch)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub message_id: String,
    pub content: String,
    pub recipient_peer_id: String,
    pub recipient_nickname: String,
    pub timestamp: Timestamp,
    pub is_private: bool,
    pub retry_count: u32,
    pub channel: Option<String>,
    pub max_retries: u32,
    pub priority: MessagePriority,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl Default for MessagePriority {
    fn default() -> Self {
        MessagePriority::Normal
    }
}

impl QueuedMessage {
    pub fn new(
        message_id: String,
        content: String,
        recipient_peer_id: String,
        recipient_nickname: String,
        is_private: bool,
        channel: Option<String>,
    ) -> Self {
        Self {
            message_id,
            content,
            recipient_peer_id,
            recipient_nickname,
            timestamp: Timestamp::now(),
            is_private,
            retry_count: 0,
            channel,
            max_retries: 3,
            priority: MessagePriority::default(),
        }
    }
    
    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }
    
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }
    
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }
    
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
        self.timestamp = Timestamp::now(); // Reset timestamp for retry
    }
    
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.age() > timeout
    }
    
    pub fn has_retries_left(&self) -> bool {
        self.retry_count < self.max_retries
    }
    
    pub fn should_retry(&self, retry_timeout: Duration) -> bool {
        self.has_retries_left() && self.is_expired(retry_timeout)
    }
    
    pub fn get_next_retry_delay(&self) -> Duration {
        // Exponential backoff: 1s, 2s, 4s, 8s, etc.
        let base_delay = Duration::from_secs(1);
        let multiplier = 2_u32.pow(self.retry_count);
        base_delay * multiplier.min(60) // Cap at 60 seconds
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageQueueConfig {
    pub max_retries: u32,
    pub message_timeout: Duration,
    pub retry_timeout: Duration,
    pub max_queue_size_per_peer: usize,
    pub max_total_queue_size: usize,
    pub cleanup_interval: Duration,
}

impl Default for MessageQueueConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            message_timeout: Duration::from_secs(300), // 5 minutes
            retry_timeout: Duration::from_secs(30),     // 30 seconds
            max_queue_size_per_peer: 50,
            max_total_queue_size: 500,
            cleanup_interval: Duration::from_secs(60), // 1 minute
        }
    }
}

pub struct MessageQueue {
    pending_messages: HashMap<String, VecDeque<QueuedMessage>>, // peer_id -> msg
    config: MessageQueueConfig,
    last_cleanup: Timestamp,
    total_messages: usize,
}

impl MessageQueue {
    pub fn new() -> Self {
        Self::with_config(MessageQueueConfig::default())
    }
    
    pub fn with_config(config: MessageQueueConfig) -> Self {
        Self {
            pending_messages: HashMap::new(),
            config,
            last_cleanup: Timestamp::now(),
            total_messages: 0,
        }
    }
    
    pub fn queue_message(&mut self, mut message: QueuedMessage) -> bool {
        // Apply default config if not set
        if message.max_retries == 0 {
            message.max_retries = self.config.max_retries;
        }
        
        let peer_id = message.recipient_peer_id.clone();
        
        // Check total queue size limit
        if self.total_messages >= self.config.max_total_queue_size {
            self.evict_oldest_messages();
        }
        
        let queue = self.pending_messages.entry(peer_id).or_insert_with(VecDeque::new);
        
        // Check per-peer queue size limit
        if queue.len() >= self.config.max_queue_size_per_peer {
            // Remove oldest msg for this peer
            if queue.pop_front().is_some() {
                self.total_messages = self.total_messages.saturating_sub(1);
            }
        }
        
        // Insert msg in priority order (higher priority first)
        let insert_pos = queue.iter().position(|msg| msg.priority < message.priority)
            .unwrap_or(queue.len());
        
        queue.insert(insert_pos, message);
        self.total_messages += 1;
        
        true
    }
    
    pub fn get_pending_messages(&mut self, peer_id: &str) -> Vec<QueuedMessage> {
        if let Some(queue) = self.pending_messages.remove(peer_id) {
            let messages: Vec<QueuedMessage> = queue.into_iter().collect();
            self.total_messages = self.total_messages.saturating_sub(messages.len());
            messages
        } else {
            Vec::new()
        }
    }
    
    pub fn peek_pending_messages(&self, peer_id: &str) -> Vec<QueuedMessage> {
        self.pending_messages
            .get(peer_id)
            .map(|queue| queue.iter().cloned().collect())
            .unwrap_or_default()
    }
    
    pub fn has_pending_messages(&self, peer_id: &str) -> bool {
        self.pending_messages
            .get(peer_id)
            .map(|queue| !queue.is_empty())
            .unwrap_or(false)
    }
    
    pub fn get_total_queued(&self) -> usize {
        self.total_messages
    }
    
    pub fn get_queue_summary(&self) -> Vec<(String, usize)> {
        self.pending_messages
            .iter()
            .map(|(peer_id, queue)| (peer_id.clone(), queue.len()))
            .collect()
    }
    
    pub fn get_detailed_summary(&self) -> HashMap<String, Vec<QueuedMessage>> {
        self.pending_messages
            .iter()
            .map(|(peer_id, queue)| (peer_id.clone(), queue.iter().cloned().collect()))
            .collect()
    }
    
    pub fn get_priority_summary(&self) -> HashMap<MessagePriority, usize> {
        let mut summary = HashMap::new();
        
        for queue in self.pending_messages.values() {
            for message in queue {
                *summary.entry(message.priority).or_insert(0) += 1;
            }
        }
        
        summary
    }
    
    pub fn cleanup_expired(&mut self) {
        let now = Timestamp::now();
        let mut removed_count = 0;
        
        for queue in self.pending_messages.values_mut() {
            let original_len = queue.len();
            queue.retain(|msg| !msg.is_expired(self.config.message_timeout));
            removed_count += original_len - queue.len();
        }
        
        // Remove empty queues
        self.pending_messages.retain(|_, queue| !queue.is_empty());
        self.total_messages = self.total_messages.saturating_sub(removed_count);
        self.last_cleanup = now;
    }
    
    pub fn get_failed_deliveries(&mut self) -> Vec<QueuedMessage> {
        let mut failed = Vec::new();
        let mut removed_count = 0;
        
        for queue in self.pending_messages.values_mut() {
            let mut to_retry = VecDeque::new();
            
            while let Some(mut msg) = queue.pop_front() {
                if msg.should_retry(self.config.retry_timeout) {
                    msg.increment_retry();
                    failed.push(msg);
                    removed_count += 1;
                } else if msg.is_expired(self.config.message_timeout) {
                    // msg expired completely, drop it
                    removed_count += 1;
                } else {
                    // msg not ready for retry yet
                    to_retry.push_back(msg);
                }
            }
            
            *queue = to_retry;
        }
        
        // Remove empty queues
        self.pending_messages.retain(|_, queue| !queue.is_empty());
        self.total_messages = self.total_messages.saturating_sub(removed_count);
        
        failed
    }
    
    pub fn remove_message(&mut self, peer_id: &str, message_id: &str) -> bool {
        if let Some(queue) = self.pending_messages.get_mut(peer_id) {
            if let Some(pos) = queue.iter().position(|msg| msg.message_id == message_id) {
                queue.remove(pos);
                self.total_messages = self.total_messages.saturating_sub(1);
                
                // Remove empty queue
                if queue.is_empty() {
                    self.pending_messages.remove(peer_id);
                }
                
                return true;
            }
        }
        false
    }
    
    pub fn get_messages_for_peer(&self, peer_id: &str) -> Vec<QueuedMessage> {
        self.pending_messages
            .get(peer_id)
            .map(|queue| queue.iter().cloned().collect())
            .unwrap_or_default()
    }
    
    pub fn get_high_priority_messages(&mut self) -> Vec<(String, QueuedMessage)> {
        let mut high_priority = Vec::new();
        let mut removed_count = 0;
        
        for (peer_id, queue) in self.pending_messages.iter_mut() {
            let mut remaining = VecDeque::new();
            
            while let Some(msg) = queue.pop_front() {
                if msg.priority >= MessagePriority::High {
                    high_priority.push((peer_id.clone(), msg));
                    removed_count += 1;
                } else {
                    remaining.push_back(msg);
                }
            }
            
            *queue = remaining;
        }
        
        // Remove empty queues
        self.pending_messages.retain(|_, queue| !queue.is_empty());
        self.total_messages = self.total_messages.saturating_sub(removed_count);
        
        // Sort by priority (highest first)
        high_priority.sort_by(|a, b| b.1.priority.cmp(&a.1.priority));
        
        high_priority
    }
    
    pub fn should_cleanup(&self) -> bool {
        self.last_cleanup.elapsed() >= self.config.cleanup_interval
    }
    
    pub fn get_stats(&self) -> MessageQueueStats {
        let mut stats = MessageQueueStats::default();
        
        stats.total_messages = self.total_messages;
        stats.total_peers = self.pending_messages.len();
        
        for queue in self.pending_messages.values() {
            for message in queue {
                match message.priority {
                    MessagePriority::Critical => stats.critical_messages += 1,
                    MessagePriority::High => stats.high_priority_messages += 1,
                    MessagePriority::Normal => stats.normal_messages += 1,
                    MessagePriority::Low => stats.low_priority_messages += 1,
                }
                
                if message.is_private {
                    stats.private_messages += 1;
                } else {
                    stats.public_messages += 1;
                }
                
                if message.retry_count > 0 {
                    stats.retry_messages += 1;
                }
            }
        }
        
        stats
    }
    
    fn evict_oldest_messages(&mut self) {
        // Remove 10% of msg, starting with oldest and lowest priority
        let target_remove = (self.total_messages / 10).max(1);
        let mut removed = 0;
        
        // Collect all msg with their metadata for sorting
        let mut all_messages: Vec<(String, usize, QueuedMessage)> = Vec::new();
        
        for (peer_id, queue) in &self.pending_messages {
            for (index, message) in queue.iter().enumerate() {
                all_messages.push((peer_id.clone(), index, message.clone()));
            }
        }
        
        // Sort by priority (low first) then by age (old first)
        all_messages.sort_by(|a, b| {
            a.2.priority.cmp(&b.2.priority)
                .then_with(|| a.2.timestamp.secs_since_epoch.cmp(&b.2.timestamp.secs_since_epoch))
        });
        
        // Remove the oldest, lowest priority msg
        for (peer_id, _, _) in all_messages.iter().take(target_remove) {
            if let Some(queue) = self.pending_messages.get_mut(peer_id) {
                if queue.pop_front().is_some() {
                    removed += 1;
                }
            }
        }
        
        // Remove empty queues
        self.pending_messages.retain(|_, queue| !queue.is_empty());
        self.total_messages = self.total_messages.saturating_sub(removed);
    }
    
    pub fn clear(&mut self) {
        self.pending_messages.clear();
        self.total_messages = 0;
    }
    
    pub fn clear_peer(&mut self, peer_id: &str) -> usize {
        if let Some(queue) = self.pending_messages.remove(peer_id) {
            let count = queue.len();
            self.total_messages = self.total_messages.saturating_sub(count);
            count
        } else {
            0
        }
    }
}

impl Default for MessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default, Clone)]
pub struct MessageQueueStats {
    pub total_messages: usize,
    pub total_peers: usize,
    pub private_messages: usize,
    pub public_messages: usize,
    pub critical_messages: usize,
    pub high_priority_messages: usize,
    pub normal_messages: usize,
    pub low_priority_messages: usize,
    pub retry_messages: usize,
}

impl MessageQueueStats {
    pub fn print_summary(&self) {
        println!("  Message Queue Statistics:");
        println!("  Total messages: {}", self.total_messages);
        println!("  Total peers: {}", self.total_peers);
        println!("  Private: {}, Public: {}", self.private_messages, self.public_messages);
        println!("  Priority - Critical: {}, High: {}, Normal: {}, Low: {}", 
                 self.critical_messages, self.high_priority_messages, 
                 self.normal_messages, self.low_priority_messages);
        println!("  Messages with retries: {}", self.retry_messages);
    }
}

impl MessageQueue {
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::to_string_pretty(&self.pending_messages)?;
        std::fs::write(path, data)?;
        Ok(())
    }
    
    pub fn load_from_file(&mut self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        if path.exists() {
            let data = std::fs::read_to_string(path)?;
            let messages: HashMap<String, VecDeque<QueuedMessage>> = serde_json::from_str(&data)?;
            
            // Calculate total msg
            let total = messages.values().map(|queue| queue.len()).sum();
            
            self.pending_messages = messages;
            self.total_messages = total;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_queue_basic() {
        let mut queue = MessageQueue::new();
        
        let message = QueuedMessage::new(
            "msg1".to_string(),
            "Hello".to_string(),
            "peer1".to_string(),
            "Alice".to_string(),
            true,
            None,
        );
        
        assert!(queue.queue_message(message));
        assert_eq!(queue.get_total_queued(), 1);
        assert!(queue.has_pending_messages("peer1"));
        
        let messages = queue.get_pending_messages("peer1");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "Hello");
        assert_eq!(queue.get_total_queued(), 0);
    }
    
    #[test]
    fn test_message_priority() {
        let mut queue = MessageQueue::new();
        
        // Add msg with different priorities
        let normal_msg = QueuedMessage::new(
            "msg1".to_string(),
            "Normal".to_string(),
            "peer1".to_string(),
            "Alice".to_string(),
            false,
            None,
        );
        
        let high_msg = QueuedMessage::new(
            "msg2".to_string(),
            "High".to_string(),
            "peer1".to_string(),
            "Alice".to_string(),
            false,
            None,
        ).with_priority(MessagePriority::High);
        
        let critical_msg = QueuedMessage::new(
            "msg3".to_string(),
            "Critical".to_string(),
            "peer1".to_string(),
            "Alice".to_string(),
            false,
            None,
        ).with_priority(MessagePriority::Critical);
        
        // Add in reverse priority order
        queue.queue_message(normal_msg);
        queue.queue_message(high_msg);
        queue.queue_message(critical_msg);
        
        let messages = queue.get_pending_messages("peer1");
        assert_eq!(messages.len(), 3);
        
        // Should be ordered by priority (highest first)
        assert_eq!(messages[0].content, "Critical");
        assert_eq!(messages[1].content, "High");
        assert_eq!(messages[2].content, "Normal");
    }
    
    #[test]
    fn test_message_expiration() {
        let mut config = MessageQueueConfig::default();
        config.message_timeout = Duration::from_secs(1);
        
        let mut queue = MessageQueue::with_config(config);
        
        let mut message = QueuedMessage::new(
            "msg1".to_string(),
            "Test".to_string(),
            "peer1".to_string(),
            "Alice".to_string(),
            false,
            None,
        );
        
        // Manually set old timestamp
        message.timestamp = Timestamp {
            secs_since_epoch: 0, // Very old timestamp
        };
        
        queue.queue_message(message);
        assert_eq!(queue.get_total_queued(), 1);
        
        queue.cleanup_expired();
        assert_eq!(queue.get_total_queued(), 0);
    }
    
    #[test]
    fn test_retry_logic() {
        let mut config = MessageQueueConfig::default();
        config.retry_timeout = Duration::from_secs(0);
        config.max_retries = 2;
        
        let mut queue = MessageQueue::with_config(config);
        
        let mut message = QueuedMessage::new(
            "msg1".to_string(),
            "Test".to_string(),
            "peer1".to_string(),
            "Alice".to_string(),
            false,
            None,
        ).with_max_retries(2);
        
        message.timestamp = Timestamp {
            secs_since_epoch: 1,
        };
        
        queue.queue_message(message);
        
        let failed = queue.get_failed_deliveries();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].retry_count, 1);
        
        // Queue the failed msg again with old timestamp
        let mut retry_msg = failed[0].clone();
        retry_msg.timestamp = Timestamp { secs_since_epoch: 1 };
        queue.queue_message(retry_msg);
        
        let failed2 = queue.get_failed_deliveries();
        assert_eq!(failed2.len(), 1);
        assert_eq!(failed2[0].retry_count, 2);
        
        // Queue again should reach max retries and be dropped
        let mut final_retry = failed2[0].clone();
        final_retry.timestamp = Timestamp { secs_since_epoch: 1 };
        queue.queue_message(final_retry);
        
        let failed3 = queue.get_failed_deliveries();
        assert_eq!(failed3.len(), 0); // No more retries, msg dropped
    }
    
    #[test]
    fn test_queue_size_limits() {
        let mut config = MessageQueueConfig::default();
        config.max_queue_size_per_peer = 2;
        config.max_total_queue_size = 3;
        
        let mut queue = MessageQueue::with_config(config);
        
        // Add 3 msg for peer1 (should evict oldest)
        for i in 0..3 {
            let message = QueuedMessage::new(
                format!("msg{}", i),
                format!("Content {}", i),
                "peer1".to_string(),
                "Alice".to_string(),
                false,
                None,
            );
            queue.queue_message(message);
        }
        
        // Should only have 2 msg for peer1 (per-peer limit)
        assert_eq!(queue.get_messages_for_peer("peer1").len(), 2);
        
        // Add msg for peer2 - should trigger total limit
        let message = QueuedMessage::new(
            "msg_peer2".to_string(),
            "Content peer2".to_string(),
            "peer2".to_string(),
            "Bob".to_string(),
            false,
            None,
        );
        queue.queue_message(message);
        
        // Total should not exceed limit
        assert!(queue.get_total_queued() <= 3);
    }
    
    #[test]
    fn test_high_priority_extraction() {
        let mut queue = MessageQueue::new();
        
        // Add mix of priorities
        let messages = vec![
            ("Normal 1", MessagePriority::Normal),
            ("High 1", MessagePriority::High),
            ("Normal 2", MessagePriority::Normal),
            ("Critical 1", MessagePriority::Critical),
            ("High 2", MessagePriority::High),
        ];
        
        for (i, (content, priority)) in messages.iter().enumerate() {
            let message = QueuedMessage::new(
                format!("msg{}", i),
                content.to_string(),
                "peer1".to_string(),
                "Alice".to_string(),
                false,
                None,
            ).with_priority(*priority);
            queue.queue_message(message);
        }
        
        let high_priority = queue.get_high_priority_messages();
        assert_eq!(high_priority.len(), 3); // 1 Critical + 2 High
        
        // Should be sorted by priority (Critical first)
        assert_eq!(high_priority[0].1.content, "Critical 1");
        assert!(high_priority[1].1.content.starts_with("High"));
        assert!(high_priority[2].1.content.starts_with("High"));
        
        // Remaining msg should be Normal priority only
        let remaining = queue.get_messages_for_peer("peer1");
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().all(|msg| msg.priority == MessagePriority::Normal));
    }
    
    #[test]
    fn test_stats() {
        let mut queue = MessageQueue::new();
        
        // Add various types of msg
        let messages = vec![
            (true, MessagePriority::Critical),
            (false, MessagePriority::High),
            (true, MessagePriority::Normal),
            (false, MessagePriority::Low),
        ];
        
        for (i, (is_private, priority)) in messages.iter().enumerate() {
            let message = QueuedMessage::new(
                format!("msg{}", i),
                "Content".to_string(),
                "peer1".to_string(),
                "Alice".to_string(),
                *is_private,
                None,
            ).with_priority(*priority);
            queue.queue_message(message);
        }
        
        let stats = queue.get_stats();
        assert_eq!(stats.total_messages, 4);
        assert_eq!(stats.private_messages, 2);
        assert_eq!(stats.public_messages, 2);
        assert_eq!(stats.critical_messages, 1);
        assert_eq!(stats.high_priority_messages, 1);
        assert_eq!(stats.normal_messages, 1);
        assert_eq!(stats.low_priority_messages, 1);
    }
    
    #[test]
    fn test_serialization() {
        let mut queue = MessageQueue::new();
        
        let message = QueuedMessage::new(
            "msg1".to_string(),
            "Test message".to_string(),
            "peer1".to_string(),
            "Alice".to_string(),
            true,
            Some("#general".to_string()),
        ).with_priority(MessagePriority::High);
        
        queue.queue_message(message);
        
        // Test JSON serialization
        let json = serde_json::to_string(&queue.pending_messages).unwrap();
        assert!(json.contains("Test message"));
        assert!(json.contains("Alice"));
        assert!(json.contains("#general"));
        
        // Test deserialization
        let deserialized: HashMap<String, VecDeque<QueuedMessage>> = 
            serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.len(), 1);
        let peer_queue = deserialized.get("peer1").unwrap();
        assert_eq!(peer_queue.len(), 1);
        assert_eq!(peer_queue[0].content, "Test message");
        assert_eq!(peer_queue[0].priority, MessagePriority::High);
    }
}
