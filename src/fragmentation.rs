use rand::Rng;

// This ensures fragments + headers stay under 512 byte block size
// BLE 5.0 supports up to 512 bytes MTU on iOS
#[allow(dead_code)]
const MAX_FRAGMENT_SIZE: usize = 460;  // Reduced to fit within 512 byte blocks

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum FragmentType {
    Start = 0x05,
    Continue = 0x06,
    End = 0x07,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Fragment {
    pub fragment_id: [u8; 8],
    pub fragment_type: FragmentType,
    pub index: u16,
    pub total: u16,
    pub original_type: u8,
    pub data: Vec<u8>,
}

// Helper function to convert fragment ID to hex string (matching Swift's hexEncodedString)
#[allow(dead_code)]
fn fragment_id_to_hex(fragment_id: &[u8; 8]) -> String {
    fragment_id.iter().map(|b| format!("{:02x}", b)).collect()
}

// Helper function to convert hex string back to fragment ID
#[allow(dead_code)]
fn hex_to_fragment_id(hex: &str) -> Result<[u8; 8], String> {
    if hex.len() != 16 {
        return Err("Invalid hex string length".to_string());
    }
    
    let mut fragment_id = [0u8; 8];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8")?;
        fragment_id[i] = u8::from_str_radix(hex_str, 16).map_err(|_| "Invalid hex")?;
    }
    
    Ok(fragment_id)
}

#[allow(dead_code)]
pub fn fragment_payload(payload: &[u8], original_msg_type: u8) -> Vec<Fragment> {
    if payload.len() <= MAX_FRAGMENT_SIZE {
        return vec![];
    }
    
    // Generate random 8 bytes for fragment ID (matching Swift's arc4random_buf)
    let mut fragment_id = [0u8; 8];
    rand::thread_rng().fill(&mut fragment_id);
    
    let chunks: Vec<&[u8]> = payload.chunks(MAX_FRAGMENT_SIZE).collect();
    let total = chunks.len() as u16;
    
    chunks.iter().enumerate().map(|(i, chunk)| {
        let fragment_type = match i {
            0 => FragmentType::Start,
            n if n == chunks.len() - 1 => FragmentType::End,
            _ => FragmentType::Continue,
        };
        
        Fragment {
            fragment_id,
            fragment_type,
            index: i as u16,
            total,
            original_type: original_msg_type,
            data: chunk.to_vec(),
        }
    }).collect()
} 
