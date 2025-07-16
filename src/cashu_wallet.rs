use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bip39::rand::{thread_rng, Rng};
use bip39::Mnemonic;
use cdk::cdk_database;
use cdk::cdk_database::WalletDatabase;
use cdk::nuts::CurrencyUnit;
use cdk::wallet::{HttpClient, MultiMintWallet, Wallet, WalletBuilder, SendOptions};
use cdk::wallet::MintConnector;
use cdk::wallet::types::{WalletKey, SendKind};
use cdk::mint_url::MintUrl;
use cdk::Amount;
use cdk::amount::SplitTarget;
use cdk::nuts::{MintQuoteState, NotificationPayload};
use cdk::wallet::WalletSubscription;
use cdk_sqlite::WalletSqliteDatabase;
use cdk::nuts::Token;

const DEFAULT_CASHU_DIR: &str = ".bitchat";

#[derive(Debug, Clone)]
pub struct ClaimableToken {
    pub id: String,
    pub token: String,
    pub amount: u64,
    pub unit: String,
    pub mint_url: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug)]
pub struct ClaimableTokenManager {
    tokens: HashMap<String, ClaimableToken>,
}

impl ClaimableTokenManager {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    pub fn generate_token_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!("{:04}", rng.gen_range(1000..10000))
    }

    pub fn add_token(&mut self, token: String, amount: u64, unit: String, mint_url: String) -> String {
        let id = Self::generate_token_id();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let claimable = ClaimableToken {
            id: id.clone(),
            token,
            amount,
            unit,
            mint_url,
            created_at: current_time,
            expires_at: current_time + 3600, // 1 hour expiry
        };

        self.tokens.insert(id.clone(), claimable);
        id
    }

    pub fn claim_token(&mut self, id: &str) -> Option<String> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(claimable) = self.tokens.get(id) {
            if current_time > claimable.expires_at {
                self.tokens.remove(id);
                return None; // Token expired
            }
            
            let token = claimable.token.clone();
            self.tokens.remove(id);
            Some(token)
        } else {
            None
        }
    }

    pub fn cleanup_expired(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.tokens.retain(|_, token| current_time <= token.expires_at);
    }

    pub fn list_active_tokens(&self) -> Vec<(String, &ClaimableToken)> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.tokens
            .iter()
            .filter(|(_, token)| current_time <= token.expires_at)
            .map(|(id, token)| (id.clone(), token))
            .collect()
    }
}

pub fn print_ascii_token(id: &str, amount: u64, unit: &str, mint_url: &str) {
    println!("\n\x1b[33m╔═══════════════════════════════════════╗\x1b[0m");
    println!("\x1b[33m║\x1b[0m           \x1b[36m💰 CASHU TOKEN DROP\x1b[0m           \x1b[33m║\x1b[0m");
    println!("\x1b[33m╠═══════════════════════════════════════╣\x1b[0m");
    println!("\x1b[33m║\x1b[0m                                       \x1b[33m║\x1b[0m");
    println!("\x1b[33m║\x1b[0m    \x1b[32m┌─────────────────────────────┐\x1b[0m    \x1b[33m║\x1b[0m");
    
    // Format token ID with proper padding
    let token_line = format!("     TOKEN ID: {}     ", id);
    let padding = if token_line.len() < 29 {
        " ".repeat((29 - token_line.len()) / 2)
    } else {
        "".to_string()
    };
    let right_padding = if token_line.len() < 29 {
        " ".repeat(29 - token_line.len() - padding.len())
    } else {
        "".to_string()
    };
    
    println!("\x1b[33m║\x1b[0m    \x1b[32m│\x1b[0m{}\x1b[93m{}\x1b[0m{}\x1b[32m│\x1b[0m    \x1b[33m║\x1b[0m", padding, token_line.trim(), right_padding);
    println!("\x1b[33m║\x1b[0m    \x1b[32m└─────────────────────────────┘\x1b[0m    \x1b[33m║\x1b[0m");
    println!("\x1b[33m║\x1b[0m                                       \x1b[33m║\x1b[0m");
    
    // Format amount with proper padding
    let amount_line = format!("Amount: {} {}", amount, unit);
    let amount_padding = if amount_line.len() < 37 {
        " ".repeat((37 - amount_line.len()) / 2)
    } else {
        "".to_string()
    };
    let amount_right_padding = if amount_line.len() < 37 {
        " ".repeat(37 - amount_line.len() - amount_padding.len())
    } else {
        "".to_string()
    };
    
    println!("\x1b[33m║\x1b[0m{}\x1b[92m{}\x1b[0m{}\x1b[33m║\x1b[0m", amount_padding, amount_line, amount_right_padding);
    
    // Truncate mint URL if too long and format with proper padding
    let display_mint = if mint_url.len() > 30 {
        format!("{}...", &mint_url[..27])
    } else {
        mint_url.to_string()
    };
    let mint_line = format!("Mint: {}", display_mint);
    let mint_padding = if mint_line.len() < 37 {
        " ".repeat((37 - mint_line.len()) / 2)
    } else {
        "".to_string()
    };
    let mint_right_padding = if mint_line.len() < 37 {
        " ".repeat(37 - mint_line.len() - mint_padding.len())
    } else {
        "".to_string()
    };
    
    println!("\x1b[33m║\x1b[0m{}\x1b[90m{}\x1b[0m{}\x1b[33m║\x1b[0m", mint_padding, mint_line, mint_right_padding);
    
    println!("\x1b[33m║\x1b[0m                                       \x1b[33m║\x1b[0m");
    
    // Format claim instruction with proper padding
    let claim_line = format!("Type: /wallet claim {} to claim!", id);
    let claim_padding = if claim_line.len() < 37 {
        " ".repeat((37 - claim_line.len()) / 2)
    } else {
        "".to_string()
    };
    let claim_right_padding = if claim_line.len() < 37 {
        " ".repeat(37 - claim_line.len() - claim_padding.len())
    } else {
        "".to_string()
    };
    
    println!("\x1b[33m║\x1b[0m{}\x1b[96m{}\x1b[0m{}\x1b[33m║\x1b[0m", claim_padding, claim_line, claim_right_padding);
    println!("\x1b[33m║\x1b[0m                                       \x1b[33m║\x1b[0m");
    println!("\x1b[33m║\x1b[0m           \x1b[91m⏰ Expires in 1 hour\x1b[0m          \x1b[33m║\x1b[0m");
    println!("\x1b[33m╚═══════════════════════════════════════╝\x1b[0m\n");
}

pub fn print_token_claimed(id: &str, amount: u64, unit: &str) {
    println!("\n\x1b[32m╔═══════════════════════════════════════╗\x1b[0m");
    println!("\x1b[32m║\x1b[0m           \x1b[93m🎉 TOKEN CLAIMED!\x1b[0m            \x1b[32m║\x1b[0m");
    println!("\x1b[32m╠═══════════════════════════════════════╣\x1b[0m");
    println!("\x1b[32m║\x1b[0m                                       \x1b[32m║\x1b[0m");
    println!("\x1b[32m║\x1b[0m      You successfully claimed:         \x1b[32m║\x1b[0m");
    println!("\x1b[32m║\x1b[0m                                       \x1b[32m║\x1b[0m");
    
    // Format token ID with proper padding
    let token_id_line = format!("Token ID: {}", id);
    let token_id_padding = if token_id_line.len() < 37 {
        " ".repeat((37 - token_id_line.len()) / 2)
    } else {
        "".to_string()
    };
    let token_id_right_padding = if token_id_line.len() < 37 {
        " ".repeat(37 - token_id_line.len() - token_id_padding.len())
    } else {
        "".to_string()
    };
    
    println!("\x1b[32m║\x1b[0m{}\x1b[93m{}\x1b[0m{}\x1b[32m║\x1b[0m", token_id_padding, token_id_line, token_id_right_padding);
    
    // Format amount with proper padding
    let amount_line = format!("Amount: {} {}", amount, unit);
    let amount_padding = if amount_line.len() < 37 {
        " ".repeat((37 - amount_line.len()) / 2)
    } else {
        "".to_string()
    };
    let amount_right_padding = if amount_line.len() < 37 {
        " ".repeat(37 - amount_line.len() - amount_padding.len())
    } else {
        "".to_string()
    };
    
    println!("\x1b[32m║\x1b[0m{}\x1b[92m{}\x1b[0m{}\x1b[32m║\x1b[0m", amount_padding, amount_line, amount_right_padding);
    println!("\x1b[32m║\x1b[0m                                       \x1b[32m║\x1b[0m");
    println!("\x1b[32m║\x1b[0m    The token has been added to your    \x1b[32m║\x1b[0m");
    println!("\x1b[32m║\x1b[0m           Cashu wallet! 💰             \x1b[32m║\x1b[0m");
    println!("\x1b[32m╚═══════════════════════════════════════╝\x1b[0m\n");
}

pub fn print_active_tokens(tokens: &[(String, &ClaimableToken)]) {
    if tokens.is_empty() {
        println!("\n\x1b[90m╔═══════════════════════════════════════╗\x1b[0m");
        println!("\x1b[90m║\x1b[0m         \x1b[36m💰 CLAIMABLE TOKENS\x1b[0m          \x1b[90m║\x1b[0m");
        println!("\x1b[90m╠═══════════════════════════════════════╣\x1b[0m");
        println!("\x1b[90m║\x1b[0m                                       \x1b[90m║\x1b[0m");
        println!("\x1b[90m║\x1b[0m        No tokens available to         \x1b[90m║\x1b[0m");
        println!("\x1b[90m║\x1b[0m             claim right now           \x1b[90m║\x1b[0m");
        println!("\x1b[90m║\x1b[0m                                       \x1b[90m║\x1b[0m");
        println!("\x1b[90m╚═══════════════════════════════════════╝\x1b[0m\n");
        return;
    }

    println!("\n\x1b[33m╔═══════════════════════════════════════╗\x1b[0m");
    println!("\x1b[33m║\x1b[0m         \x1b[36m💰 CLAIMABLE TOKENS\x1b[0m          \x1b[33m║\x1b[0m");
    println!("\x1b[33m╠═══════════════════════════════════════╣\x1b[0m");
    
    for (id, token) in tokens {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time_left = if token.expires_at > current_time {
            let mins_left = (token.expires_at - current_time) / 60;
            if mins_left > 60 {
                format!("{}h {}m", mins_left / 60, mins_left % 60)
            } else {
                format!("{}m", mins_left)
            }
        } else {
            "Expired".to_string()
        };

        println!("\x1b[33m║\x1b[0m                                       \x1b[33m║\x1b[0m");
        
        // Format token line with proper spacing
        let token_info = format!("ID: {}  {} {}  ({})", id, token.amount, token.unit, time_left);
        let token_padding = if token_info.len() < 37 {
            " ".repeat((37 - token_info.len()) / 2)
        } else {
            "".to_string()
        };
        let token_right_padding = if token_info.len() < 37 {
            " ".repeat(37 - token_info.len() - token_padding.len())
        } else {
            "".to_string()
        };
        
        println!("\x1b[33m║\x1b[0m{}\x1b[93mID: {}\x1b[0m  \x1b[92m{} {}\x1b[0m  \x1b[91m({})\x1b[0m{}\x1b[33m║\x1b[0m", 
            token_padding, id, token.amount, token.unit, time_left, token_right_padding);
    }
    
    println!("\x1b[33m║\x1b[0m                                       \x1b[33m║\x1b[0m");
    println!("\x1b[33m║\x1b[0m      \x1b[96mUse /wallet claim <ID>\x1b[0m        \x1b[33m║\x1b[0m");
    println!("\x1b[33m╚═══════════════════════════════════════╝\x1b[0m\n");
}

pub struct CashuWallet {
    multi_mint_wallet: MultiMintWallet,
    work_dir: PathBuf,
    active_mint: Option<MintUrl>,
    claimable_tokens: ClaimableTokenManager,
}

impl CashuWallet {
    pub async fn new() -> Result<Self> {
        let work_dir = match home::home_dir() {
            Some(home_dir) => home_dir.join(DEFAULT_CASHU_DIR),
            None => PathBuf::from(DEFAULT_CASHU_DIR),
        };

        fs::create_dir_all(&work_dir)?;

        let localstore: Arc<dyn WalletDatabase<Err = cdk_database::Error> + Send + Sync> = {
            let sql_path = work_dir.join("cashu-wallet.sqlite");
            Arc::new(WalletSqliteDatabase::new(&sql_path).await?)
        };

        let seed_path = work_dir.join("seed");
        let mnemonic = match fs::metadata(seed_path.clone()) {
            Ok(_) => {
                let contents = fs::read_to_string(seed_path.clone())?;
                Mnemonic::from_str(&contents)?
            }
            Err(_) => {
                let mut rng = thread_rng();
                let random_bytes: [u8; 32] = rng.gen();
                let mnemonic = Mnemonic::from_entropy(&random_bytes)?;
                fs::write(seed_path, mnemonic.to_string())?;
                mnemonic
            }
        };

        let seed = mnemonic.to_seed_normalized("");
        let mut wallets: Vec<Wallet> = Vec::new();
        let mints = localstore.get_mints().await?;

        for (mint_url, mint_info) in mints {
            let units = if let Some(mint_info) = mint_info {
                mint_info.supported_units().into_iter().cloned().collect()
            } else {
                vec![CurrencyUnit::Sat]
            };

            for unit in units {
                let wallet = WalletBuilder::new()
                    .mint_url(mint_url.clone())
                    .unit(unit)
                    .localstore(localstore.clone())
                    .seed(&seed)
                    .build()?;

                let wallet_clone = wallet.clone();
                tokio::spawn(async move {
                    if let Err(err) = wallet_clone.get_mint_info().await {
                        eprintln!("Could not get mint info for {}: {}", wallet_clone.mint_url, err);
                    }
                });

                wallets.push(wallet);
            }
        }

        let multi_mint_wallet = MultiMintWallet::new(localstore, Arc::new(seed), wallets);

        // Load active mint from storage
        let active_mint_path = work_dir.join("active_mint");
        let active_mint = match fs::read_to_string(&active_mint_path) {
            Ok(mint_url_str) => {
                match MintUrl::from_str(&mint_url_str.trim()) {
                    Ok(mint_url) => Some(mint_url),
                    Err(_) => {
                        // Invalid mint URL in file, remove it
                        let _ = fs::remove_file(&active_mint_path);
                        None
                    }
                }
            }
            Err(_) => None, // File doesn't exist or can't be read
        };

        Ok(Self {
            multi_mint_wallet,
            work_dir,
            active_mint,
            claimable_tokens: ClaimableTokenManager::new(),
        })
    }

    pub async fn handle_command<F>(&mut self, command: &str, send_message_fn: F) -> Result<()> 
    where
        F: Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send>> + Send + Sync,
    {
        let parts: Vec<&str> = command.trim().split_whitespace().collect();
        
        // Handle empty command or help
        if parts.is_empty() || command.trim().is_empty() {
            self.print_help();
            return Ok(());
        }

        match parts[0] {
            "balance" => self.balance().await,
            "info" => {
                let mint_url = self.get_mint_url_with_fallback(parts.get(1).map(|s| s.to_string()));
                self.mint_info(mint_url).await
            }
            "seed" => self.show_seed().await,
            "topup" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet topup <amount> [mint_url] [unit]");
                    return Ok(());
                }
                let amount = parts[1].parse::<u64>().map_err(|_| anyhow::anyhow!("Invalid amount"))?;
                let mint_url = self.get_mint_url_with_fallback(parts.get(2).map(|s| s.to_string()));
                let unit = parts.get(3).unwrap_or(&"sat").to_string();
                self.mint(amount, mint_url, &unit).await
            }
            "send" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet send <amount> [mint_url] [unit]");
                    return Ok(());
                }
                let amount = parts[1].parse::<u64>().map_err(|_| anyhow::anyhow!("Invalid amount"))?;
                let mint_url = self.get_mint_url_with_fallback(parts.get(2).map(|s| s.to_string()));
                let unit = parts.get(3).unwrap_or(&"sat").to_string();
                
                // Create claimable token with ASCII display and send to chat
                match self.create_claimable_token(amount, mint_url, &unit).await {
                    Ok((token, amount, unit, mint_url)) => {
                        // Add to claimable tokens manager
                        let token_id = self.claimable_tokens.add_token(
                            format!("cashu:{}", token),
                            amount,
                            unit.clone(),
                            mint_url.clone()
                        );
                        
                        // Display ASCII art token
                        print_ascii_token(&token_id, amount, &unit, &mint_url);
                        
                        // Send the cashu message to chat
                        let cashu_message = format!("cashu:{}", token);
                        match send_message_fn(&cashu_message).await {
                            Ok(_) => {
                                println!("✅ Cashu token sent to chat!");
                            }
                            Err(e) => {
                                println!("\x1b[91m❌ Failed to send message: {}\x1b[0m", e);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        println!("\x1b[91m❌ Failed to create cashu token: {}\x1b[0m", e);
                        Err(e)
                    }
                }
            }
            "receive" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet receive <token>");
                    return Ok(());
                }
                let token_str = parts[1];
                self.receive_token(token_str).await.map(|_| ())
            }
            // TODO: This command should ask for confirmation before deleting a mint be
            // 
            // "delete_mint" => {
            //     if parts.len() < 2 {
            //         println!("Usage: /wallet delete_mint <mint_url>");
            //         return Ok(());
            //     }
            //     let mint_url = parts[1].to_string();
            //     self.delete_mint(&mint_url).await
            // }
            "set_mint" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet set_mint <mint_url>");
                    return Ok(());
                }
                let mint_url = parts[1].to_string();
                self.set_active_mint(&mint_url).await
            }
            "add_mint" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet add_mint <mint_url>");
                    return Ok(());
                }
                let mint_url = parts[1].to_string();
                self.add_mint(&mint_url).await
            }
            "active_mint" | "current_mint" => {
                self.show_active_mint().await
            }
            "unset_mint" => {
                self.unset_active_mint().await
            }
            "claim" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet claim <token_id>");
                    return Ok(());
                }
                
                let token_id = parts[1];
                self.claimable_tokens.cleanup_expired();
                
                if let Some(token_str) = self.claimable_tokens.claim_token(token_id) {
                    // Remove cashu: prefix if present for wallet processing
                    let clean_token = if token_str.starts_with("cashu:") {
                        &token_str[6..]
                    } else {
                        &token_str
                    };
                    
                    match self.receive_token(clean_token).await {
                        Ok((amount, unit)) => {
                            print_token_claimed(token_id, amount, &unit);
                        }
                        Err(e) => {
                            println!("\x1b[91m❌ Failed to receive token: {}\x1b[0m", e);
                        }
                    }
                } else {
                    println!("\x1b[93m⚠ Token not found or expired: {}\x1b[0m", token_id);
                }
                Ok(())
            }
            "tokens" => {
                self.claimable_tokens.cleanup_expired();
                let active_tokens = self.claimable_tokens.list_active_tokens();
                print_active_tokens(&active_tokens);
                Ok(())
            }
            "help" => {
                self.print_help();
                Ok(())
            }
            _ => {
                println!("Unknown command: {}", parts[0]);
                self.print_help();
                Ok(())
            }
        }
    }
    async fn get_available_wallet(&self, unit: CurrencyUnit) -> Result<Wallet> {
        let balances = self.multi_mint_wallet.get_balances(&unit).await?;
        
        // Find the wallet with the highest balance
        let mut best_wallet: Option<(MintUrl, Amount)> = None;
        
        for (mint_url, balance) in balances.iter() {
            if balance > &Amount::ZERO {
                match &best_wallet {
                    None => best_wallet = Some((mint_url.clone(), *balance)),
                    Some((_, current_best_balance)) => {
                        if balance > current_best_balance {
                            best_wallet = Some((mint_url.clone(), *balance));
                        }
                    }
                }
            }
        }
        
        // If we found a wallet with balance, return it
        if let Some((mint_url, _)) = best_wallet {
            let wallet_key = WalletKey::new(mint_url, unit.clone());
            if let Some(wallet) = self.multi_mint_wallet.get_wallet(&wallet_key).await {
                return Ok(wallet.clone());
            }
        }
        
        // If no wallet with balance found, try to get any wallet for this unit
        let mints = self.multi_mint_wallet.localstore.get_mints().await?;
        for (mint_url, _) in mints {
            let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
            if let Some(wallet) = self.multi_mint_wallet.get_wallet(&wallet_key).await {
                return Ok(wallet.clone());
            }
        }
        
        Err(anyhow::anyhow!("No wallets available for unit {}", unit))
    }

    async fn balance(&self) -> Result<()> {
        let unit = CurrencyUnit::Sat;
        
        match self.multi_mint_wallet.get_balances(&unit).await {
            Ok(wallets) => {
                let mut total_balance = Amount::ZERO;
                let mut mint_count = 0;
                
                println!("💰 Wallet Balances:");
                
                for (mint_url, amount) in wallets.iter() {
                    if amount > &Amount::ZERO {
                        println!("  📍 {}: {} {}", mint_url, amount, unit);
                        total_balance += *amount;
                        mint_count += 1;
                    }
                }
                
                if mint_count == 0 {
                    println!("  No funds in any mint");
                } else {
                    println!("💰 Total Balance: {} {}", total_balance, unit);
                }
            }
            Err(e) => eprintln!("Error getting balances: {}", e),
        }
        Ok(())
    }

    async fn mint_info(&self, mint_url: Option<String>) -> Result<()> {
        let mint_url = if let Some(url) = mint_url {
            MintUrl::from_str(&url)?
        } else {
            // Get any available wallet and use its mint URL
            let wallet = self.get_available_wallet(CurrencyUnit::Sat).await?;
            wallet.mint_url.clone()
        };
        
        let client = HttpClient::new(mint_url.clone(), None);

        match client.get_mint_info().await {
            Ok(info) => {
                println!("🏦 Mint Info for: {}", mint_url);
                println!("{:#?}", info);
            }
            Err(e) => eprintln!("Error getting mint info for {}: {}", mint_url, e),
        }
        Ok(())
    }

    async fn get_or_create_wallet(&self, mint_url: &MintUrl, unit: CurrencyUnit) -> Result<Wallet> {
        // Check if wallet already exists using the proper WalletKey
        let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
        
        match self.multi_mint_wallet.get_wallet(&wallet_key).await {
            Some(wallet) => Ok(wallet.clone()),
            None => {
                // Create new wallet using MultiMintWallet's method which properly adds it to localstore
                self.multi_mint_wallet
                    .create_and_add_wallet(&mint_url.to_string(), unit, None)
                    .await
            }
        }
    }

    async fn mint(&self, amount: u64, mint_url: Option<String>, unit: &str) -> Result<()> {
        let unit = CurrencyUnit::from_str(unit)?;
        let amount = Amount::from(amount);

        let wallet = if let Some(url) = mint_url {
            let mint_url = MintUrl::from_str(&url)?;
            self.get_or_create_wallet(&mint_url, unit.clone()).await?
        } else {
            self.get_available_wallet(unit.clone()).await?
        };

        // Create mint quote
        let quote = wallet.mint_quote(amount, None).await?;

        println!("🏦 Mint quote created:");
        println!("Quote ID: {}", quote.id);
        println!("Amount: {} {}", amount, unit);
        println!("Payment request: {}", quote.request);
        println!("Please pay this invoice to mint tokens");

        // Subscribe to quote state changes
        let mut subscription = wallet
            .subscribe(WalletSubscription::Bolt11MintQuoteState(vec![quote.id.clone()]))
            .await;

        println!("⏳ Waiting for payment...");

        // Wait for payment
        while let Some(msg) = subscription.recv().await {
            if let NotificationPayload::MintQuoteBolt11Response(response) = msg {
                if response.state == MintQuoteState::Paid {
                    println!("✅ Payment received!");
                    break;
                }
            }
        }

        // Mint the tokens
        let proofs = wallet.mint(&quote.id, SplitTarget::default(), None).await?;
        let receive_amount = proofs.iter().fold(Amount::ZERO, |acc, p| acc + p.amount);

        println!("🎉 Successfully minted {} {} from {}", receive_amount, unit, wallet.mint_url);

        Ok(())
    }

    pub async fn send(&self, amount: u64, mint_url: Option<String>, unit: &str) -> Result<Token> {
        let unit = CurrencyUnit::from_str(unit)?;
        let amount = Amount::from(amount);

        // If mint_url is provided, use that specific mint, otherwise find the first mint with sufficient balance
        let wallet = if let Some(url) = mint_url {
            let mint_url = MintUrl::from_str(&url)?;
            self.get_or_create_wallet(&mint_url, unit.clone()).await?
        } else {
            // Find a wallet with sufficient balance
            let balances = self.multi_mint_wallet.get_balances(&unit).await?;
            let mut selected_mint_url = None;
            
            for (mint_url, balance) in balances.iter() {
                if balance >= &amount {
                    selected_mint_url = Some(mint_url.clone());
                    break;
                }
            }
            
            let mint_url = selected_mint_url.ok_or_else(|| {
                anyhow::anyhow!("No mint found with sufficient balance of {} {}", amount, unit)
            })?;
            
            self.get_or_create_wallet(&mint_url, unit.clone()).await?
        };

        // Check if wallet has sufficient balance
        let balances = self.multi_mint_wallet.get_balances(&unit).await?;
        let balance = balances.get(&wallet.mint_url).unwrap_or(&Amount::ZERO);
        
        if balance < &amount {
            return Err(anyhow::anyhow!(
                "Insufficient balance. Available: {} {}, Requested: {} {}",
                balance, unit, amount, unit
            ));
        }

        // Prepare the send with default options
        let send_options = SendOptions {
            memo: None,
            send_kind: SendKind::OnlineExact,
            include_fee: false,
            conditions: None,
            ..Default::default()
        };

        // Create the token using the new API
        let prepared_send = wallet.prepare_send(amount, send_options).await?;
        let token = wallet.send(prepared_send, None).await?;

        println!("📤 Token created successfully!");
        println!("Amount: {} {}", amount, unit);
        println!("Mint: {}", wallet.mint_url);
        
        Ok(token)
    }

    pub async fn create_claimable_token(&self, amount: u64, mint_url: Option<String>, unit: &str) -> Result<(Token, u64, String, String)> {
        let unit = CurrencyUnit::from_str(unit)?;
        let amount = Amount::from(amount);

        // Create the token using the existing send method
        let token = self.send(amount.into(), mint_url.clone(), unit.to_string().as_str()).await?;
        
        // Get the mint URL for display
        let display_mint_url = if let Some(url) = mint_url {
            url
        } else {
            // Find the mint that was used
            let balances = self.multi_mint_wallet.get_balances(&unit).await?;
            if let Some((mint_url, _)) = balances.iter().find(|(_, balance)| balance >= &&amount) {
                mint_url.to_string()
            } else {
                "unknown".to_string()
            }
        };

        Ok((token, amount.into(), unit.to_string(), display_mint_url))
    }

    pub async fn receive_token(&self, token_str: &str) -> Result<(u64, String)> {
        // Parse the token
        let token = Token::from_str(token_str)?;
        
        // Get the mint URL from the token
        let mint_url = token.mint_url()?;
        let unit = token.unit().unwrap_or(CurrencyUnit::Sat);
        
        // Get or create wallet for this mint
        let wallet = self.get_or_create_wallet(&mint_url, unit.clone()).await?;
        
        // Receive the token
        use cdk::wallet::ReceiveOptions;
        let receive_options = ReceiveOptions::default();
        let amount = wallet.receive(&token_str, receive_options).await?;
        
        println!("✅ Successfully received {} {} from {}", amount, unit, mint_url);
        
        Ok((amount.into(), unit.to_string()))
    }

    async fn delete_mint(&self, mint_url: &str) -> Result<()> {
        let mint_url = MintUrl::from_str(mint_url)?;
        
        // Check all possible currency units for this mint
        let all_units = vec![
            CurrencyUnit::Sat,
            CurrencyUnit::Msat,
            CurrencyUnit::Usd,
            CurrencyUnit::Eur,
            CurrencyUnit::Auth,
        ];
        
        let mut found_wallets = Vec::new();
        let mut total_balance = Amount::ZERO;
        
        // Check each unit for this mint
        for unit in all_units {
            let balances = self.multi_mint_wallet.get_balances(&unit).await?;
            if let Some(balance) = balances.get(&mint_url) {
                if balance > &Amount::ZERO {
                    found_wallets.push((unit.clone(), *balance));
                    total_balance += *balance;
                }
            } else {
                // Check if wallet exists even with zero balance
                let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
                if let Some(_) = self.multi_mint_wallet.get_wallet(&wallet_key).await {
                    found_wallets.push((unit.clone(), Amount::ZERO));
                }
            }
        }
        
        if found_wallets.is_empty() {
            println!("❌ No wallets found for mint: {}", mint_url);
            return Ok(());
        }
        
        // Show what will be deleted
        println!("\n⚠️  \x1b[91mWARNING: You are about to PERMANENTLY DELETE mint: {}\x1b[0m", mint_url);
        println!("This will remove the following wallets and their balances:");
        
        for (unit, balance) in &found_wallets {
            if balance > &Amount::ZERO {
                println!("  🔥 \x1b[91m{} {}\x1b[0m - \x1b[93mFUNDS WILL BE LOST!\x1b[0m", balance, unit);
            } else {
                println!("  📦 {} {} (empty wallet)", balance, unit);
            }
        }
        
        if total_balance > Amount::ZERO {
            println!("\n\x1b[91m💀 TOTAL FUNDS THAT WILL BE LOST: {} sats equivalent\x1b[0m", total_balance);
        }
        
        println!("\n🔥 \x1b[91mProceeding with deletion...\x1b[0m");
        
        // Delete all wallets for this mint
        let mut deleted_count = 0;
        for (unit, _) in found_wallets {
            let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
            self.multi_mint_wallet.remove_wallet(&wallet_key).await;
            deleted_count += 1;
        }
        
        // Remove the mint from the database
        if let Err(e) = self.multi_mint_wallet.localstore.remove_mint(mint_url.clone()).await {
            println!("⚠️  Warning: Failed to remove mint from database: {}", e);
        }
        
        println!("✅ Successfully deleted {} wallet(s) for mint: {}", deleted_count, mint_url);
        
        Ok(())
    }

    pub async fn show_seed(&self) -> Result<()> {
        let seed_path = self.work_dir.join("seed");
        let mnemonic = fs::read_to_string(seed_path)?;
        let seed = Mnemonic::from_str(&mnemonic)?;

        println!("\n\x1b[38;5;46m━━━ Your Cashu Seed ━━━\x1b[0m\n");
        println!("Your Cashu seed is your private key. Do not share it with anyone!");
        println!("This seed is stored in your home directory: {}", self.work_dir.display());
        println!("Please back it up and store it securely.");
        println!("\nYour Seed (Mnemonic):");
        println!("{}", mnemonic);
        println!("\nYour Seed (Hex):");
        println!("{}", seed.words().collect::<Vec<_>>().join(" "));
        println!("\n\x1b[90mExample: /wallet restore <your_seed_hex>\x1b[0m");
        Ok(())
    }

    pub fn print_help(&self) {
        println!("\n\x1b[38;5;46m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
        println!("\x1b[38;5;46m                        🪙 CASHU WALLET COMMANDS 🪙\x1b[0m");
        println!("\x1b[38;5;46m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
        
        println!("\x1b[38;5;40m📊 BALANCE & INFO\x1b[0m");
        println!("  \x1b[36m/wallet balance\x1b[0m                    Show wallet balances across all mints");
        println!("  \x1b[36m/wallet info\x1b[0m \x1b[90m[mint_url]\x1b[0m           Get detailed mint information");
        println!("  \x1b[36m/wallet seed\x1b[0m                     \x1b[91m⚠️  Show wallet seed (SENSITIVE!)\x1b[0m\n");
        
        println!("\x1b[38;5;40m💸 SEND & RECEIVE\x1b[0m");
        println!("  \x1b[36m/wallet send\x1b[0m \x1b[90m<amount> [mint_url] [unit]\x1b[0m");
        println!("      Create a cashu token, send to chat, and make it claimable");
        println!("  \x1b[36m/wallet receive\x1b[0m \x1b[90m<token>\x1b[0m             Receive and claim a cashu token");
        println!("  \x1b[36m/wallet topup\x1b[0m \x1b[90m<amount> [mint_url] [unit]\x1b[0m");
        println!("      Mint new tokens from a Lightning invoice (alias: mint)\n");
        
        println!("\x1b[38;5;40m🎯 TOKEN CLAIMS\x1b[0m");
        println!("  \x1b[36m/wallet claim\x1b[0m \x1b[90m<token_id>\x1b[0m           Claim a token that was dropped in chat");
        println!("  \x1b[36m/wallet tokens\x1b[0m                   List all active claimable tokens with expiry\n");
        
        println!("\x1b[38;5;40m🏦 MINT MANAGEMENT\x1b[0m");
        println!("  \x1b[36m/wallet add_mint\x1b[0m \x1b[90m<mint_url>\x1b[0m        Add a new mint to your wallet");
        println!("  \x1b[36m/wallet set_mint\x1b[0m \x1b[90m<mint_url>\x1b[0m        Set the default mint for operations");
        println!("  \x1b[36m/wallet active_mint\x1b[0m              Show current active/default mint");
        println!("  \x1b[36m/wallet current_mint\x1b[0m             Alias for active_mint");
        println!("  \x1b[36m/wallet unset_mint\x1b[0m               Clear the active/default mint\n");
        
        println!("\x1b[38;5;40m❓ HELP & SUPPORT\x1b[0m");
        println!("  \x1b[36m/wallet help\x1b[0m                     Show this comprehensive help guide");
        println!("  \x1b[36m/wallet\x1b[0m                          Show this help (same as /wallet help)\n");
        
        println!("\x1b[38;5;214m💡 QUICK START GUIDE\x1b[0m");
        println!("1️⃣  Add a mint:    \x1b[36m/wallet add_mint https://mint.example.com\x1b[0m");
        println!("2️⃣  Set as active: \x1b[36m/wallet set_mint https://mint.example.com\x1b[0m");
        println!("3️⃣  Add funds:     \x1b[36m/wallet topup 1000\x1b[0m");
        println!("4️⃣  Send tokens:   \x1b[36m/wallet send 100\x1b[0m");
        println!("5️⃣  Claim tokens:  \x1b[36m/wallet claim 1234\x1b[0m\n");
        
        println!("\x1b[38;5;33m📝 USAGE EXAMPLES\x1b[0m");
        println!("\x1b[90m• Send 1000 sats using active mint:\x1b[0m");
        println!("  \x1b[36m/wallet send 1000\x1b[0m");
        println!("\x1b[90m• Send 500 sats from specific mint:\x1b[0m");
        println!("  \x1b[36m/wallet send 500 https://mint.example.com sat\x1b[0m");
        println!("\x1b[90m• Mint 2000 sats using active mint:\x1b[0m");
        println!("  \x1b[36m/wallet topup 2000\x1b[0m");
        println!("\x1b[90m• Receive a cashu token:\x1b[0m");
        println!("  \x1b[36m/wallet receive cashuAeyJ0eXAiOiJQMlBLI...\x1b[0m");
        println!("\x1b[90m• Claim a dropped token with ID 1234:\x1b[0m");
        println!("  \x1b[36m/wallet claim 1234\x1b[0m");
        println!("\x1b[90m• Check your current active mint:\x1b[0m");
        println!("  \x1b[36m/wallet active_mint\x1b[0m\n");
        
        println!("\x1b[38;5;196m⚠️  IMPORTANT NOTES\x1b[0m");
        println!("• Claimable tokens expire after 1 hour");
        println!("• Always verify mint URLs before adding them");
        println!("• Keep your seed phrase secure and backed up");
        println!("• Use '/wallet seed' only in private/secure environments\n");
        
        println!("\x1b[38;5;46m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    }

    // Active mint management methods
    pub async fn set_active_mint(&mut self, mint_url: &str) -> Result<()> {
        let mint_url = MintUrl::from_str(mint_url)?;
        
        // Verify the mint is accessible
        let client = HttpClient::new(mint_url.clone(), None);
        match client.get_mint_info().await {
            Ok(_) => {
                // Save to file
                let active_mint_path = self.work_dir.join("active_mint");
                fs::write(&active_mint_path, mint_url.to_string())?;
                
                // Update in memory
                self.active_mint = Some(mint_url.clone());
                
                println!("✅ Active mint set to: {}", mint_url);
                Ok(())
            }
            Err(e) => {
                Err(anyhow::anyhow!("Failed to connect to mint {}: {}", mint_url, e))
            }
        }
    }

    pub async fn unset_active_mint(&mut self) -> Result<()> {
        let active_mint_path = self.work_dir.join("active_mint");
        if active_mint_path.exists() {
            fs::remove_file(&active_mint_path)?;
        }
        self.active_mint = None;
        println!("✅ Active mint cleared");
        Ok(())
    }

    pub fn get_active_mint(&self) -> Option<&MintUrl> {
        self.active_mint.as_ref()
    }

    pub async fn show_active_mint(&self) -> Result<()> {
        match &self.active_mint {
            Some(mint_url) => {
                println!("🎯 Active mint: {}", mint_url);
                
                // Show balance for this mint
                let unit = CurrencyUnit::Sat;
                match self.multi_mint_wallet.get_balances(&unit).await {
                    Ok(balances) => {
                        if let Some(balance) = balances.get(mint_url) {
                            println!("💰 Balance: {} {}", balance, unit);
                        } else {
                            println!("💰 Balance: 0 {}", unit);
                        }
                    }
                    Err(e) => {
                        println!("⚠️  Could not get balance: {}", e);
                    }
                }
            }
            None => {
                println!("❌ No active mint set");
                println!("Use '/wallet set_mint <mint_url>' to set an active mint");
            }
        }
        Ok(())
    }

    pub async fn add_mint(&self, mint_url: &str) -> Result<()> {
        let mint_url = MintUrl::from_str(mint_url)?;
        
        // Verify the mint is accessible and get mint info
        let client = HttpClient::new(mint_url.clone(), None);
        let mint_info = match client.get_mint_info().await {
            Ok(info) => info,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to connect to mint {}: {}", mint_url, e));
            }
        };

        // Check if mint already exists
        let existing_mints = self.multi_mint_wallet.localstore.get_mints().await?;
        if existing_mints.contains_key(&mint_url) {
            println!("⚠️  Mint {} is already added to your wallet.", mint_url);
            
            // Show existing wallets for this mint
            let all_units = vec![
                CurrencyUnit::Sat,
                CurrencyUnit::Msat,
                CurrencyUnit::Usd,
                CurrencyUnit::Eur,
                CurrencyUnit::Auth,
            ];
            
            let mut existing_wallets = Vec::new();
            for unit in all_units {
                let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
                if let Some(_) = self.multi_mint_wallet.get_wallet(&wallet_key).await {
                    existing_wallets.push(unit);
                }
            }
            
            if !existing_wallets.is_empty() {
                println!("Existing wallets for this mint:");
                for unit in existing_wallets {
                    println!("  📦 {} {}", unit, "(ready to use)");
                }
            }
            return Ok(());
        }

        // Use default supported units (most mints support sat)
        let supported_units = vec![CurrencyUnit::Sat];

        println!("🏦 Adding mint: {}", mint_url);
        println!("📋 Mint info: {} (version {})", 
            mint_info.name.unwrap_or_else(|| "Unknown".to_string()),
            mint_info.version.map(|v| v.to_string()).unwrap_or_else(|| "Unknown".to_string())
        );
        
        println!("🔧 Creating wallets for supported units:");
        let mut created_wallets = Vec::new();
        
        for unit in &supported_units {
            match self.multi_mint_wallet
                .create_and_add_wallet(&mint_url.to_string(), unit.clone(), None)
                .await 
            {
                Ok(_) => {
                    println!("  ✅ {} {} wallet created", unit, "");
                    created_wallets.push(unit.clone());
                }
                Err(e) => {
                    println!("  ❌ Failed to create {} wallet: {}", unit, e);
                }
            }
        }

        if created_wallets.is_empty() {
            println!("❌ Failed to create any wallets for mint: {}", mint_url);
            return Err(anyhow::anyhow!("No wallets could be created"));
        }

        println!("✅ Successfully added mint {} with {} wallet(s)!", 
            mint_url, created_wallets.len());
        
        // Optionally suggest setting as active mint
        if self.active_mint.is_none() {
            println!("\n💡 Tip: Set this as your active mint with: /wallet set_mint {}", mint_url);
        }
        
        Ok(())
    }

    // Helper method to get mint URL with fallback logic
    fn get_mint_url_with_fallback(&self, provided_mint_url: Option<String>) -> Option<String> {
        if let Some(url) = provided_mint_url {
            Some(url)
        } else if let Some(active_mint) = &self.active_mint {
            Some(active_mint.to_string())
        } else {
            None
        }
    }
} 