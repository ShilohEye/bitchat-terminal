<div align="center">
<pre>
##\       ##\   ##\               ##\                  ##\     
## |      \__|  ## |              ## |                 ## |    
#######\  ##\ ######\    #######\ #######\   ######\ ######\   
##  __##\ ## |\_##  _|  ##  _____|##  __##\  \____##\\_##  _|  
## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |    
## |  ## |## |  ## |##\ ## |      ## |  ## |##  __## | ## |##\ 
#######  |## |  \####  |\#######\ ## |  ## |\####### | \####  |
\_______/ \__|   \____/  \_______|\___|  \__| \_______|  \____/ 
</pre>

**_bitch@ the terminal v1.0.0_**

**Decentralized • Encrypted • Peer-to-Peer • Open Source | Written in Rust**

</div>

---

A terminal client for BitChat - the decentralized, encrypted mesh network chat protocol that works over Bluetooth LE.

> ⚠️ **Security Notice**: I have found & reported some security flaws in the current implementation that will hopefully be fixed in later releases with the Noise protocol. Private messages and channels are pending external audit. Use at your own risk for sensitive communications.

> **Permissions**: BitChat-terminal needs sudo because Bluetooth Low Energy (BLE) access requires elevated permissions on Linux I believe macOS works without sudo on install. The btleplug library needs to interact with the
  system's Bluetooth adapter directly, which is a privileged operation,similar to how packet capture tools need root access.
- You can run ```sudo usermod -a -G bluetooth $USER``` and log out & back in before installing and you will be able to run without sudo.
 
- Or you can  ```sudo setcap 'cap_net_raw,cap_net_admin+eip' /usr/local/bin/bitchat``` so that the binary has the necessary privileges to run.

- If you are having issues building the binary you can run ``cargo build --release`` and manually move the binary to ```/usr/local/bin``` 

## Running with Docker

Build the image locally.
```
git clone https://github.com/ShilohEye/bitchat-terminal.git
cd bitchat-terminal
docker build -t bitchat-terminal .
```

Run the container (with Bluetooth support)
```
docker run --rm -it --privileged \
  -v /dev:/dev \
  --env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
  -v /run/dbus:/host/run/dbus \
  bitchat-terminal
```

## Installing Rust (First Time Users)

If you don't have Rust installed:

```bash
# Install Rust using the official installer
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow the prompts (press 1 for default installation)
# Then reload your shell configuration:
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

> **Note**: BitChat uses stable Rust (no nightly required). The installer will set up everything you need.

## Quick Start

```bash
# Install (system-wide)
sudo cargo install --git https://github.com/ShilohEye/bitchat-terminal --root /usr/local

# Run (requires sudo for Bluetooth)
sudo bitchat
```

## Features

- **Mesh Networking** - Messages relay through peers to reach everyone
- **End-to-End Encryption** - X25519 + AES-256-GCM for private messages
- **No Internet Required** - Works completely offline over Bluetooth LE
- **Channels** - Public and password-protected group chats
- **Privacy First** - No accounts, no tracking, no phone numbers
- **Cross-Platform** - Compatible with iOS/Android BitChat apps


## Commands

```
/help              Show all commands
/name <newname>       Set your nickname
/dm <user> [msg]   Private message
/j #channel [pwd]  Join channel
/block @user       Block a user
/online            Show who's nearby
```

Type `/help` in-app for the full command list.

## Building

```bash
git clone https://github.com/ShilohEye/bitchat-terminal
cd bitchat-terminal
sudo cargo build --release
sudo ./target/release/bitchat
or 
sudo cargo run
```

**Requirements**: Linux, Bluetooth LE, Rust 1.70+ -- 
Have not tested on Windows should work natively on MacOS without sudo, it supports btleplug and other dependencies used by the terminal client while Windows would require some changes to the code and further testing.


> ⚠️ **Known Issues**: There is alot of client side functionality done on the rust client to work with ios and android seamlessly, and I have had more issues working with some small features in android. it is ongoing process to get it 100% but will work soon.
- Connection not found errors are typically fixed with a re run of the command, if that doesnt work restart bluetooth on the device runnign the rust client and try again.

- Android Private Messages are currently not displaying, this is a client side issue I am looking to resolve, the goal is  to be 1:1 with the iOS version which is undergoing changes as well.

- If you are having trouble and restarting the bluetooth on your device hasnt worked, then unpair all devices from phone(s) and rust client device and re-do mesh network again by running bitchat. I havent had any issues outside of these mentioned please submit for anything found  

## Debug Modes
- I would really reccomended taking a look at all of these for a better understanding of what is happening under the hood.
```bash
sudo bitchat      # Clean output (default)
sudo bitchat -d   # Connection info
sudo bitchat -dd  # Full packet inspection

or
sudo cargo run      # Clean output (default)
sudo cargo run -- -d   # Connection info
sudo cargo run -- -dd  # Full packet inspection
```

## Screenshot:

 
 <p align="center">
    <img src="https://github.com/user-attachments/assets/6d2e9804-5ff5-4f6a-841e-a5e65b4b5223" alt="BitChat Terminal" width="700">
  </p>


## Technical

- **Protocol**: Compatible with BitChat binary protocol
- **Crypto**: X25519-dalek, Ed25519-dalek, AES-256-GCM
- **Stack**: Tokio, btleplug, ANSI terminal UI
- **Privacy**: Ephemeral keys, PKCS#7 padding, no logs

## Contributing

PRs welcome! Please ensure iOS/Android compatibility.

## License

Public Domain

---
Original Projects:

The Rust Terminal implementation is based on the original Bitchat projects:
- bitchat by [@jackjackbits] (https://github.com/jackjackbits)
- bitchat-android by [@callebtc] (https://github.com/callebtc)


Part of the [BitChat ecosystem](https://github.com/permissionlesstech)
