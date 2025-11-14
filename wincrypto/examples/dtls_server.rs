use std::io;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Instant;
use str0m_wincrypto::{Certificate, Dtls, DtlsEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("=== DTLS Server Example ===");
    println!();

    // Generate a self-signed certificate using EC-DSA
    println!("[*] Generating self-signed EC-DSA certificate...");
    let cert = Arc::new(Certificate::new_self_signed(
        true, // use EC-DSA keys
        "CN=localhost",
    )?);
    println!("[✓] Certificate generated successfully");
    println!();

    // Create DTLS instance for server
    println!("[*] Initializing DTLS server...");
    let mut dtls = Dtls::new(cert)?;
    dtls.set_as_client(false)?; // Set as server
    println!("[✓] DTLS server initialized");
    println!();

    // Bind UDP socket
    println!("[*] Opening Ephemeral UDP socket");
    let socket = UdpSocket::bind("0.0.0.0:30000")?;
    let addr = socket.local_addr()?;
    println!("[✓] UDP socket opened on {}", addr);
    println!();

    println!("Waiting for incoming DTLS handshake...");
    println!("---");
    println!();

    // Handshake loop
    let mut peer_addr = None;

    loop {
        // Check for timeout
        let now = Instant::now();
        if let Some(next_timeout) = dtls.next_timeout(now) {
            let _timeout_ms = std::cmp::max(1, next_timeout.duration_since(now).as_millis() as u64);
        }

        // Try to receive data from socket
        let mut buffer = [0u8; 1500];
        let result = socket.recv_from(&mut buffer);

        let received_data = match result {
            Ok((n, addr)) => {
                if peer_addr.is_none() {
                    println!("[+] Received data from peer: {}", addr);
                    peer_addr = Some(addr);
                }
                Some((&buffer[..n], addr))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Timeout, continue
                None
            }
            Err(e) => return Err(e.into()),
        };

        // Process received data
        if let Some((data, addr)) = received_data {
            println!("[<] Received {} bytes from {}", data.len(), addr);

            match dtls.handle_receive(Some(data))? {
                DtlsEvent::None => {
                    println!("    -> No event (processing handshake message)");
                }
                DtlsEvent::WouldBlock => {
                    println!("    -> Would block (waiting for more data)");
                }
                DtlsEvent::Connected {
                    srtp_profile_id,
                    srtp_keying_material,
                    peer_fingerprint,
                } => {
                    println!("    -> *** HANDSHAKE COMPLETE ***");
                    println!("    -> SRTP Profile ID: 0x{:04x}", srtp_profile_id);
                    println!(
                        "    -> SRTP Keying Material: {} bytes",
                        srtp_keying_material.len()
                    );
                    println!("    -> Peer Fingerprint: {}", hex::encode(peer_fingerprint));
                    break;
                }
                DtlsEvent::Data(data) => {
                    println!("    -> Received application data: {} bytes", data.len());
                }
            }
        }

        // Send any pending datagrams
        while let Some(dgram) = dtls.pull_datagram() {
            if let Some(addr) = peer_addr {
                socket.send_to(&dgram, addr)?;
                println!("[>] Sent {} bytes to {}", dgram.len(), addr);
            } else {
                println!("[!] Warning: No peer address, discarding handshake message");
            }
        }

        // Check if handshake failed
        if !dtls.is_connected() {
            // Handshake still in progress
        }
    }

    println!();
    println!("---");
    println!("[✓] DTLS handshake completed successfully!");

    Ok(())
}
