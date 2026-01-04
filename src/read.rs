use crate::CHUNK_SIZE;
use crossbeam::channel::Sender;

use std::fs::File;
use std::io::{self, BufReader, Read, Result};

use aes_gcm_stream::Aes256GcmStreamDecryptor;
use zeroize::Zeroize;

pub fn read_loop(
    infile: &str,
    stats_tx: Sender<usize>,
    write_tx: Sender<Vec<u8>>,
    deccode: &str,
) -> Result<()> {
    let mut reader: Box<dyn Read> = if !infile.is_empty() {
        Box::new(BufReader::new(File::open(infile)?))
    } else {
        Box::new(BufReader::new(io::stdin()))
    };
    let mut buffer = [0; CHUNK_SIZE];

    if !deccode.is_empty() {
        let (mut nonce, mut key) = read_nonce_and_key(deccode)?;
        let key_array: [u8; 32] = key.clone().try_into().expect("key must be 32 bytes");
        let mut decryptor = Aes256GcmStreamDecryptor::new(key_array, &nonce);

        loop {
            let num_read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(x) => x,
                Err(_) => break,
            };
            if num_read == 0 {
                break;
            }

            let plaintext = decryptor.update(&buffer[..num_read]);
            if !plaintext.is_empty() {
                let _ = stats_tx.send(plaintext.len()); // Dont care if it cant see stats
                if write_tx.send(plaintext).is_err() {
                    break;
                };
            }
        }
        match decryptor.finalize() {
            Ok(last_block) => {
                if !last_block.is_empty() {
                    let _ = stats_tx.send(last_block.len());
                    let _ = write_tx.send(last_block);
                }
            }
            Err(_) => {
                nonce.zeroize();
                key.zeroize();
                let _ = stats_tx.send(0);
                let _ = write_tx.send(Vec::new()); // empty vec
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decryption failed: authentication tag mismatch",
                ));
            }
        }

        nonce.zeroize();
        key.zeroize();
    } else {
        loop {
            let num_read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(x) => x,
                Err(_) => break,
            };
            let _ = stats_tx.send(num_read); // Dont care if it cant see stats
            if write_tx.send(Vec::from(&buffer[..num_read])).is_err() {
                break;
            };
        }
    }

    let _ = stats_tx.send(0);
    let _ = write_tx.send(Vec::new()); // empty vec
    Ok(())
}

fn read_nonce_and_key(deccode: &str) -> Result<([u8; 12], [u8; 32])> {
    let mut file = File::open(deccode)?;
    let mut nonce = [0u8; 12];
    let mut key = [0u8; 32];
    file.read_exact(&mut nonce)?;
    file.read_exact(&mut key)?;
    Ok((nonce, key))
}
