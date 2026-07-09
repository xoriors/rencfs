use reed_solomon_erasure::galois_8::Field as Gf8;
use reed_solomon_erasure::ReedSolomon;
use thiserror::Error;

/// Error type for Reed-Solomon encode/reconstruct operations.
#[derive(Debug, Error)]
pub enum RsError {
    #[error("Reed-Solomon error: {0}")]
    ReedSolomon(String),
}

/// Configuration for Reed-Solomon error correction (opt-in feature).
/// Users can disable by passing `None` to avoid the additional storage overhead.
///
/// Only `data_shards = 1` is currently supported in the filesystem integration.
/// The encrypted file itself acts as the single data shard; parity shards enable
/// recovery if the main file is lost.
#[derive(Clone, Debug)]
pub struct RsConfig {
    /// Number of data shards used for encoding.
    pub data_shards: usize,
    /// Number of parity shards to create (for recovery).
    pub parity_shards: usize,
}

pub struct RsEncoder {
    data_shards: usize,
    parity_shards: usize,
}

impl RsEncoder {
    /// Creates a new encoder with the given shard counts.
    /// Panics if either `data_shards` or `parity_shards` is zero.
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        assert!(data_shards > 0, "data_shards must be > 0");
        assert!(parity_shards > 0, "parity_shards must be > 0");
        Self {
            data_shards,
            parity_shards,
        }
    }

    /// Creates an encoder from an [`RsConfig`].
    pub fn from_config(config: &RsConfig) -> Self {
        Self::new(config.data_shards, config.parity_shards)
    }

    /// Encodes `data` into `data_shards + parity_shards` shards.
    ///
    /// The returned `Vec` has length `data_shards + parity_shards`. The first
    /// `data_shards` entries are the (padded) data shards; the remaining entries
    /// are the parity shards needed for reconstruction.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, RsError> {
        let r = ReedSolomon::<Gf8>::new(self.data_shards, self.parity_shards)
            .map_err(|e| RsError::ReedSolomon(e.to_string()))?;

        // prefix with original length so we can trim padding when reconstructing
        let mut payload = Vec::with_capacity(8 + data.len());
        payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
        payload.extend_from_slice(data);

        let shard_size = payload.len().div_ceil(self.data_shards);
        let total_shards = self.data_shards + self.parity_shards;

        let mut shards: Vec<Vec<u8>> = vec![vec![0u8; shard_size]; total_shards];

        for (i, shard) in shards.iter_mut().take(self.data_shards).enumerate() {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, payload.len());
            if start < payload.len() {
                shard[..end - start].copy_from_slice(&payload[start..end]);
            }
        }

        let mut shard_refs: Vec<&mut [u8]> = shards.iter_mut().map(|v| v.as_mut_slice()).collect();
        r.encode(&mut shard_refs)
            .map_err(|e| RsError::ReedSolomon(e.to_string()))?;

        Ok(shards)
    }

    /// Reconstructs the original data from a mix of data and parity shards.
    ///
    /// `shards_opt` must have exactly `data_shards + parity_shards` entries.
    /// Each `None` slot represents a missing shard. At least `data_shards`
    /// shards must be present for reconstruction to succeed.
    pub fn reconstruct(&self, shards_opt: &mut [Option<Vec<u8>>]) -> Result<Vec<u8>, RsError> {
        let r = ReedSolomon::<Gf8>::new(self.data_shards, self.parity_shards)
            .map_err(|e| RsError::ReedSolomon(e.to_string()))?;
        let total_shards = self.data_shards + self.parity_shards;

        if shards_opt.len() != total_shards {
            return Err(RsError::ReedSolomon("shards length mismatch".to_owned()));
        }

        let shard_len = shards_opt
            .iter()
            .find_map(|s| s.as_ref().map(|v| v.len()))
            .ok_or_else(|| RsError::ReedSolomon("no shards available".to_owned()))?;

        for v in shards_opt.iter_mut().flatten() {
            if v.len() < shard_len {
                v.resize(shard_len, 0u8);
            } else if v.len() > shard_len {
                return Err(RsError::ReedSolomon(
                    "inconsistent shard lengths".to_owned(),
                ));
            }
        }

        r.reconstruct(shards_opt)
            .map_err(|e| RsError::ReedSolomon(e.to_string()))?;

        let mut payload = Vec::with_capacity(shard_len * self.data_shards);
        for shard in shards_opt.iter().take(self.data_shards) {
            let slice = shard.as_ref().ok_or_else(|| {
                RsError::ReedSolomon("missing shard after reconstruct".to_owned())
            })?;
            payload.extend_from_slice(slice);
        }

        if payload.len() < 8 {
            return Err(RsError::ReedSolomon("payload too small".to_owned()));
        }
        let orig_len = u64::from_le_bytes(payload[0..8].try_into().unwrap()) as usize;
        if 8 + orig_len > payload.len() {
            return Err(RsError::ReedSolomon(
                "original length exceeds reconstructed payload".to_owned(),
            ));
        }
        Ok(payload[8..8 + orig_len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{RsConfig, RsEncoder};

    #[test]
    fn rs_encode_reconstruct() {
        let encoder = RsEncoder::new(3, 2); // 3 data, 2 parity
        let data = b"Hello Reed-Solomon! Let's test recovery.";
        let shards = encoder.encode(data).expect("encode failed");
        assert_eq!(shards.len(), 5);

        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        shards_opt[1] = None;
        shards_opt[4] = None;

        let recovered = encoder
            .reconstruct(&mut shards_opt)
            .expect("reconstruct failed");

        assert_eq!(recovered, data);
    }

    #[test]
    fn rs_reconstruct_empty_data() {
        let encoder = RsEncoder::new(1, 2);
        let data: &[u8] = b"";
        let shards = encoder.encode(data).expect("encode failed");
        assert_eq!(shards.len(), 3);

        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shards_opt[0] = None; // drop the data shard, keep parity shards

        let recovered = encoder
            .reconstruct(&mut shards_opt)
            .expect("reconstruct failed");

        assert_eq!(recovered, data);
    }

    #[test]
    fn rs_reconstruct_unrecoverable() {
        let encoder = RsEncoder::new(1, 2);
        let data = b"test data that cannot be recovered";
        let shards = encoder.encode(data).expect("encode failed");
        assert_eq!(shards.len(), 3);

        // Drop all shards - impossible to reconstruct
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(|_| None).collect();

        let result = encoder.reconstruct(&mut shards_opt);
        assert!(result.is_err(), "should fail when no shards are available");
    }

    #[test]
    fn rs_from_config() {
        let config = RsConfig {
            data_shards: 2,
            parity_shards: 3,
        };
        let encoder = RsEncoder::from_config(&config);
        let data = b"config-based encoder test";
        let shards = encoder.encode(data).expect("encode failed");
        assert_eq!(shards.len(), 5);

        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shards_opt[0] = None;
        shards_opt[3] = None;

        let recovered = encoder
            .reconstruct(&mut shards_opt)
            .expect("reconstruct failed");
        assert_eq!(recovered, data);
    }

    #[test]
    #[should_panic(expected = "data_shards must be > 0")]
    fn rs_zero_data_shards_panics() {
        RsEncoder::new(0, 2);
    }

    #[test]
    #[should_panic(expected = "parity_shards must be > 0")]
    fn rs_zero_parity_shards_panics() {
        RsEncoder::new(2, 0);
    }
}
