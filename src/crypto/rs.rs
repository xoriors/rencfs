use reed_solomon_erasure::galois_8::Field as Gf8;
use reed_solomon_erasure::ReedSolomon;
use std::error::Error;

/// Configuration for Reed-Solomon error correction (opt-in feature).
/// Users can disable by passing `None` to avoid the additional storage overhead.
#[derive(Clone, Debug)]
pub struct RsConfig {
    /// Number of data shards (original file is split across these).
    pub data_shards: usize,
    /// Number of parity shards to create (for recovery).
    pub parity_shards: usize,
}

pub struct RsEncoder {
    data_shards: usize,
    parity_shards: usize,
}

impl RsEncoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
        }
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        let r = ReedSolomon::<Gf8>::new(self.data_shards, self.parity_shards)?;

        // prefix with original length so we can trim when reconstructing
        let mut payload = Vec::with_capacity(8 + data.len());
        payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
        payload.extend_from_slice(data);

        let shard_size = (payload.len() + self.data_shards - 1) / self.data_shards;
        let total_shards = self.data_shards + self.parity_shards;

        let mut shards: Vec<Vec<u8>> = vec![vec![0u8; shard_size]; total_shards];

        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, payload.len());
            if start < payload.len() {
                shards[i][..end - start].copy_from_slice(&payload[start..end]);
            }
        }

        let mut shard_refs: Vec<&mut [u8]> = shards.iter_mut().map(|v| v.as_mut_slice()).collect();
        r.encode(&mut shard_refs)?;

        Ok(shards)
    }

    pub fn reconstruct(
        &self,
        shards_opt: &mut [Option<Vec<u8>>],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let r = ReedSolomon::<Gf8>::new(self.data_shards, self.parity_shards)?;
        let total_shards = self.data_shards + self.parity_shards;

        if shards_opt.len() != total_shards {
            return Err("shards length mismatch".into());
        }

        let shard_len = shards_opt
            .iter()
            .find_map(|s| s.as_ref().map(|v| v.len()))
            .ok_or("no shards available")?;

        for slot in shards_opt.iter_mut() {
            if let Some(v) = slot {
                if v.len() < shard_len {
                    v.resize(shard_len, 0u8);
                } else if v.len() > shard_len {
                    return Err("inconsistent shard lengths".into());
                }
            }
        }

        r.reconstruct(shards_opt)?;

        let mut payload = Vec::with_capacity(shard_len * self.data_shards);
        for i in 0..self.data_shards {
            let slice = shards_opt[i]
                .as_ref()
                .ok_or("missing shard after reconstruct")?;
            payload.extend_from_slice(slice);
        }

        if payload.len() < 8 {
            return Err("payload too small".into());
        }
        let orig_len = u64::from_le_bytes(payload[0..8].try_into().unwrap()) as usize;
        if 8 + orig_len > payload.len() {
            return Err("original length exceeds reconstructed payload".into());
        }
        Ok(payload[8..8 + orig_len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::RsEncoder;

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
}
