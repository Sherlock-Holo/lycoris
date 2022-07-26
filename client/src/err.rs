use aya::maps::MapError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("load bpf map failed: {0}")]
    BpfMap(#[from] MapError),
}
