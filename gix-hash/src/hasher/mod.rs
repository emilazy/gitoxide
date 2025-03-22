/// A implementation of the Sha1 hash, which can be used once.
#[derive(Default, Clone)]
pub struct Hasher(gix_features::hash::Hasher);

impl Hasher {
    /// Digest the given `bytes`.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    /// Finalize the hash and produce a digest.
    pub fn digest(self) -> gix_features::hash::Digest {
        self.0.digest()
    }
}

/// Produce a hasher suitable for the given kind of hash.
pub fn hasher(kind: crate::Kind) -> Hasher {
    match kind {
        crate::Kind::Sha1 => Hasher::default(),
    }
}

/// Hashing utilities for I/O operations.
pub mod io;
