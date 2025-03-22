/// The error returned by [`Hasher::digest()`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {}

/// A implementation of the Sha1 hash, which can be used once.
#[derive(Default, Clone)]
pub struct Hasher(gix_features::hash::Hasher);

impl Hasher {
    /// Digest the given `bytes`.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    /// Finalize the hash and produce an object ID.
    pub fn try_finalize(self) -> Result<crate::ObjectId, Error> {
        Ok(self.0.digest().into())
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
