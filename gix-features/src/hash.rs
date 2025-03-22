//! Hash functions and hash utilities
//!
//! With the `fast-sha1` feature, the `Sha1` hash type will use a more elaborate implementation utilizing hardware support
//! in case it is available. Otherwise the `rustsha1` feature should be set. `fast-sha1` will take precedence.
//! Otherwise, a minimal yet performant implementation is used instead for a decent trade-off between compile times and run-time performance.
#[cfg(all(feature = "rustsha1", not(feature = "fast-sha1")))]
mod _impl {
    use super::Digest;

    /// A implementation of the Sha1 hash, which can be used once.
    #[derive(Default, Clone)]
    pub struct Sha1(sha1_smol::Sha1);

    impl Sha1 {
        /// Digest the given `bytes`.
        pub fn update(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
        /// Finalize the hash and produce a digest.
        pub fn digest(self) -> Digest {
            self.0.digest().bytes()
        }
    }
}

/// A hash-digest produced by a [`Hasher`] hash implementation.
#[cfg(any(feature = "fast-sha1", feature = "rustsha1"))]
pub type Digest = [u8; 20];

#[cfg(feature = "fast-sha1")]
mod _impl {
    use sha1::Digest;

    /// A implementation of the Sha1 hash, which can be used once.
    #[derive(Default, Clone)]
    pub struct Sha1(sha1::Sha1);

    impl Sha1 {
        /// Digest the given `bytes`.
        pub fn update(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
        /// Finalize the hash and produce a digest.
        pub fn digest(self) -> super::Digest {
            self.0.finalize().into()
        }
    }
}

#[cfg(any(feature = "rustsha1", feature = "fast-sha1"))]
pub use _impl::Sha1 as Hasher;

/// Compute a CRC32 hash from the given `bytes`, returning the CRC32 hash.
///
/// When calling this function for the first time, `previous_value` should be `0`. Otherwise it
/// should be the previous return value of this function to provide a hash of multiple sequential
/// chunks of `bytes`.
#[cfg(feature = "crc32")]
pub fn crc32_update(previous_value: u32, bytes: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(previous_value);
    h.update(bytes);
    h.finalize()
}

/// Compute a CRC32 value of the given input `bytes`.
///
/// In case multiple chunks of `bytes` are present, one should use [`crc32_update()`] instead.
#[cfg(feature = "crc32")]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(bytes);
    h.finalize()
}
