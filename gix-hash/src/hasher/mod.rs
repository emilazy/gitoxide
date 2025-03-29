/// The error returned by [`Hasher::digest()`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Detected SHA-1 collision attack with digest {digest}")]
    CollisionAttack { digest: crate::ObjectId },
}

/// A implementation of the Sha1 hash, which can be used once.
///
/// We use [`sha1collisiondetection`] to implement the same
/// collision detection algorithm as Git.
#[derive(Clone)]
pub struct Hasher(sha1collisiondetection::Sha1CD);

impl Default for Hasher {
    #[inline]
    fn default() -> Self {
        // This matches the configuration used by Git, which only uses
        // the collision detection to bail out, rather than computing
        // alternate “safe hashes” for inputs where a collision attack
        // was detected.
        Self(sha1collisiondetection::Builder::default().safe_hash(false).build())
    }
}

impl Hasher {
    /// Digest the given `bytes`.
    #[inline]
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    /// Finalize the hash and produce an object ID.
    ///
    /// Returns [`Error`] if a collision attack is detected.
    #[inline]
    pub fn try_finalize(mut self) -> Result<crate::ObjectId, Error> {
        let mut output = sha1collisiondetection::Output::default();
        let result = self.0.finalize_into_dirty_cd(&mut output);
        let digest = crate::ObjectId::Sha1(output.into());
        match result {
            Ok(()) => Ok(digest),
            Err(sha1collisiondetection::Collision {}) => Err(Error::CollisionAttack { digest }),
        }
    }
}

/// Produce a hasher suitable for the given kind of hash.
#[inline]
pub fn hasher(kind: crate::Kind) -> Hasher {
    match kind {
        crate::Kind::Sha1 => Hasher::default(),
    }
}

/// Hashing utilities for I/O operations.
pub mod io;
