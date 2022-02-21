use super::{FixedOutput, FixedOutputReset, InvalidBufferSize, Reset, Update};
use array::Array;
use crypto_common::OutputSizeUser;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Marker trait for cryptographic hash functions.
pub trait HashMarker {}

/// Convinience wrapper trait covering functionality of cryptographic hash
/// functions with fixed output size.
///
/// This trait wraps [`Update`], [`FixedOutput`], [`Default`], and
/// [`HashMarker`] traits and provides additional convenience methods.
pub trait Digest: OutputSizeUser {
    /// Create new hasher instance.
    fn new() -> Self;

    /// Create new hasher instance which has processed the provided data.
    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self;

    /// Process data, updating the internal state.
    fn update(&mut self, data: impl AsRef<[u8]>);

    /// Process input data in a chained manner.
    #[must_use]
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self;

    /// Retrieve result and consume hasher instance.
    fn finalize(self) -> Self::Output;

    /// Write result into provided array and consume the hasher instance.
    fn finalize_into(self, out: &mut Self::Output);

    /// Retrieve result and reset hasher instance.
    fn finalize_reset(&mut self) -> Self::Output
    where
        Self: FixedOutputReset;

    /// Write result into provided array and reset the hasher instance.
    fn finalize_into_reset(&mut self, out: &mut Self::Output)
    where
        Self: FixedOutputReset;

    /// Reset hasher instance to its initial state.
    fn reset(&mut self)
    where
        Self: Reset;

    /// Get output size of the hasher
    fn output_size() -> usize;

    /// Compute hash of `data`.
    fn digest(data: impl AsRef<[u8]>) -> Self::Output;
}

impl<D: FixedOutput + Default + Update + HashMarker> Digest for D {
    #[inline]
    fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self
    where
        Self: Default + Sized,
    {
        let mut h = Self::default();
        h.update(data.as_ref());
        h
    }

    #[inline]
    fn update(&mut self, data: impl AsRef<[u8]>) {
        Update::update(self, data.as_ref());
    }

    #[inline]
    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Update::update(&mut self, data.as_ref());
        self
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        FixedOutput::finalize_fixed(self)
    }

    #[inline]
    fn finalize_into(self, out: &mut Self::Output) {
        FixedOutput::finalize_into(self, out);
    }

    #[inline]
    fn finalize_reset(&mut self) -> Self::Output
    where
        Self: FixedOutputReset,
    {
        FixedOutputReset::finalize_fixed_reset(self)
    }

    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Self::Output)
    where
        Self: FixedOutputReset,
    {
        FixedOutputReset::finalize_into_reset(self, out);
    }

    #[inline]
    fn reset(&mut self)
    where
        Self: Reset,
    {
        Reset::reset(self)
    }

    #[inline]
    fn output_size() -> usize {
        <<Self as OutputSizeUser>::Output as Array>::LEN
    }

    #[inline]
    fn digest(data: impl AsRef<[u8]>) -> Self::Output {
        let mut hasher = Self::default();
        hasher.update(data.as_ref());
        hasher.finalize()
    }
}

/// Modification of the [`Digest`] trait suitable for trait objects.
pub trait DynDigest {
    /// Digest input data.
    ///
    /// This method can be called repeatedly for use with streaming messages.
    fn update(&mut self, data: &[u8]);

    /// Retrieve result and reset hasher instance
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_reset(&mut self) -> Box<[u8]> {
        let mut result = vec![0; self.output_size()];
        self.finalize_into_reset(&mut result).unwrap();
        result.into_boxed_slice()
    }

    /// Retrieve result and consume boxed hasher instance
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[allow(clippy::boxed_local)]
    fn finalize(mut self: Box<Self>) -> Box<[u8]> {
        let mut result = vec![0; self.output_size()];
        self.finalize_into_reset(&mut result).unwrap();
        result.into_boxed_slice()
    }

    /// Write result into provided array and consume the hasher instance.
    ///
    /// Returns error if buffer length is not equal to `output_size`.
    fn finalize_into(self, buf: &mut [u8]) -> Result<(), InvalidBufferSize>;

    /// Write result into provided array and reset the hasher instance.
    ///
    /// Returns error if buffer length is not equal to `output_size`.
    fn finalize_into_reset(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize>;

    /// Reset hasher instance to its initial state.
    fn reset(&mut self);

    /// Get output size of the hasher
    fn output_size(&self) -> usize;

    /// Clone hasher state into a boxed trait object
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn box_clone(&self) -> Box<dyn DynDigest>;
}

impl<D: Update + FixedOutputReset + Reset + Clone + 'static> DynDigest for D {
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[cfg(feature = "alloc")]
    fn finalize_reset(&mut self) -> Box<[u8]> {
        FixedOutputReset::finalize_fixed_reset(self)
            .to_vec()
            .into_boxed_slice()
    }

    #[cfg(feature = "alloc")]
    fn finalize(self: Box<Self>) -> Box<[u8]> {
        FixedOutput::finalize_fixed(*self)
            .to_vec()
            .into_boxed_slice()
    }

    fn finalize_into(self, buf: &mut [u8]) -> Result<(), InvalidBufferSize> {
        FixedOutput::finalize_into(
            self,
            <<Self as OutputSizeUser>::Output as Array>::try_from_mut_slice(buf)
                .map_err(|_| InvalidBufferSize)?,
        );
        Ok(())
    }

    fn finalize_into_reset(&mut self, buf: &mut [u8]) -> Result<(), InvalidBufferSize> {
        FixedOutputReset::finalize_into_reset(
            self,
            <<Self as OutputSizeUser>::Output as Array>::try_from_mut_slice(buf)
                .map_err(|_| InvalidBufferSize)?,
        );
        Ok(())
    }

    fn reset(&mut self) {
        Reset::reset(self);
    }

    fn output_size(&self) -> usize {
        <<Self as OutputSizeUser>::Output as Array>::LEN
    }

    #[cfg(feature = "alloc")]
    fn box_clone(&self) -> Box<dyn DynDigest> {
        Box::new(self.clone())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Clone for Box<dyn DynDigest> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
