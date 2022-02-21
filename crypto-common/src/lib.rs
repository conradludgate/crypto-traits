//! Common cryptographic traits.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/crypto-common/0.1.3"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// #![allow(incomplete_features)]
// #![feature(adt_const_params, generic_const_exprs)]

#[cfg(feature = "std")]
extern crate std;

use array::Array;
#[cfg(feature = "rand_core")]
pub use rand_core;

use core::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
    fmt,
};
#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

/// Types which process data in blocks.
pub trait BlockSizeUser {
    /// Size of the block in bytes.
    type Block: Array;
}

impl<T: BlockSizeUser> BlockSizeUser for &T {
    type Block = T::Block;
}

impl<T: BlockSizeUser> BlockSizeUser for &mut T {
    type Block = T::Block;
}

/// Types which return data with the given size.
pub trait OutputSizeUser {
    /// Size of the block in bytes.
    type Output: Array;
}

/// Types which use key for initialization.
///
/// Generally it's used indirectly via [`KeyInit`] or [`KeyIvInit`].
pub trait KeySizeUser {
    /// Size of the block in bytes.
    type Key: Array;
}

/// Types which use initialization vector (nonce) for initialization.
///
/// Generally it's used indirectly via [`KeyIvInit`] or [`InnerIvInit`].
pub trait IvSizeUser {
    /// Initialization vector size in bytes.
    type Iv: Array;
}

/// Types which use another type for initialization.
///
/// Generally it's used indirectly via [`InnerInit`] or [`InnerIvInit`].
pub trait InnerUser {
    /// Inner type.
    type Inner;
}

/// Resettable types.
pub trait Reset {
    /// Reset state to its initial value.
    fn reset(&mut self);
}

/// Trait which stores algorithm name constant, used in `Debug` implementations.
pub trait AlgorithmName {
    /// Write algorithm name into `f`.
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

/// Types which can be initialized from key.
pub trait KeyInit: KeySizeUser + Sized {
    /// Create new value from fixed size key.
    fn new(key: Self::Key) -> Self;

    /// Create new value from variable size key.
    fn new_from_slice(key: &[u8]) -> Result<Self, TryFromSliceError> {
        Self::Key::try_from(key).map(Self::new)
    }

    /// Generate random key using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> Self::Key {
        let mut key = Self::Key::zero();
        rng.fill_bytes(&mut key);
        key
    }
}

/// Types which can be initialized from key and initialization vector (nonce).
pub trait KeyIvInit: KeySizeUser + IvSizeUser + Sized {
    /// Create new value from fixed length key and nonce.
    fn new(key: Self::Key, iv: Self::Iv) -> Self;

    /// Create new value from variable length key and nonce.
    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, TryFromSliceError> {
        let key = key.try_into()?;
        let iv = iv.try_into()?;
        Ok(Self::new(key, iv))
    }

    /// Generate random key using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> Self::Key {
        let mut key = Self::Key::zero();
        rng.fill_bytes(&mut key);
        key
    }

    /// Generate random IV using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_iv(mut rng: impl CryptoRng + RngCore) -> Self::Iv {
        let mut iv = Self::Iv::zero();
        rng.fill_bytes(&mut iv);
        iv
    }

    /// Generate random key and nonce using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key_iv(mut rng: impl CryptoRng + RngCore) -> (Self::Key, Self::Iv) {
        (Self::generate_key(&mut rng), Self::generate_iv(&mut rng))
    }
}

/// Types which can be initialized from another type (usually block ciphers).
///
/// Usually used for initializing types from block ciphers.
pub trait InnerInit: InnerUser + Sized {
    /// Initialize value from the `inner`.
    fn inner_init(inner: Self::Inner) -> Self;
}

/// Types which can be initialized from another type and additional initialization
/// vector/nonce.
///
/// Usually used for initializing types from block ciphers.
pub trait InnerIvInit: InnerUser + IvSizeUser + Sized {
    /// Initialize value using `inner` and `iv` array.
    fn inner_iv_init(inner: Self::Inner, iv: Self::Iv) -> Self;

    /// Initialize value using `inner` and `iv` slice.
    fn inner_iv_slice_init(inner: Self::Inner, iv: &[u8]) -> Result<Self, TryFromSliceError> {
        let iv = iv.try_into()?;
        Ok(Self::inner_iv_init(inner, iv))
    }

    /// Generate random IV using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_iv(mut rng: impl CryptoRng + RngCore) -> Self::Iv {
        let mut iv = Self::Iv::zero();
        rng.fill_bytes(&mut iv);
        iv
    }
}

impl<T> KeySizeUser for T
where
    T: InnerUser,
    T::Inner: KeySizeUser,
{
    type Key = <T::Inner as KeySizeUser>::Key;
}

impl<T> KeyIvInit for T
where
    T: InnerIvInit,
    T::Inner: KeyInit,
{
    #[inline]
    fn new(key: Self::Key, iv: Self::Iv) -> Self {
        Self::inner_iv_init(T::Inner::new(key), iv)
    }

    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, TryFromSliceError> {
        T::Inner::new_from_slice(key).and_then(|i| T::inner_iv_slice_init(i, iv))
    }
}

impl<T> KeyInit for T
where
    T: InnerInit,
    T::Inner: KeyInit,
{
    #[inline]
    fn new(key: Self::Key) -> Self {
        Self::inner_init(T::Inner::new(key))
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, TryFromSliceError> {
        T::Inner::new_from_slice(key).map(Self::inner_init)
    }
}

// Unfortunately this blanket impl is impossible without mutually
// exclusive traits, see: https://github.com/rust-lang/rfcs/issues/1053
// or at the very least without: https://github.com/rust-lang/rust/issues/20400
/*
impl<T> KeyIvInit for T
where
    T: InnerInit,
    T::Inner: KeyIvInit,
{
    #[inline]
    fn new(key: &Self::Key, iv: &Self::Iv) -> Self {
        Self::inner_init(T::Inner::new(key, iv))
    }

    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        T::Inner::new_from_slice(key)
            .map_err(|_| InvalidLength)
            .map(Self::inner_init)
    }
}
*/
