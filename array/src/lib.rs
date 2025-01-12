use std::{array::TryFromSliceError, convert::TryFrom};

/// Array type
pub trait Array: for<'a> TryFrom<&'a [u8], Error = TryFromSliceError> + AsRef<[u8]> + AsMut<[u8]> + Copy {
    /// Length of the array
    const LEN: usize;
    /// Get the zero value for the array
    fn zero() -> Self;

    fn try_from_slice(slice: &[u8]) -> Result<&Self, TryFromSliceError>;
    fn try_from_mut_slice(slice: &mut [u8]) -> Result<&mut Self, TryFromSliceError>;
}

impl<const N: usize> Array for [u8; N] {
    const LEN: usize = N;
    fn zero() -> Self {
        [0; N]
    }

    fn try_from_slice(slice: &[u8]) -> Result<&Self, TryFromSliceError> {
        <&Self>::try_from(slice)
    }

    fn try_from_mut_slice(slice: &mut [u8]) -> Result<&mut Self, TryFromSliceError>{
        <&mut Self>::try_from(slice)
    }
}
