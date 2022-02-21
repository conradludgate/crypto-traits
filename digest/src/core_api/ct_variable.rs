use super::{
    AlgorithmName, Buffer, BufferKindUser, FixedOutputCore, Reset, TruncSide, UpdateCore,
    VariableOutputCore,
};
use crate::HashMarker;
#[cfg(feature = "mac")]
use crate::MacMarker;
use array::Array;
use core::{fmt, marker::PhantomData};
use crypto_common::{BlockSizeUser, OutputSizeUser};

/// Wrapper around [`VariableOutputCore`] which selects output size
/// at compile time.
#[derive(Clone)]
pub struct CtVariableCoreWrapper<T, const OUT_SIZE: usize>
where
    T: VariableOutputCore,
{
    inner: T,
    _out: PhantomData<[u8; OUT_SIZE]>,
}

impl<T, const OUT_SIZE: usize> HashMarker for CtVariableCoreWrapper<T, OUT_SIZE> where
    T: VariableOutputCore + HashMarker
{
}

#[cfg(feature = "mac")]
impl<T, const OUT_SIZE: usize> MacMarker for CtVariableCoreWrapper<T, OUT_SIZE> where
    T: VariableOutputCore + MacMarker
{
}

impl<T, const OUT_SIZE: usize> BlockSizeUser for CtVariableCoreWrapper<T, OUT_SIZE>
where
    T: VariableOutputCore,
{
    type Block = T::Block;
}

impl<T, const OUT_SIZE: usize> UpdateCore for CtVariableCoreWrapper<T, OUT_SIZE>
where
    T: VariableOutputCore,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Self::Block]) {
        self.inner.update_blocks(blocks);
    }
}

impl<T, const OUT_SIZE: usize> OutputSizeUser for CtVariableCoreWrapper<T, OUT_SIZE>
where
    T: VariableOutputCore,
{
    type Output = [u8; OUT_SIZE];
}

impl<T, const OUT_SIZE: usize> BufferKindUser for CtVariableCoreWrapper<T, OUT_SIZE>
where
    T: VariableOutputCore,
{
    type BufferKind = T::BufferKind;
}

impl<T, const OUT_SIZE: usize> FixedOutputCore for CtVariableCoreWrapper<T, OUT_SIZE>
where
    T: VariableOutputCore,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut [u8; OUT_SIZE]) {
        let mut full_res = <T::Output as Array>::zero();
        self.inner.finalize_variable_core(buffer, &mut full_res);
        let n = out.len();
        let m = full_res.as_ref().len() - n;
        match T::TRUNC_SIDE {
            TruncSide::Left => out.copy_from_slice(&full_res.as_ref()[..n]),
            TruncSide::Right => out.copy_from_slice(&full_res.as_ref()[m..]),
        }
    }
}

impl<T, const OUT_SIZE: usize> Default for CtVariableCoreWrapper<T, OUT_SIZE>
where
    T: VariableOutputCore,
{
    #[inline]
    fn default() -> Self {
        Self {
            inner: T::new(OUT_SIZE).unwrap(),
            _out: PhantomData,
        }
    }
}

impl<T, const OUT_SIZE: usize> Reset for CtVariableCoreWrapper<T, OUT_SIZE>
where
    T: VariableOutputCore,
{
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<T, const OUT_SIZE: usize> AlgorithmName for CtVariableCoreWrapper<T, OUT_SIZE>
where
    T: VariableOutputCore + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::write_alg_name(f)?;
        f.write_str("_")?;
        write!(f, "{}", OUT_SIZE)
    }
}
