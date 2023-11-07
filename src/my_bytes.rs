use mockall::automock;
use std::fmt::Debug;
use std::mem::{size_of, ManuallyDrop};
use std::ops::Index;
use std::slice::SliceIndex;

#[allow(unused)]
struct Point(i32, i32);

#[automock]
trait BytesOperations {}

#[derive(Debug)]
pub struct Bytes2(pub Vec<u8>);

impl<T> From<Vec<T>> for Bytes2 {
    fn from(value: Vec<T>) -> Self {
        let t_size: usize = size_of::<T>();
        let v_len = value.len() * t_size;

        unsafe {
            let mut value = ManuallyDrop::new(value);
            Bytes2(Vec::from_raw_parts(
                value.as_mut_ptr() as *mut u8,
                v_len,
                value.capacity(),
            ))
        }
    }
}

impl<T> Into<Vec<T>> for Bytes2 {
    fn into(self) -> Vec<T> {
        // assert_eq!(size_of::<T>(), 1);
        let from = self.0;
        let t_size: usize = size_of::<T>();
        let to_len = from.len() / t_size;

        unsafe {
            let mut from = ManuallyDrop::new(from);
            Vec::from_raw_parts(from.as_mut_ptr() as *mut T, to_len, from.capacity())
        }
    }
}

impl<const U: usize> Into<Result<[u8; U], String>> for Bytes2 {
    fn into(self) -> Result<[u8; U], String> {
        if self.0.len() > U {
            return Err(format!("Sizes mismatch: {:} > {:}", self.0.len(), U));
        }

        let as_vec: Vec<u8> = self.into();
        Ok(std::array::from_fn(|i| as_vec[i]))
    }
}

impl Into<String> for Bytes2 {
    fn into(self) -> String {
        ";".parse().unwrap()
    }
}

impl<I: SliceIndex<[u8]>> Index<I> for Bytes2 {
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        return self.0.index(index);
    }
}

// impl<T> Into<&[u8]> for Bytes2 {
//     fn into(self) -> &T [u8] {
//
//     }
// }

impl Into<i64> for Bytes2 {
    fn into(self) -> i64 {
        let max_allowed_length: usize = size_of::<i64>() / size_of::<u8>();
        assert!(self.0.len() <= max_allowed_length);

        let ptr = self.0.as_ptr() as *const i64;
        unsafe { ptr.read() }
    }
}
