use std::any::Any;

use bincode::ErrorKind;
use serde::Deserialize;

/// This trait should be implemented by an enum that represents all the possible structs that will be sent over the stream.
///
/// ### Example
/// ```
/// use std::any::Any;
///
/// use bincode::ErrorKind;
/// use networking_lib::stream::PacketTrait;
/// use serde::{Serialize, Deserialize};
///
/// struct FooStruct {
///     foo: i32,
/// }
///
/// #[derive(Serialize, Deserialize)]
/// struct BarStruct {}
///
///
/// enum Packets {
///     Foo(i32),
///     Bar,
/// }
///
/// impl PacketTrait for Packets {
///     fn to_struct(&self, bytes: &[u8]) -> Result<Box<dyn Any>, Box<ErrorKind>> {
///         match self {
///             Self::Foo(foo) => Ok(Box::new(FooStruct {foo: *foo})),
///             Self::Bar => Ok(Box::new(Self::bincode_deserialize::<BarStruct>(bytes))),
///         }
///     }
/// }
/// ```
pub trait PacketTrait {
    /// This function should convert the bytes into a struct.
    /// ### Example:
    /// ```
    /// ```
    fn to_struct(&self, bytes: &[u8]) -> Result<Box<dyn Any>, Box<ErrorKind>>;

    fn bincode_deserialize<S: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<S, Box<ErrorKind>> {
        bincode::deserialize(bytes)
    }
}
