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
///
/// struct FooStruct {
///     foo: i32,
/// }
///
/// struct BazStruct {}
///
///
/// enum Packets {
///     Foo(i32),
///     Bar,
///     Baz(BazStruct),
/// }
///
/// impl PacketTrait for Packets {
///     fn to_struct(&self, bytes: &[u8]) -> Result<Box<dyn Any>, Box<ErrorKind>> {
///         match self {
///             Self::Foo(foo) => FooStruct {foo},
///             Self::Bar => Self::bincode_deserialize(bytes),
///             Self::Baz(baz_struct) => Box::new(baz_struct),
///         }
///     }
/// }
/// ```
pub trait PacketTrait {
    /// This function should convert the bytes into a struct.
    /// ### Example:
    /// ```
    /// fn to_struct(&self, bytes: &[u8]) -> Result<Box<dyn Any>, Box<ErrorKind>> {
    ///     match self {
    ///         Packets::Foo(foo) => FooStruct {foo},
    ///         Packets::Bar => Self::bincode_deserialize(bytes),
    ///         Packets::Baz(baz_struct) => baz_struct,
    ///     }
    /// }
    /// ```
    fn to_struct(&self, bytes: &[u8]) -> Result<Box<dyn Any>, Box<ErrorKind>>;

    fn bincode_deserialize<S: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<S, Box<ErrorKind>> {
        bincode::deserialize(bytes)
    }
}
