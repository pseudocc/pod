# Pod - Simple Serialization for Zig

`pod` is a Zig module that:

1. Converts complex data structures into a compact binary buffer.

1. Reconstruct with pointers tied to the buffer.

## Usage

`pod` provides two main functions:

1. `pod.seal(T, value, allocator)`: Serializes a value of type T into a
binary buffer.

1. `pod.unseal(T, data)`: Deserializes a buffer back into a value of type T,
with pointers referencing the buffer.
