//! Provides the engine and associated config types.

use wasm_bindgen::prelude::*;

/// No documentation.
#[derive(Debug, Clone)]
pub struct NodeBufferBase64 {
    config: NodeBufferBase64Config,
    node_buffer_encoding: &'static str,
}

#[derive(Debug, Clone)]
/// No documentation.
pub struct NodeBufferBase64Config {
    padding: bool,
}

impl NodeBufferBase64Config {
    /// new().
    pub const fn new() -> Self {
        NodeBufferBase64Config { padding: true }
    }

    /// with_decode_padding_mode().
    pub const fn with_decode_padding_mode(self, _mode: crate::engine::DecodePaddingMode) -> Self {
        self
    }
}

/// No documentation.
pub struct NodeBufferBase64DecodeEstimate(usize);

impl super::DecodeEstimate for NodeBufferBase64DecodeEstimate {
    fn decoded_len_estimate(&self) -> usize {
        self.0
    }
}

#[allow(dead_code)]
pub(crate) const INVALID_VALUE: u8 = 255;

impl super::Config for NodeBufferBase64Config {
    fn encode_padding(&self) -> bool {
        self.padding
    }
}

#[wasm_bindgen(raw_module = "node:buffer")]
extern "C" {
    #[wasm_bindgen(extends=js_sys::Uint8Array)]
    pub type Buffer;

    #[wasm_bindgen(static_method_of = Buffer, catch)]
    pub fn from(value: js_sys::Uint8Array) -> Result<Buffer, JsValue>;

    #[wasm_bindgen(static_method_of = Buffer, catch, js_name = "from")]
    pub fn from_with_encoding(value: &str, encoding: &str) -> Result<Buffer, JsValue>;

    #[wasm_bindgen(method, catch)]
    pub fn toString(this: &Buffer, encoding: &str) -> Result<String, JsValue>;

    #[wasm_bindgen(method, catch)]
    pub fn copy(this: &Buffer, target: &js_sys::Uint8Array) -> Result<usize, JsValue>;

    #[wasm_bindgen(method, getter)]
    pub fn length(this: &Buffer) -> u32;
}

impl NodeBufferBase64 {
    /// Create an engine;
    pub const fn new(alphabet: &crate::alphabet::Alphabet, config: NodeBufferBase64Config) -> Self {
        Self {
            config,
            node_buffer_encoding: if alphabet.symbols[crate::alphabet::ALPHABET_SIZE - 1] == b'_' {
                "base64url"
            } else {
                "base64"
            },
        }
    }
}

impl super::Engine for NodeBufferBase64 {
    type Config = NodeBufferBase64Config;

    type DecodeEstimate = NodeBufferBase64DecodeEstimate;

    fn internal_encode(&self, input: &[u8], output: &mut [u8]) -> usize {
        let input = Buffer::from(input.into()).expect("must succeed");
        let intermediate = input
            .toString(self.node_buffer_encoding)
            .expect("must succeed");
        let mut intermediate_str = intermediate.as_str();
        if !self.config.padding && intermediate_str.ends_with('=') {
            intermediate_str = intermediate_str.trim_end_matches('=');
        }
        let intermediate_bytes = intermediate_str.as_bytes();
        let output_length = intermediate_bytes.len();
        assert!(output_length <= output.len());
        output.clone_from_slice(intermediate_bytes);
        output_length
    }

    fn internal_decoded_len_estimate(&self, input_len: usize) -> Self::DecodeEstimate {
        let numerator = input_len * 4;
        NodeBufferBase64DecodeEstimate((numerator + numerator % 4) / 3)
    }

    fn internal_decode(
        &self,
        input: &[u8],
        output: &mut [u8],
        _decode_estimate: Self::DecodeEstimate,
    ) -> Result<super::DecodeMetadata, crate::DecodeError> {
        let input_str = std::str::from_utf8(input).expect("must succeed");
        let buffer =
            Buffer::from_with_encoding(input_str, self.node_buffer_encoding).expect("must succeed");
        let length = buffer.length();
        let output_array = js_sys::Uint8Array::new_with_length(length);
        assert_eq!(
            buffer.copy(&output_array).expect("must succeed"),
            length as usize
        );
        output_array.copy_to(output);
        Ok(super::DecodeMetadata {
            decoded_len: length as usize,
            padding_offset: None, // FIXME: Implement?
        })
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }
}

/// Standard.
pub const STANDARD: NodeBufferBase64 = NodeBufferBase64 {
    config: PAD,
    node_buffer_encoding: "base64",
};

/// No pad.
pub const STANDARD_NO_PAD: NodeBufferBase64 = NodeBufferBase64 {
    config: NO_PAD,
    node_buffer_encoding: "base64",
};

/// URL-safe, pad.
pub const URL_SAFE: NodeBufferBase64 = NodeBufferBase64 {
    config: PAD,
    node_buffer_encoding: "base64url",
};

/// URL-safe, no pad.
pub const URL_SAFE_NO_PAD: NodeBufferBase64 = NodeBufferBase64 {
    config: NO_PAD,
    node_buffer_encoding: "base64url",
};

/// Pad.
pub const PAD: NodeBufferBase64Config = NodeBufferBase64Config { padding: true };

/// Pad.
pub const NO_PAD: NodeBufferBase64Config = NodeBufferBase64Config { padding: false };

pub use NodeBufferBase64 as GeneralPurpose;
pub use NodeBufferBase64Config as GeneralPurposeConfig;
pub use NodeBufferBase64DecodeEstimate as GeneralPurposeEstimate;
