//! libFuzzer target for [`npro_fuzz::Target::Utf8`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::Utf8.run(data));
