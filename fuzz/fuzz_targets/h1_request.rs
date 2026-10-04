//! libFuzzer target for [`npro_fuzz::Target::H1Request`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::H1Request.run(data));
