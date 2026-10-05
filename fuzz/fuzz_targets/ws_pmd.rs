//! libFuzzer target for [`npro_fuzz::Target::WsPmd`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::WsPmd.run(data));
