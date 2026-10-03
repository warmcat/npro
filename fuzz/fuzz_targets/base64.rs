//! libFuzzer target for [`npro_fuzz::Target::Base64`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::Base64.run(data));
