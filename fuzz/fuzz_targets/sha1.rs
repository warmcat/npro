//! libFuzzer target for [`npro_fuzz::Target::Sha1`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::Sha1.run(data));
