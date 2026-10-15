//! libFuzzer target for [`npro_fuzz::Target::CertdistUpdate`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::CertdistUpdate.run(data));
