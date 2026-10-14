//! libFuzzer target for [`npro_fuzz::Target::Files`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::Files.run(data));
