//! libFuzzer target for [`npro_fuzz::Target::H1Response`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::H1Response.run(data));
