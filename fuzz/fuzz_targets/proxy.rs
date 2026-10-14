//! libFuzzer target for [`npro_fuzz::Target::Proxy`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::Proxy.run(data));
