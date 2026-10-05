//! libFuzzer target for [`npro_fuzz::Target::WsClient`].

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| npro_fuzz::Target::WsClient.run(data));
