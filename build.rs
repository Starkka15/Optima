fn main() {
    for p in ["demux", "ownership", "download", "download_service", "download_install_state"] {
        println!("cargo:rerun-if-changed=proto/{p}.proto");
    }
    prost_build::compile_protos(
        &[
            "proto/demux.proto",
            "proto/ownership.proto",
            "proto/download.proto",
            "proto/download_service.proto",
            "proto/download_install_state.proto",
        ],
        &["proto/"],
    )
    .expect("compiling protobufs");
}
