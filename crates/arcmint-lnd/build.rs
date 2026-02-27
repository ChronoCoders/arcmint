fn main() {
    tonic_build::configure()
        .build_server(false)
        .compile(
            &["proto/lightning.proto", "proto/router.proto"],
            &["proto/"],
        )
        .unwrap();
}
