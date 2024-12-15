fn main() {
    // Ensure this matches the versions set in your `Package.swift` file.
    #[cfg(feature = "with-secure-enclave")]
    swift_rs::SwiftLinker::new("11")
        .with_ios("11")
        .with_package("swift-lib", "./swift-lib/")
        .link();
}

