fn main() {
    glib_build_tools::compile_resources(
        &["src/welsib-verifier/resources"],
        "src/welsib-verifier/resources/resources.gresource.xml",
        "welsib-verifier.gresource",
    );
}