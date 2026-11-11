# iOS example resources

This example app bundles proving artifacts only from the repository's
generated, hash-pinned artifact package.

The `zk_demo` resource tree is staged into
`build/native/ios-demo-resources` and added to the
Xcode project as a folder resource so nested artifact filenames keep their
directory context. Legacy `.acir`, `.vk`, and CRS files must not be added to
this source directory.
