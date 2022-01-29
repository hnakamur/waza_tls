const std = @import("std");
const os = std.os;
const pem = @import("pem.zig");
const x509 = @import("x509.zig");

// Possible certificate files; stop after finding one.
const cert_files = &[_][]const u8{
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
    "/etc/pki/tls/certs/ca-bundle.crt", // Fedora/RHEL 6
    "/etc/ssl/ca-bundle.pem", // OpenSUSE
    "/etc/pki/tls/cacert.pem", // OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
    "/etc/ssl/cert.pem", // Alpine Linux
};

// Possible directories with certificate files; all will be read.
const cert_directories = &[_][]const u8{
    "/etc/ssl/certs", // SLES10/SLES11, https://golang.org/issue/12139
    "/etc/pki/tls/certs", // Fedora/RHEL
    "/system/etc/security/cacerts", // Android
};

const testing = std.testing;
test "read_cert_file" {
    // testing.log_level = .debug;

    const allocator = testing.allocator;
    const max_bytes = 1024 * 1024 * 1024;
    const data = try std.fs.cwd().readFileAlloc(
        allocator,
        "/etc/ssl/certs/ca-certificates.crt",
        max_bytes,
    );
    defer allocator.free(data);

    var offset: usize = 0;
    while (offset < data.len) {
        var block = try pem.Block.decode(allocator, data, &offset);
        defer block.deinit(allocator);

        var cert = try x509.Certificate.parse(allocator, block.bytes);
        defer cert.deinit(allocator);

        std.log.debug("cert={}", .{cert});
    }
}
