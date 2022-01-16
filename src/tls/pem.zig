// A Block represents a PEM encoded structure.
//
// The encoded form is:
//    -----BEGIN Type-----
//    Headers
//    base64-encoded Bytes
//    -----END Type-----
// where Headers is a possibly empty sequence of Key: Value lines.
pub const Block = struct {
    // The type, taken from the preamble (i.e. "RSA PRIVATE KEY").
    @"type": []const u8,

    // Optional headers.
    headers: []Header = &[_]Header{},

    // The decoded bytes of the contents. Typically a DER encoded ASN.1 structure.
    bytes: []const u8,
};
