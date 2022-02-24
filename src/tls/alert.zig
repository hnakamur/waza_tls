const std = @import("std");

pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
    _,
};

pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100,
    missing_extension = 109,
    unsupported_extension = 110,
    certificate_unobtainable = 111,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    bad_certificate_hash_value = 114,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,

    pub fn level(self: AlertDescription) AlertLevel {
        return switch (self) {
            .no_renegotiation, .close_notify => .warning,
            else => .fatal,
        };
    }

    pub fn toError(self: AlertDescription) AlertError {
        return switch (self) {
            .close_notify => error.CloseNotify,
            .unexpected_message => error.UnexpectedMessage,
            .bad_record_mac => error.BadRecordMac,
            .decryption_failed => error.DecryptionFailed,
            .record_overflow => error.RecordOverflow,
            .decompression_failure => error.DecompressionFailure,
            .handshake_failure => error.HandshakeFailure,
            .bad_certificate => error.BadCertificate,
            .unsupported_certificate => error.UnsupportedCertificate,
            .certificate_revoked => error.CertificateRevoked,
            .certificate_expired => error.CertificateExpired,
            .certificate_unknown => error.CertificateUnknown,
            .illegal_parameter => error.IllegalParameter,
            .unknown_ca => error.UnknownCa,
            .access_denied => error.AccessDenied,
            .decode_error => error.DecodeError,
            .decrypt_error => error.DecryptError,
            .export_restriction => error.ExportRestriction,
            .protocol_version => error.ProtocolVersion,
            .insufficient_security => error.InsufficientSecurity,
            .internal_error => error.InternalError,
            .inappropriate_fallback => error.InappropriateFallback,
            .user_canceled => error.UserCanceled,
            .no_renegotiation => error.NoRenegotiation,
            .missing_extension => error.MissingExtension,
            .unsupported_extension => error.UnsupportedExtension,
            .certificate_unobtainable => error.CertificateUnobtainable,
            .unrecognized_name => error.UnrecognizedName,
            .bad_certificate_status_response => error.BadCertificateStatusResponse,
            .bad_certificate_hash_value => error.BadCertificateHashValue,
            .unknown_psk_identity => error.UnknownPskIdentity,
            .certificate_required => error.CertificateRequired,
            .no_application_protocol => error.NoApplicationProtocol,
            else => @panic("invalid AlertDescription value"),
        };
    }
};

pub const AlertError = error{
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    DecryptionFailed,
    RecordOverflow,
    DecompressionFailure,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ExportRestriction,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    NoRenegotiation,
    MissingExtension,
    UnsupportedExtension,
    CertificateUnobtainable,
    UnrecognizedName,
    BadCertificateStatusResponse,
    BadCertificateHashValue,
    UnknownPskIdentity,
    CertificateRequired,
    NoApplicationProtocol,
};

const testing = std.testing;

test "AlertDescription.level" {
    const f = struct {
        fn f(want: AlertLevel, desc: AlertDescription) !void {
            try testing.expectEqual(want, desc.level());
        }
    }.f;

    try f(.warning, .close_notify);
    try f(.fatal, .unexpected_message);
    try f(.fatal, .bad_record_mac);
    try f(.fatal, .decryption_failed);
    try f(.fatal, .record_overflow);
    try f(.fatal, .decompression_failure);
    try f(.fatal, .handshake_failure);
    try f(.fatal, .bad_certificate);
    try f(.fatal, .unsupported_certificate);
    try f(.fatal, .certificate_revoked);
    try f(.fatal, .certificate_expired);
    try f(.fatal, .certificate_unknown);
    try f(.fatal, .illegal_parameter);
    try f(.fatal, .unknown_ca);
    try f(.fatal, .access_denied);
    try f(.fatal, .decode_error);
    try f(.fatal, .decrypt_error);
    try f(.fatal, .export_restriction);
    try f(.fatal, .protocol_version);
    try f(.fatal, .insufficient_security);
    try f(.fatal, .internal_error);
    try f(.fatal, .inappropriate_fallback);
    try f(.fatal, .user_canceled);
    try f(.warning, .no_renegotiation);
    try f(.fatal, .missing_extension);
    try f(.fatal, .unsupported_extension);
    try f(.fatal, .certificate_unobtainable);
    try f(.fatal, .unrecognized_name);
    try f(.fatal, .bad_certificate_status_response);
    try f(.fatal, .bad_certificate_hash_value);
    try f(.fatal, .unknown_psk_identity);
    try f(.fatal, .certificate_required);
    try f(.fatal, .no_application_protocol);
}

test "AlertDescription.toError" {
    const f = struct {
        fn f(want: AlertError, desc: AlertDescription) !void {
            try testing.expectEqual(want, desc.toError());
        }
    }.f;

    try f(error.CloseNotify, .close_notify);
    try f(error.UnexpectedMessage, .unexpected_message);
    try f(error.BadRecordMac, .bad_record_mac);
    try f(error.DecryptionFailed, .decryption_failed);
    try f(error.RecordOverflow, .record_overflow);
    try f(error.DecompressionFailure, .decompression_failure);
    try f(error.HandshakeFailure, .handshake_failure);
    try f(error.BadCertificate, .bad_certificate);
    try f(error.UnsupportedCertificate, .unsupported_certificate);
    try f(error.CertificateRevoked, .certificate_revoked);
    try f(error.CertificateExpired, .certificate_expired);
    try f(error.CertificateUnknown, .certificate_unknown);
    try f(error.IllegalParameter, .illegal_parameter);
    try f(error.UnknownCa, .unknown_ca);
    try f(error.AccessDenied, .access_denied);
    try f(error.DecodeError, .decode_error);
    try f(error.DecryptError, .decrypt_error);
    try f(error.ExportRestriction, .export_restriction);
    try f(error.ProtocolVersion, .protocol_version);
    try f(error.InsufficientSecurity, .insufficient_security);
    try f(error.InternalError, .internal_error);
    try f(error.InappropriateFallback, .inappropriate_fallback);
    try f(error.UserCanceled, .user_canceled);
    try f(error.NoRenegotiation, .no_renegotiation);
    try f(error.MissingExtension, .missing_extension);
    try f(error.UnsupportedExtension, .unsupported_extension);
    try f(error.CertificateUnobtainable, .certificate_unobtainable);
    try f(error.UnrecognizedName, .unrecognized_name);
    try f(error.BadCertificateStatusResponse, .bad_certificate_status_response);
    try f(error.BadCertificateHashValue, .bad_certificate_hash_value);
    try f(error.UnknownPskIdentity, .unknown_psk_identity);
    try f(error.CertificateRequired, .certificate_required);
    try f(error.NoApplicationProtocol, .no_application_protocol);
}
