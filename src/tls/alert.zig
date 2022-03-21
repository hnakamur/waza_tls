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

    pub fn fromError(err: anyerror) AlertDescription {
        return switch (err) {
            error.CloseNotify => .close_notify,
            error.UnexpectedMessage => .unexpected_message,
            error.BadRecordMac => .bad_record_mac,
            error.DecryptionFailed => .decryption_failed,
            error.RecordOverflow => .record_overflow,
            error.DecompressionFailure => .decompression_failure,
            error.HandshakeFailure => .handshake_failure,
            error.BadCertificate => .bad_certificate,
            error.UnsupportedCertificate => .unsupported_certificate,
            error.CertificateRevoked => .certificate_revoked,
            error.CertificateExpired => .certificate_expired,
            error.CertificateUnknown => .certificate_unknown,
            error.IllegalParameter => .illegal_parameter,
            error.UnknownCa => .unknown_ca,
            error.AccessDenied => .access_denied,
            error.DecodeError => .decode_error,
            error.DecryptError => .decrypt_error,
            error.ExportRestriction => .export_restriction,
            error.ProtocolVersion => .protocol_version,
            error.InsufficientSecurity => .insufficient_security,
            error.InternalError => .internal_error,
            error.InappropriateFallback => .inappropriate_fallback,
            error.UserCanceled => .user_canceled,
            error.NoRenegotiation => .no_renegotiation,
            error.MissingExtension => .missing_extension,
            error.UnsupportedExtension => .unsupported_extension,
            error.CertificateUnobtainable => .certificate_unobtainable,
            error.UnrecognizedName => .unrecognized_name,
            error.BadCertificateStatusResponse => .bad_certificate_status_response,
            error.BadCertificateHashValue => .bad_certificate_hash_value,
            error.UnknownPskIdentity => .unknown_psk_identity,
            error.CertificateRequired => .certificate_required,
            error.NoApplicationProtocol => .no_application_protocol,
            else => .internal_error,
        };
    }

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

pub fn isAlertError(err: anyerror) bool {
    return switch (err) {
        error.CloseNotify => true,
        error.UnexpectedMessage => true,
        error.BadRecordMac => true,
        error.DecryptionFailed => true,
        error.RecordOverflow => true,
        error.DecompressionFailure => true,
        error.HandshakeFailure => true,
        error.BadCertificate => true,
        error.UnsupportedCertificate => true,
        error.CertificateRevoked => true,
        error.CertificateExpired => true,
        error.CertificateUnknown => true,
        error.IllegalParameter => true,
        error.UnknownCa => true,
        error.AccessDenied => true,
        error.DecodeError => true,
        error.DecryptError => true,
        error.ExportRestriction => true,
        error.ProtocolVersion => true,
        error.InsufficientSecurity => true,
        error.InternalError => true,
        error.InappropriateFallback => true,
        error.UserCanceled => true,
        error.NoRenegotiation => true,
        error.MissingExtension => true,
        error.UnsupportedExtension => true,
        error.CertificateUnobtainable => true,
        error.UnrecognizedName => true,
        error.BadCertificateStatusResponse => true,
        error.BadCertificateHashValue => true,
        error.UnknownPskIdentity => true,
        error.CertificateRequired => true,
        error.NoApplicationProtocol => true,
        else => false,
    };
}

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

test "AlertDescription.fromError" {
    const f = struct {
        fn f(err: anyerror, want: AlertDescription) !void {
            try testing.expectEqual(want, AlertDescription.fromError(err));
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

    try f(error.OutOfMemory, .internal_error);
}

test "isAlertError" {
    try testing.expect(isAlertError(error.CloseNotify));
    try testing.expect(isAlertError(error.UnexpectedMessage));
    try testing.expect(isAlertError(error.BadRecordMac));
    try testing.expect(isAlertError(error.DecryptionFailed));
    try testing.expect(isAlertError(error.RecordOverflow));
    try testing.expect(isAlertError(error.DecompressionFailure));
    try testing.expect(isAlertError(error.HandshakeFailure));
    try testing.expect(isAlertError(error.BadCertificate));
    try testing.expect(isAlertError(error.UnsupportedCertificate));
    try testing.expect(isAlertError(error.CertificateRevoked));
    try testing.expect(isAlertError(error.CertificateExpired));
    try testing.expect(isAlertError(error.CertificateUnknown));
    try testing.expect(isAlertError(error.IllegalParameter));
    try testing.expect(isAlertError(error.UnknownCa));
    try testing.expect(isAlertError(error.AccessDenied));
    try testing.expect(isAlertError(error.DecodeError));
    try testing.expect(isAlertError(error.DecryptError));
    try testing.expect(isAlertError(error.ExportRestriction));
    try testing.expect(isAlertError(error.ProtocolVersion));
    try testing.expect(isAlertError(error.InsufficientSecurity));
    try testing.expect(isAlertError(error.InternalError));
    try testing.expect(isAlertError(error.InappropriateFallback));
    try testing.expect(isAlertError(error.UserCanceled));
    try testing.expect(isAlertError(error.NoRenegotiation));
    try testing.expect(isAlertError(error.MissingExtension));
    try testing.expect(isAlertError(error.UnsupportedExtension));
    try testing.expect(isAlertError(error.CertificateUnobtainable));
    try testing.expect(isAlertError(error.UnrecognizedName));
    try testing.expect(isAlertError(error.BadCertificateStatusResponse));
    try testing.expect(isAlertError(error.BadCertificateHashValue));
    try testing.expect(isAlertError(error.UnknownPskIdentity));
    try testing.expect(isAlertError(error.CertificateRequired));
    try testing.expect(isAlertError(error.NoApplicationProtocol));

    try testing.expect(!isAlertError(error.OutOfMemory));
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
