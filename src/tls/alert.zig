const std = @import("std");

pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,

    pub fn fromAlertError(err: AlertError) AlertLevel {
        return switch (err) {
            error.NoRenegotiation, error.CloseNotify => .warning,
            else => .fatal,
        };
    }
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

    pub fn fromAlertError(err: AlertError) AlertDescription {
        return switch (err) {
            error.CloseNotify => .close_notify,
            error.UnexpectedMessage => .unexpected_message,
            error.BadRecordMAC => .bad_record_mac,
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
            error.UnknownCA => .unknown_ca,
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
            error.UnknownPSKIdentity => .unknown_psk_identity,
            error.CertificateRequired => .certificate_required,
            error.NoApplicationProtocol => .no_application_protocol,
        };
    }
};

pub const AlertError = error{
    CloseNotify,
    UnexpectedMessage,
    BadRecordMAC,
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
    UnknownCA,
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
    UnknownPSKIdentity,
    CertificateRequired,
    NoApplicationProtocol,
};

const testing = std.testing;

test "AlertLevel.fromAlertError" {
    const f = struct {
        fn f(want: AlertLevel, err: AlertError) !void {
            try testing.expectEqual(want, AlertLevel.fromAlertError(err));
        }
    }.f;

    try f(.warning, error.CloseNotify);
    try f(.fatal, error.UnexpectedMessage);
    try f(.fatal, error.BadRecordMAC);
    try f(.fatal, error.DecryptionFailed);
    try f(.fatal, error.RecordOverflow);
    try f(.fatal, error.DecompressionFailure);
    try f(.fatal, error.HandshakeFailure);
    try f(.fatal, error.BadCertificate);
    try f(.fatal, error.UnsupportedCertificate);
    try f(.fatal, error.CertificateRevoked);
    try f(.fatal, error.CertificateExpired);
    try f(.fatal, error.CertificateUnknown);
    try f(.fatal, error.IllegalParameter);
    try f(.fatal, error.UnknownCA);
    try f(.fatal, error.AccessDenied);
    try f(.fatal, error.DecodeError);
    try f(.fatal, error.DecryptError);
    try f(.fatal, error.ExportRestriction);
    try f(.fatal, error.ProtocolVersion);
    try f(.fatal, error.InsufficientSecurity);
    try f(.fatal, error.InternalError);
    try f(.fatal, error.InappropriateFallback);
    try f(.fatal, error.UserCanceled);
    try f(.warning, error.NoRenegotiation);
    try f(.fatal, error.MissingExtension);
    try f(.fatal, error.UnsupportedExtension);
    try f(.fatal, error.CertificateUnobtainable);
    try f(.fatal, error.UnrecognizedName);
    try f(.fatal, error.BadCertificateStatusResponse);
    try f(.fatal, error.BadCertificateHashValue);
    try f(.fatal, error.UnknownPSKIdentity);
    try f(.fatal, error.CertificateRequired);
    try f(.fatal, error.NoApplicationProtocol);
}

test "AlertDescription.fromAlertError" {
    const f = struct {
        fn f(want: AlertDescription, err: AlertError) !void {
            try testing.expectEqual(want, AlertDescription.fromAlertError(err));
        }
    }.f;

    try f(.close_notify, error.CloseNotify);
    try f(.unexpected_message, error.UnexpectedMessage);
    try f(.bad_record_mac, error.BadRecordMAC);
    try f(.decryption_failed, error.DecryptionFailed);
    try f(.record_overflow, error.RecordOverflow);
    try f(.decompression_failure, error.DecompressionFailure);
    try f(.handshake_failure, error.HandshakeFailure);
    try f(.bad_certificate, error.BadCertificate);
    try f(.unsupported_certificate, error.UnsupportedCertificate);
    try f(.certificate_revoked, error.CertificateRevoked);
    try f(.certificate_expired, error.CertificateExpired);
    try f(.certificate_unknown, error.CertificateUnknown);
    try f(.illegal_parameter, error.IllegalParameter);
    try f(.unknown_ca, error.UnknownCA);
    try f(.access_denied, error.AccessDenied);
    try f(.decode_error, error.DecodeError);
    try f(.decrypt_error, error.DecryptError);
    try f(.export_restriction, error.ExportRestriction);
    try f(.protocol_version, error.ProtocolVersion);
    try f(.insufficient_security, error.InsufficientSecurity);
    try f(.internal_error, error.InternalError);
    try f(.inappropriate_fallback, error.InappropriateFallback);
    try f(.user_canceled, error.UserCanceled);
    try f(.no_renegotiation, error.NoRenegotiation);
    try f(.missing_extension, error.MissingExtension);
    try f(.unsupported_extension, error.UnsupportedExtension);
    try f(.certificate_unobtainable, error.CertificateUnobtainable);
    try f(.unrecognized_name, error.UnrecognizedName);
    try f(.bad_certificate_status_response, error.BadCertificateStatusResponse);
    try f(.bad_certificate_hash_value, error.BadCertificateHashValue);
    try f(.unknown_psk_identity, error.UnknownPSKIdentity);
    try f(.certificate_required, error.CertificateRequired);
    try f(.no_application_protocol, error.NoApplicationProtocol);
}
