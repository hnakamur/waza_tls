const std = @import("std");

pub const StatusCode = enum(u10) {
    // based on 2021-10-01 version of
    // https://www.iana.org/assignments/http-status-codes/http-status-codes.txt

    @"continue" = 100,
    switching_protocols = 101,
    processing = 102,
    early_hints = 103,
    // 104-199 Unassigned

    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative_information = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,
    multi_status = 207,
    already_reported = 208,
    // 209-225 Unassigned
    im_used = 226,
    // 227-299 Unassigned

    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    use_proxy = 305,
    // 306 (Unused)
    temporary_redirect = 307,
    permanent_redirect = 308,
    // 309-399 Unassigned

    bad_request = 400,
    unauthorized = 401,
    payment_required = 402,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    proxy_authentication_required = 407,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    content_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    // 418 (Unused)
    // 419-420 Unassigned
    misdirected_request = 421,
    unprocessable_content = 422,
    locked = 423,
    failed_dependency = 424,
    too_early = 425,
    upgrade_required = 426,
    // 427 Unassigned
    precondition_required = 428,
    too_many_requests = 429,
    // 430 Unassigned
    request_header_fields_too_large = 431,
    // 432-450 Unassigned
    unavailable_for_legal_reasons = 451,
    // 452-499 Unassigned

    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,
    variant_also_negotiates = 506,
    insufficient_storage = 507,
    loop_detected = 508,
    // 509 Unassigned
    not_extended = 510,
    network_authentication_required = 511,
    // 512-599 Unassigned

    _,

    pub fn code(self: StatusCode) std.meta.Tag(StatusCode) {
        return @enumToInt(self);
    }

    pub fn isValid(self: StatusCode) bool {
        return self.group() != .invalid;
    }

    pub fn fromBytes(input: []const u8) !StatusCode {
        if (input.len != 3) return error.InvalidInput;
        var v: u10 = 0;
        for (input) |c| {
            v *= 10;
            v += try std.fmt.charToDigit(c, 10);
        }
        return @intToEnum(StatusCode, v);
    }

    pub fn toText(self: StatusCode) []const u8 {
        return switch (self) {
            .@"continue" => "Continue",
            .switching_protocols => "Switching Protocols",
            .processing => "Processing",
            .early_hints => "Early Hints",

            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .non_authoritative_information => "Non-Authoritative Information",
            .no_content => "No Content",
            .reset_content => "Reset Content",
            .partial_content => "Partial Content",
            .multi_status => "Multi-Status",
            .already_reported => "Already Reported",
            .im_used => "IM Used",

            .multiple_choices => "Multiple Choices",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .not_modified => "Not Modified",
            .use_proxy => "Use Proxy",
            .temporary_redirect => "Temporary Redirect",
            .permanent_redirect => "Permanent Redirect",

            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .payment_required => "Payment Required",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .not_acceptable => "Not Acceptable",
            .proxy_authentication_required => "Proxy Authentication Required",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .precondition_failed => "Precondition Failed",
            .content_too_large => "Content Too Large",
            .uri_too_long => "URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .range_not_satisfiable => "Range Not Satisfiable",
            .expectation_failed => "Expectation Failed",
            .misdirected_request => "Misdirected Request",
            .unprocessable_content => "Unprocessable Content",
            .locked => "Locked",
            .failed_dependency => "Failed Dependency",
            .too_early => "Too Early",
            .upgrade_required => "Upgrade Required",
            .precondition_required => "Precondition Required",
            .too_many_requests => "Too Many Requests",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .unavailable_for_legal_reasons => "Unavailable For Legal Reasons",

            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
            .variant_also_negotiates => "Variant Also Negotiates",
            .insufficient_storage => "Insufficient Storage",
            .loop_detected => "Loop Detected",
            .not_extended => "Not Extended",
            .network_authentication_required => "Network Authentication Required",

            else => "",
        };
    }

    pub const Group = enum {
        info,
        success,
        redirect,
        client_error,
        server_error,
        invalid,
    };

    pub fn group(self: StatusCode) Group {
        return switch (self.code()) {
            100...199 => .info,
            200...299 => .success,
            300...399 => .redirect,
            400...499 => .client_error,
            500...599 => .server_error,
            else => .invalid,
        };
    }
};

const testing = std.testing;

test "StatusCode" {
    try testing.expectEqual(@as(u10, 100), StatusCode.@"continue".code());
    try testing.expectEqual(@as(u10, 499), @intToEnum(StatusCode, 499).code());

    try testing.expectEqual(StatusCode.@"continue", try StatusCode.fromBytes("100"));
    try testing.expectEqual(StatusCode.network_authentication_required, try StatusCode.fromBytes("511"));
    try testing.expectError(error.InvalidInput, StatusCode.fromBytes("5110"));
    try testing.expectError(error.InvalidCharacter, StatusCode.fromBytes("51A"));

    try testing.expectEqualStrings("Continue", StatusCode.@"continue".toText());
    try testing.expectEqualStrings("Switching Protocols", StatusCode.switching_protocols.toText());
    try testing.expectEqualStrings("Processing", StatusCode.processing.toText());
    try testing.expectEqualStrings("Early Hints", StatusCode.early_hints.toText());
    try testing.expectEqualStrings("OK", StatusCode.ok.toText());
    try testing.expectEqualStrings("Created", StatusCode.created.toText());
    try testing.expectEqualStrings("Accepted", StatusCode.accepted.toText());
    try testing.expectEqualStrings("Non-Authoritative Information", StatusCode.non_authoritative_information.toText());
    try testing.expectEqualStrings("No Content", StatusCode.no_content.toText());
    try testing.expectEqualStrings("Reset Content", StatusCode.reset_content.toText());
    try testing.expectEqualStrings("Partial Content", StatusCode.partial_content.toText());
    try testing.expectEqualStrings("Multi-Status", StatusCode.multi_status.toText());
    try testing.expectEqualStrings("Already Reported", StatusCode.already_reported.toText());
    try testing.expectEqualStrings("IM Used", StatusCode.im_used.toText());
    try testing.expectEqualStrings("Multiple Choices", StatusCode.multiple_choices.toText());
    try testing.expectEqualStrings("Moved Permanently", StatusCode.moved_permanently.toText());
    try testing.expectEqualStrings("Found", StatusCode.found.toText());
    try testing.expectEqualStrings("See Other", StatusCode.see_other.toText());
    try testing.expectEqualStrings("Not Modified", StatusCode.not_modified.toText());
    try testing.expectEqualStrings("Use Proxy", StatusCode.use_proxy.toText());
    try testing.expectEqualStrings("Temporary Redirect", StatusCode.temporary_redirect.toText());
    try testing.expectEqualStrings("Permanent Redirect", StatusCode.permanent_redirect.toText());
    try testing.expectEqualStrings("Bad Request", StatusCode.bad_request.toText());
    try testing.expectEqualStrings("Unauthorized", StatusCode.unauthorized.toText());
    try testing.expectEqualStrings("Payment Required", StatusCode.payment_required.toText());
    try testing.expectEqualStrings("Forbidden", StatusCode.forbidden.toText());
    try testing.expectEqualStrings("Not Found", StatusCode.not_found.toText());
    try testing.expectEqualStrings("Method Not Allowed", StatusCode.method_not_allowed.toText());
    try testing.expectEqualStrings("Not Acceptable", StatusCode.not_acceptable.toText());
    try testing.expectEqualStrings("Proxy Authentication Required", StatusCode.proxy_authentication_required.toText());
    try testing.expectEqualStrings("Request Timeout", StatusCode.request_timeout.toText());
    try testing.expectEqualStrings("Conflict", StatusCode.conflict.toText());
    try testing.expectEqualStrings("Gone", StatusCode.gone.toText());
    try testing.expectEqualStrings("Length Required", StatusCode.length_required.toText());
    try testing.expectEqualStrings("Precondition Failed", StatusCode.precondition_failed.toText());
    try testing.expectEqualStrings("Content Too Large", StatusCode.content_too_large.toText());
    try testing.expectEqualStrings("URI Too Long", StatusCode.uri_too_long.toText());
    try testing.expectEqualStrings("Unsupported Media Type", StatusCode.unsupported_media_type.toText());
    try testing.expectEqualStrings("Range Not Satisfiable", StatusCode.range_not_satisfiable.toText());
    try testing.expectEqualStrings("Expectation Failed", StatusCode.expectation_failed.toText());
    try testing.expectEqualStrings("Misdirected Request", StatusCode.misdirected_request.toText());
    try testing.expectEqualStrings("Unprocessable Content", StatusCode.unprocessable_content.toText());
    try testing.expectEqualStrings("Locked", StatusCode.locked.toText());
    try testing.expectEqualStrings("Failed Dependency", StatusCode.failed_dependency.toText());
    try testing.expectEqualStrings("Too Early", StatusCode.too_early.toText());
    try testing.expectEqualStrings("Upgrade Required", StatusCode.upgrade_required.toText());
    try testing.expectEqualStrings("Precondition Required", StatusCode.precondition_required.toText());
    try testing.expectEqualStrings("Too Many Requests", StatusCode.too_many_requests.toText());
    try testing.expectEqualStrings("Request Header Fields Too Large", StatusCode.request_header_fields_too_large.toText());
    try testing.expectEqualStrings("Unavailable For Legal Reasons", StatusCode.unavailable_for_legal_reasons.toText());
    try testing.expectEqualStrings("Internal Server Error", StatusCode.internal_server_error.toText());
    try testing.expectEqualStrings("Not Implemented", StatusCode.not_implemented.toText());
    try testing.expectEqualStrings("Bad Gateway", StatusCode.bad_gateway.toText());
    try testing.expectEqualStrings("Service Unavailable", StatusCode.service_unavailable.toText());
    try testing.expectEqualStrings("Gateway Timeout", StatusCode.gateway_timeout.toText());
    try testing.expectEqualStrings("HTTP Version Not Supported", StatusCode.http_version_not_supported.toText());
    try testing.expectEqualStrings("Variant Also Negotiates", StatusCode.variant_also_negotiates.toText());
    try testing.expectEqualStrings("Insufficient Storage", StatusCode.insufficient_storage.toText());
    try testing.expectEqualStrings("Loop Detected", StatusCode.loop_detected.toText());
    try testing.expectEqualStrings("Not Extended", StatusCode.not_extended.toText());
    try testing.expectEqualStrings("Network Authentication Required", StatusCode.network_authentication_required.toText());
    try testing.expectEqualStrings("", (try StatusCode.fromBytes("418")).toText());

    try testing.expectEqual(StatusCode.Group.info, StatusCode.@"continue".group());
    try testing.expectEqual(StatusCode.Group.success, StatusCode.ok.group());
    try testing.expectEqual(StatusCode.Group.redirect, StatusCode.multiple_choices.group());
    try testing.expectEqual(StatusCode.Group.client_error, StatusCode.bad_request.group());
    try testing.expectEqual(StatusCode.Group.server_error, StatusCode.internal_server_error.group());
    try testing.expectEqual(StatusCode.Group.invalid, (try StatusCode.fromBytes("600")).group());

    try testing.expect(StatusCode.@"continue".isValid());
    try testing.expect(!(try StatusCode.fromBytes("600")).isValid());
}
