// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
pub const ClientAuthType = enum(u3) {
    // NoClientCert indicates that no client certificate should be requested
    // during the handshake, and if any certificates are sent they will not
    // be verified.
    no_client_cert = 0,
    // RequestClientCert indicates that a client certificate should be requested
    // during the handshake, but does not require that the client send any
    // certificates.
    request_client_cert = 1,
    // RequireAnyClientCert indicates that a client certificate should be requested
    // during the handshake, and that at least one certificate is required to be
    // sent by the client, but that certificate is not required to be valid.
    require_any_client_cert = 2,
    // VerifyClientCertIfGiven indicates that a client certificate should be requested
    // during the handshake, but does not require that the client sends a
    // certificate. If the client does send a certificate it is required to be
    // valid.
    verify_client_cert_if_given = 3,
    // RequireAndVerifyClientCert indicates that a client certificate should be requested
    // during the handshake, and that at least one valid certificate is required
    // to be sent by the client.
    require_and_verify_client_cert = 4,

    // requiresClientCert reports whether the ClientAuthType requires a client
    // certificate to be provided.
    pub fn requiresClientCert(c: ClientAuthType) bool {
        return switch (c) {
            .request_client_cert, .require_any_client_cert => true,
            else => false,
        };
    }
};
