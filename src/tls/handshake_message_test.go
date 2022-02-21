package main

import (
	"bytes"
	"crypto/tls"
	"log"
	"math/rand"
	"reflect"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeMessageHash         uint8 = 254 // synthetic message
)

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionRenegotiationInfo       uint16 = 0xff01
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

func TestEncryptedExtensionsMsgMarshalUnmarshal(t *testing.T) {
	msg := encryptedExtensionsMsg{alpnProtocol: "h2"}
	marshaled := msg.marshal()
	// log.Printf("marshaled encryptedExtensionsMsg=%x", marshaled)
	wantMarshaled := []byte("\x08\x00\x00\x0b\x00\x09\x00\x10\x00\x05\x00\x03\x02\x68\x32")
	if got, want := marshaled, wantMarshaled; !bytes.Equal(got, want) {
		t.Errorf("marshal result mismatch, got=%x, want=%x", got, want)
	}

	msg2 := encryptedExtensionsMsg{}
	if !msg2.unmarshal(marshaled) {
		t.Errorf("unmarshal failed")
	}
	if got, want := msg2.alpnProtocol, msg.alpnProtocol; got != want {
		t.Errorf("alpnProtocol mismatch, got=%s, want=%s", got, want)
	}
}

type encryptedExtensionsMsg struct {
	raw          []byte
	alpnProtocol string
}

func (m *encryptedExtensionsMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeEncryptedExtensions)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if len(m.alpnProtocol) > 0 {
				b.AddUint16(extensionALPN)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(m.alpnProtocol))
						})
					})
				})
			}
		})
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *encryptedExtensionsMsg) unmarshal(data []byte) bool {
	*m = encryptedExtensionsMsg{raw: data}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type certificateMsgTLS13 struct {
	raw          []byte
	certificate  tls.Certificate
	ocspStapling bool
	scts         bool
}

func (m *certificateMsgTLS13) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // certificate_request_context

		certificate := m.certificate
		if !m.ocspStapling {
			certificate.OCSPStaple = nil
		}
		if !m.scts {
			certificate.SignedCertificateTimestamps = nil
		}
		marshalCertificate(b, certificate)
	})

	m.raw = b.BytesOrPanic()
	// log.Printf("certificate=%+v, ocspStapling=%v, scts=%v, raw=%x", m.certificate, m.ocspStapling, m.scts, m.raw)
	return m.raw
}

func marshalCertificate(b *cryptobyte.Builder, certificate tls.Certificate) {
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for i, cert := range certificate.Certificate {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(cert)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				if i > 0 {
					// This library only supports OCSP and SCT for leaf certificates.
					return
				}
				if certificate.OCSPStaple != nil {
					b.AddUint16(extensionStatusRequest)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(statusTypeOCSP)
						b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(certificate.OCSPStaple)
						})
					})
				}
				if certificate.SignedCertificateTimestamps != nil {
					b.AddUint16(extensionSCT)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, sct := range certificate.SignedCertificateTimestamps {
								b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
									b.AddBytes(sct)
								})
							}
						})
					})
				}
			})
		}
	})
}

func (m *certificateMsgTLS13) unmarshal(data []byte) bool {
	*m = certificateMsgTLS13{raw: data}
	s := cryptobyte.String(data)

	var context cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
		!unmarshalCertificate(&s, &m.certificate) ||
		!s.Empty() {
		return false
	}

	m.scts = m.certificate.SignedCertificateTimestamps != nil
	m.ocspStapling = m.certificate.OCSPStaple != nil

	return true
}

func unmarshalCertificate(s *cryptobyte.String, certificate *tls.Certificate) bool {
	var certList cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&certList) {
		return false
	}
	for !certList.Empty() {
		var cert []byte
		var extensions cryptobyte.String
		if !readUint24LengthPrefixed(&certList, &cert) ||
			!certList.ReadUint16LengthPrefixed(&extensions) {
			return false
		}
		certificate.Certificate = append(certificate.Certificate, cert)
		for !extensions.Empty() {
			var extension uint16
			var extData cryptobyte.String
			if !extensions.ReadUint16(&extension) ||
				!extensions.ReadUint16LengthPrefixed(&extData) {
				return false
			}
			if len(certificate.Certificate) > 1 {
				// This library only supports OCSP and SCT for leaf certificates.
				continue
			}

			switch extension {
			case extensionStatusRequest:
				var statusType uint8
				if !extData.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
					!readUint24LengthPrefixed(&extData, &certificate.OCSPStaple) ||
					len(certificate.OCSPStaple) == 0 {
					return false
				}
			case extensionSCT:
				var sctList cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
					return false
				}
				for !sctList.Empty() {
					var sct []byte
					if !readUint16LengthPrefixed(&sctList, &sct) ||
						len(sct) == 0 {
						return false
					}
					certificate.SignedCertificateTimestamps = append(
						certificate.SignedCertificateTimestamps, sct)
				}
			default:
				// Ignore unknown extensions.
				continue
			}

			if !extData.Empty() {
				return false
			}
		}
	}
	return true
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed acts like s.ReadUint24LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

func randomBytes(n int, rand *rand.Rand) []byte {
	r := make([]byte, n)
	if _, err := rand.Read(r); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	return r
}

func GenerateRnadomCertificateMsgTLS13(rand *rand.Rand) *certificateMsgTLS13 {
	m := &certificateMsgTLS13{}
	for i := 0; i < 2; i++ {
		cert := randomBytes(rand.Intn(50)+1, rand)
		log.Printf("cert=%x", cert)
		m.certificate.Certificate = append(
			m.certificate.Certificate, cert)
	}
	m.ocspStapling = true
	m.certificate.OCSPStaple = randomBytes(rand.Intn(20)+1, rand)
	log.Printf("OCSPStaple=%x", m.certificate.OCSPStaple)
	m.scts = true
	for i := 0; i < 2; i++ {
		sct := randomBytes(rand.Intn(20)+1, rand)
		log.Printf("sct=%x", sct)
		m.certificate.SignedCertificateTimestamps = append(
			m.certificate.SignedCertificateTimestamps, sct)
	}
	return m
}

func TestCertificateMsgTLS13MarshalUnmarshal(t *testing.T) {
	// msg := GenerateRnadomCertificateMsgTLS13(rand.New(rand.NewSource(time.Now().UnixNano())))
	msg := certificateMsgTLS13{
		certificate: tls.Certificate{
			Certificate: [][]byte{
				[]byte("\x24\x0a\xde\xde\x3d\x3b\xa4\x35\xbc\x02\xf8\x87\x18\x0a\x61"),
				[]byte("\x52\xbb\x1f\x7f\x74\x18\x31\x74\x96\x33\x91\xac\x1a\xa3\x29\xfd\xa7\xb7\x56\x02\x72\xbb\x16\xd9\xbe\xc7\x81\x73\xd4\x01\x80\x61\x18\x1a\x1e"),
			},
			OCSPStaple: []byte("\x4d\xab\x72\x65\x6e\x8d"),
			SignedCertificateTimestamps: [][]byte{
				[]byte("\x49\x81\xed\x50\x1d\x4d\x4d\x0e\x04\x2d\xeb\xcb\xcf"),
				[]byte("\x30\x9d\x61\xf4\xab\xeb\xb1\xf5\x7c"),
			},
		},
		ocspStapling: true,
		scts:         true,
	}
	marshaled := msg.marshal()
	// log.Printf("marshaled CertificateMsgTLS13=%x", marshaled)
	wantMarshaled := []byte("\x0b\x00\x00\x6e\x00\x00\x00\x6a\x00\x00\x0f\x24\x0a\xde\xde\x3d\x3b\xa4\x35\xbc\x02\xf8\x87\x18\x0a\x61\x00\x2e\x00\x05\x00\x0a\x01\x00\x00\x06\x4d\xab\x72\x65\x6e\x8d\x00\x12\x00\x1c\x00\x1a\x00\x0d\x49\x81\xed\x50\x1d\x4d\x4d\x0e\x04\x2d\xeb\xcb\xcf\x00\x09\x30\x9d\x61\xf4\xab\xeb\xb1\xf5\x7c\x00\x00\x23\x52\xbb\x1f\x7f\x74\x18\x31\x74\x96\x33\x91\xac\x1a\xa3\x29\xfd\xa7\xb7\x56\x02\x72\xbb\x16\xd9\xbe\xc7\x81\x73\xd4\x01\x80\x61\x18\x1a\x1e\x00\x00")
	if got, want := marshaled, wantMarshaled; !bytes.Equal(got, want) {
		t.Errorf("marshal result mismatch, got=%x, want=%x", got, want)
	}

	msg2 := certificateMsgTLS13{}
	if !msg2.unmarshal(marshaled) {
		t.Errorf("unmarshal failed")
	}
	if got, want := msg2, msg; !reflect.DeepEqual(got, want) {
		t.Errorf("unmarshal result mismatch, got=%+v, want=%+v", got, want)
	}
}
