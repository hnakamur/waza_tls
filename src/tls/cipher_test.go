package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"hash"
	"io"
	"log"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestPrefixNonceAeadAES128GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 16)
	noncePrefix := bytes.Repeat([]byte{'p'}, 4)
	aead := aeadAESGCM(key, noncePrefix)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	explicitNonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, explicitNonce, plaintext, additionalData)
	want := []byte("\x4b\x94\x1c\x11\x1c\xc9\xe9\xdb\x4d\xa6\xdb\xf7\x69\xda\x42\x81\x07\xb4\x8a\x4c\x64\xda\x24\x62\xfc\xbc\xab\xb7\xfd\x76\x5e\x62")
	// want is ciphertext + tag (whose length is 16 byte = aead.Overhead())
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}

	decrypted, err := aead.Open(nil, explicitNonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestPrefixNonceAeadAES256GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 32)
	noncePrefix := bytes.Repeat([]byte{'p'}, 4)
	aead := aeadAESGCM(key, noncePrefix)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	explicitNonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, explicitNonce, plaintext, additionalData)
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))
	want := []byte("\x1a\xd2\x36\x15\xdd\xe3\x47\xec\xa5\x7d\xf1\x73\xef\xe8\xfa\x10\x9d\x47\x5e\x0a\x47\x05\xcb\x51\xd3\xba\x47\x31\xe8\x79\xad\xb9")
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}

	decrypted, err := aead.Open(nil, explicitNonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestXorNonceAeadAES128GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 16)
	nonceMask := bytes.Repeat([]byte{'m'}, 12)
	aead := aeadAESGCMTLS13(key, nonceMask)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	nonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	// want is ciphertext + tag (whose length is 16 byte = aead.Overhead())
	want := []byte("\x58\x92\x14\xf9\x47\x1f\x36\xc4\x95\x25\xe3\x16\x45\xc5\xbe\x39\xbc\xfa\xd7\x22\x79\xe1\xff\x3f\xcb\x1a\x51\x0d\x92\x2b\xbd\x8f")
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestXorNonceAeadAES256GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 32)
	nonceMask := bytes.Repeat([]byte{'m'}, 12)
	aead := aeadAESGCMTLS13(key, nonceMask)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	nonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	// want is ciphertext + tag (whose length is 16 byte = aead.Overhead())
	want := []byte("\x61\x91\xb6\x55\xb7\x04\x54\xbf\xf5\x94\x4e\x7d\xbd\x83\x6b\x84\x90\xcc\x27\x9a\xb8\x5d\x84\xf4\xcf\x67\x05\x27\x22\x27\xd4\x58")
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestXorNonceAeadChaCha20Poly1305(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 32)
	nonceMask := bytes.Repeat([]byte{'m'}, 12)
	aead := aeadChaCha20Poly1305(key, nonceMask)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	nonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	// want is ciphertext + tag (whose length is 16 byte = aead.Overhead())
	want := []byte("\xdf\x39\x03\x0c\xb1\x2f\xe4\xf9\x24\xeb\x76\x15\x80\x4c\x40\xed\xd8\x1f\x15\x82\xfc\x6c\x15\x62\x12\x9c\x8f\x77\x77\x11\x91\x60")
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 16)
	noncePrefix := bytes.Repeat([]byte{'p'}, 4)
	c := aeadAESGCM(key, noncePrefix)
	hc := halfConn{version: VersionTLS12, cipher: c}

	data := []byte("hello")
	encrypted, err := hc.testEncrypt(nil, recordTypeApplicationData, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("encrypted=%x", encrypted)

	decrypted, dec_type, err := hc.decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("decrypted=%q, dec_type=%v", decrypted, dec_type)
	if got, want := decrypted, data; !bytes.Equal(got, want) {
		t.Errorf("decrypted data mismatch, got=%q, want=%q", string(got), string(want))
	}
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	VersionSSL30 = 0x0300
)

const (
	maxPlaintext = 16384 // maximum plaintext payload length

	recordHeaderLen = 5 // record header length
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

type alert uint8

const (
	// alert level
	alertLevelWarning = 1
	alertLevelError   = 2
)

const (
	alertCloseNotify                  alert = 0
	alertUnexpectedMessage            alert = 10
	alertBadRecordMAC                 alert = 20
	alertDecryptionFailed             alert = 21
	alertRecordOverflow               alert = 22
	alertDecompressionFailure         alert = 30
	alertHandshakeFailure             alert = 40
	alertBadCertificate               alert = 42
	alertUnsupportedCertificate       alert = 43
	alertCertificateRevoked           alert = 44
	alertCertificateExpired           alert = 45
	alertCertificateUnknown           alert = 46
	alertIllegalParameter             alert = 47
	alertUnknownCA                    alert = 48
	alertAccessDenied                 alert = 49
	alertDecodeError                  alert = 50
	alertDecryptError                 alert = 51
	alertExportRestriction            alert = 60
	alertProtocolVersion              alert = 70
	alertInsufficientSecurity         alert = 71
	alertInternalError                alert = 80
	alertInappropriateFallback        alert = 86
	alertUserCanceled                 alert = 90
	alertNoRenegotiation              alert = 100
	alertMissingExtension             alert = 109
	alertUnsupportedExtension         alert = 110
	alertCertificateUnobtainable      alert = 111
	alertUnrecognizedName             alert = 112
	alertBadCertificateStatusResponse alert = 113
	alertBadCertificateHashValue      alert = 114
	alertUnknownPSKIdentity           alert = 115
	alertCertificateRequired          alert = 116
	alertNoApplicationProtocol        alert = 120
)

var alertText = map[alert]string{
	alertCloseNotify:                  "close notify",
	alertUnexpectedMessage:            "unexpected message",
	alertBadRecordMAC:                 "bad record MAC",
	alertDecryptionFailed:             "decryption failed",
	alertRecordOverflow:               "record overflow",
	alertDecompressionFailure:         "decompression failure",
	alertHandshakeFailure:             "handshake failure",
	alertBadCertificate:               "bad certificate",
	alertUnsupportedCertificate:       "unsupported certificate",
	alertCertificateRevoked:           "revoked certificate",
	alertCertificateExpired:           "expired certificate",
	alertCertificateUnknown:           "unknown certificate",
	alertIllegalParameter:             "illegal parameter",
	alertUnknownCA:                    "unknown certificate authority",
	alertAccessDenied:                 "access denied",
	alertDecodeError:                  "error decoding message",
	alertDecryptError:                 "error decrypting message",
	alertExportRestriction:            "export restriction",
	alertProtocolVersion:              "protocol version not supported",
	alertInsufficientSecurity:         "insufficient security level",
	alertInternalError:                "internal error",
	alertInappropriateFallback:        "inappropriate fallback",
	alertUserCanceled:                 "user canceled",
	alertNoRenegotiation:              "no renegotiation",
	alertMissingExtension:             "missing extension",
	alertUnsupportedExtension:         "unsupported extension",
	alertCertificateUnobtainable:      "certificate unobtainable",
	alertUnrecognizedName:             "unrecognized name",
	alertBadCertificateStatusResponse: "bad certificate status response",
	alertBadCertificateHashValue:      "bad certificate hash value",
	alertUnknownPSKIdentity:           "unknown PSK identity",
	alertCertificateRequired:          "certificate required",
	alertNoApplicationProtocol:        "no application protocol",
}

func (e alert) String() string {
	s, ok := alertText[e]
	if ok {
		return "tls: " + s
	}
	return "tls: alert(" + strconv.Itoa(int(e)) + ")"
}

func (e alert) Error() string {
	return e.String()
}

// A halfConn represents one direction of the record layer
// connection, either sending or receiving.
type halfConn struct {
	sync.Mutex

	err     error  // first permanent error
	version uint16 // protocol version
	cipher  any    // cipher algorithm
	mac     hash.Hash
	seq     [8]byte // 64-bit sequence number

	scratchBuf [13]byte // to avoid allocs; interface method args escape

	nextCipher any       // next encryption state
	nextMac    hash.Hash // next MAC algorithm

	trafficSecret []byte // current TLS 1.3 traffic secret
}

func (hc *halfConn) testEncrypt(outBuf []byte, typ recordType, data []byte) ([]byte, error) {
	m := len(data)
	// if maxPayload := c.maxPayloadSizeForWrite(typ); m > maxPayload {
	// 	m = maxPayload
	// }

	_, outBuf = sliceForAppend(outBuf[:0], recordHeaderLen)
	outBuf[0] = byte(typ)
	vers := hc.version
	if vers == 0 {
		// Some TLS servers fail if the record version is
		// greater than TLS 1.0 for the initial ClientHello.
		vers = VersionTLS10
	} else if vers == VersionTLS13 {
		// TLS 1.3 froze the record layer version to 1.2.
		// See RFC 8446, Section 5.1.
		vers = VersionTLS12
	}
	outBuf[1] = byte(vers >> 8)
	outBuf[2] = byte(vers)
	outBuf[3] = byte(m >> 8)
	outBuf[4] = byte(m)

	var err error
	outBuf, err = hc.encrypt(outBuf, data[:m], rand.Reader)
	if err != nil {
		return outBuf, err
	}

	return outBuf, nil
}

// encrypt encrypts payload, adding the appropriate nonce and/or MAC, and
// appends it to record, which must already contain the record header.
func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader) ([]byte, error) {
	if hc.cipher == nil {
		return append(record, payload...), nil
	}

	var explicitNonce []byte
	if explicitNonceLen := hc.explicitNonceLen(); explicitNonceLen > 0 {
		record, explicitNonce = sliceForAppend(record, explicitNonceLen)
		// if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
		// 	// The AES-GCM construction in TLS has an explicit nonce so that the
		// 	// nonce can be random. However, the nonce is only 8 bytes which is
		// 	// too small for a secure, random nonce. Therefore we use the
		// 	// sequence number as the nonce. The 3DES-CBC construction also has
		// 	// an 8 bytes nonce but its nonces must be unpredictable (see RFC
		// 	// 5246, Appendix F.3), forcing us to use randomness. That's not
		// 	// 3DES' biggest problem anyway because the birthday bound on block
		// 	// collision is reached first due to its similarly small block size
		// 	// (see the Sweet32 attack).
		// 	copy(explicitNonce, hc.seq[:])
		// } else {
		if _, err := io.ReadFull(rand, explicitNonce); err != nil {
			return nil, err
		}
		// }
	}

	// var dst []byte
	switch c := hc.cipher.(type) {
	// case cipher.Stream:
	// 	mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
	// 	record, dst = sliceForAppend(record, len(payload)+len(mac))
	// 	c.XORKeyStream(dst[:len(payload)], payload)
	// 	c.XORKeyStream(dst[len(payload):], mac)
	case aead:
		nonce := explicitNonce
		if len(nonce) == 0 {
			nonce = hc.seq[:]
		}

		if hc.version == VersionTLS13 {
			record = append(record, payload...)

			// Encrypt the actual ContentType and replace the plaintext one.
			record = append(record, record[0])
			record[0] = byte(recordTypeApplicationData)

			n := len(payload) + 1 + c.Overhead()
			record[3] = byte(n >> 8)
			record[4] = byte(n)

			record = c.Seal(record[:recordHeaderLen],
				nonce, record[recordHeaderLen:], record[:recordHeaderLen])
		} else {
			additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
			additionalData = append(additionalData, record[:recordHeaderLen]...)
			record = c.Seal(record, nonce, payload, additionalData)
		}
	// case cbcMode:
	// 	mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
	// 	blockSize := c.BlockSize()
	// 	plaintextLen := len(payload) + len(mac)
	// 	paddingLen := blockSize - plaintextLen%blockSize
	// 	record, dst = sliceForAppend(record, plaintextLen+paddingLen)
	// 	copy(dst, payload)
	// 	copy(dst[len(payload):], mac)
	// 	for i := plaintextLen; i < len(dst); i++ {
	// 		dst[i] = byte(paddingLen - 1)
	// 	}
	// 	if len(explicitNonce) > 0 {
	// 		c.SetIV(explicitNonce)
	// 	}
	// 	c.CryptBlocks(dst, dst)
	default:
		panic("unknown cipher type")
	}

	// Update length to include nonce, MAC and any block padding needed.
	n := len(record) - recordHeaderLen
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	// commented out for test
	// hc.incSeq()

	return record, nil
}

// decrypt authenticates and decrypts the record if protection is active at
// this stage. The returned plaintext might overlap with the input.
func (hc *halfConn) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	// In TLS 1.3, change_cipher_spec messages are to be ignored without being
	// decrypted. See RFC 8446, Appendix D.4.
	if hc.version == VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	// paddingGood := byte(255)
	// paddingLen := 0

	explicitNonceLen := hc.explicitNonceLen()
	log.Printf("typ=%d, explicitNonceLen=%d, len(payload)=%d", typ, explicitNonceLen, len(payload))

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		// case cipher.Stream:
		// 	c.XORKeyStream(payload, payload)
		case aead:
			if len(payload) < explicitNonceLen {
				return nil, 0, alertBadRecordMAC
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				nonce = hc.seq[:]
			}
			payload = payload[explicitNonceLen:]
			log.Printf("nonce=%x, payloadWithoutNonce=%x", nonce, payload)

			var additionalData []byte
			if hc.version == VersionTLS13 {
				additionalData = record[:recordHeaderLen]
			} else {
				additionalData = append(hc.scratchBuf[:0], hc.seq[:]...)
				additionalData = append(additionalData, record[:3]...)
				n := len(payload) - c.Overhead()
				additionalData = append(additionalData, byte(n>>8), byte(n))
			}

			var err error
			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
			if err != nil {
				log.Printf("halfConn.decrypt Open err=%v", err)
				return nil, 0, alertBadRecordMAC
			}
		// case cbcMode:
		// 	blockSize := c.BlockSize()
		// 	minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
		// 	if len(payload)%blockSize != 0 || len(payload) < minPayload {
		// 		return nil, 0, alertBadRecordMAC
		// 	}

		// 	if explicitNonceLen > 0 {
		// 		c.SetIV(payload[:explicitNonceLen])
		// 		payload = payload[explicitNonceLen:]
		// 	}
		// 	c.CryptBlocks(payload, payload)

		// 	// In a limited attempt to protect against CBC padding oracles like
		// 	// Lucky13, the data past paddingLen (which is secret) is passed to
		// 	// the MAC function as extra data, to be fed into the HMAC after
		// 	// computing the digest. This makes the MAC roughly constant time as
		// 	// long as the digest computation is constant time and does not
		// 	// affect the subsequent write, modulo cache effects.
		// 	paddingLen, paddingGood = extractPadding(payload)
		default:
			panic("unknown cipher type")
		}

		if hc.version == VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, alertUnexpectedMessage
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, alertRecordOverflow
			}
			// Remove padding and find the ContentType scanning from the end.
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, alertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	// if hc.mac != nil {
	// 	macSize := hc.mac.Size()
	// 	if len(payload) < macSize {
	// 		return nil, 0, alertBadRecordMAC
	// 	}

	// 	n := len(payload) - macSize - paddingLen
	// 	n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
	// 	record[3] = byte(n >> 8)
	// 	record[4] = byte(n)
	// 	remoteMAC := payload[n : n+macSize]
	// 	localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

	// 	// This is equivalent to checking the MACs and paddingGood
	// 	// separately, but in constant-time to prevent distinguishing
	// 	// padding failures from MAC failures. Depending on what value
	// 	// of paddingLen was returned on bad padding, distinguishing
	// 	// bad MAC from bad padding can lead to an attack.
	// 	//
	// 	// See also the logic at the end of extractPadding.
	// 	macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
	// 	if macAndPaddingGood != 1 {
	// 		return nil, 0, alertBadRecordMAC
	// 	}

	// 	plaintext = payload[:n]
	// }

	hc.incSeq()
	return plaintext, typ, nil
}

// incSeq increments the sequence number.
func (hc *halfConn) incSeq() {
	for i := 7; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("TLS: sequence number wraparound")
}

// explicitNonceLen returns the number of bytes of explicit nonce or IV included
// in each record. Explicit nonces are present only in CBC modes after TLS 1.0
// and in certain AEAD modes in TLS 1.2.
func (hc *halfConn) explicitNonceLen() int {
	if hc.cipher == nil {
		return 0
	}

	switch c := hc.cipher.(type) {
	// case cipher.Stream:
	// 	return 0
	case aead:
		return c.explicitNonceLen()
	// case cbcMode:
	// 	// TLS 1.1 introduced a per-record explicit IV to fix the BEAST attack.
	// 	if hc.version >= VersionTLS11 {
	// 		return c.BlockSize()
	// 	}
	// 	return 0
	default:
		panic("unknown cipher type")
	}
}

func aeadAESGCM(key, noncePrefix []byte) aead {
	if len(noncePrefix) != noncePrefixLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &prefixNonceAEAD{aead: aead}
	copy(ret.nonce[:], noncePrefix)
	return ret
}

func aeadAESGCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

// prefixNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type prefixNonceAEAD struct {
	// nonce contains the fixed part of the nonce in the first four bytes.
	nonce [aeadNonceLength]byte
	aead  cipher.AEAD
}

func (f *prefixNonceAEAD) NonceSize() int        { return aeadNonceLength - noncePrefixLength }
func (f *prefixNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *prefixNonceAEAD) explicitNonceLen() int { return f.NonceSize() }

func (f *prefixNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[4:], nonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

func (f *prefixNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[4:], nonce)
	return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
}

// xoredNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}

func TestAES128GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 16)
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		t.Fatal(err)
	}

	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	nonce := bytes.Repeat([]byte{'n'}, 12)
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	want := []byte("\x5e\x84\x2b\xcb\x73\x09\x9c\xcf\xdd\x8e\x7e\x27\x1c\x07\x14\xef\x74\xe2\xdf\xb3\x6e\x31\x90\x6f\xd5\xd1\x17\xd4\xa1\x7a\x14\x2d")
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}
