// Command webpush is the differential check of src/server/webpush.rs
// against apron-server-go's Web Push code (RFC 8291 aes128gcm and RFC 8292
// VAPID). It imports nothing from the Go clone: encryptPushWith, origin,
// and the base64url helpers are copied from internal/server/webpush.go, and
// decryptPush from internal/server/webpush_test.go, of apron-server-go at
// f137c64 (MIT, Copyright the apron-server-go authors).
//
//	go run . vectors > vectors.json   # Go-encrypted payloads for Rust to open
//	go run . check rust.json          # opens Rust's payloads, verifies its VAPID tokens
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"
)

const (
	p256PointBytes     = 65
	pushRecordSize     = 4096
	pushHeaderBytes    = 16 + 4 + 1 + p256PointBytes
	maxPushPlaintext   = pushRecordSize - pushHeaderBytes - 1 - 16
	vapidTokenLifetime = 12 * time.Hour
)

func decodeBase64URL(text string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(text, "="))
}

func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// encryptPushWith is webpush.go's, with the receiver's key and auth secret
// as arguments in place of pushKeys.
func encryptPushWith(plaintext, p256dh, auth []byte, local *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(plaintext) > maxPushPlaintext {
		return nil, errors.New("push payload is too large")
	}
	receiver, err := ecdh.P256().NewPublicKey(p256dh)
	if err != nil {
		return nil, err
	}
	secret, err := local.ECDH(receiver)
	if err != nil {
		return nil, err
	}
	localPublic := local.PublicKey().Bytes()
	keyInfo := "WebPush: info\x00" + string(p256dh) + string(localPublic)
	ikm, err := hkdf.Key(sha256.New, secret, auth, keyInfo, 32)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	body := make([]byte, pushHeaderBytes, pushHeaderBytes+len(plaintext)+1+gcm.Overhead())
	copy(body, salt)
	binary.BigEndian.PutUint32(body[16:], pushRecordSize)
	body[20] = p256PointBytes
	copy(body[21:], localPublic)
	record := append(append(make([]byte, 0, len(plaintext)+1), plaintext...), 2)
	return gcm.Seal(body, nonce, record, nil), nil
}

// decryptPush is webpush_test.go's, returning errors in place of t.Fatal.
func decryptPush(body []byte, private *ecdh.PrivateKey, auth []byte) ([]byte, error) {
	if len(body) < pushHeaderBytes || body[20] != p256PointBytes {
		return nil, errors.New("bad aes128gcm header")
	}
	salt, serverKey := body[:16], body[21:pushHeaderBytes]
	if rs := binary.BigEndian.Uint32(body[16:]); rs != pushRecordSize {
		return nil, fmt.Errorf("record size %d", rs)
	}
	server, err := ecdh.P256().NewPublicKey(serverKey)
	if err != nil {
		return nil, err
	}
	secret, err := private.ECDH(server)
	if err != nil {
		return nil, err
	}
	info := "WebPush: info\x00" + string(private.PublicKey().Bytes()) + string(serverKey)
	ikm, _ := hkdf.Key(sha256.New, secret, auth, info, 32)
	cek, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	record, err := gcm.Open(nil, nonce, body[pushHeaderBytes:], nil)
	if err != nil {
		return nil, err
	}
	if len(record) == 0 || record[len(record)-1] != 2 {
		return nil, errors.New("record does not end with the last-record delimiter")
	}
	return record[:len(record)-1], nil
}

// origin is webpush.go's.
func origin(u *url.URL) string {
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
		host += ":" + port
	}
	return scheme + "://" + host
}

// Case is one encrypted payload: the receiver's private key and auth
// secret, and, for fixed cases, the sender's key and salt. Fixed cases
// must encrypt to the same body in both implementations.
type Case struct {
	Name      string `json:"name"`
	UAPrivate string `json:"ua_private"`
	Auth      string `json:"auth"`
	ASPrivate string `json:"as_private,omitzero"`
	Salt      string `json:"salt,omitzero"`
	Plaintext string `json:"plaintext"`
	Body      string `json:"body"`
}

// Token is a VAPID Authorization header signed for endpoint and subject at
// unix time Now with the key whose public half is Public.
type Token struct {
	Endpoint      string `json:"endpoint"`
	Subject       string `json:"subject"`
	Now           int64  `json:"now"`
	Public        string `json:"public"`
	Authorization string `json:"authorization"`
}

type File struct {
	Cases  []Case  `json:"cases"`
	Tokens []Token `json:"tokens,omitzero"`
}

// fixed derives a deterministic P-256 key or salt from a label.
func fixed(label string, n int) []byte {
	sum := sha256.Sum256([]byte("apron webpush differential " + label))
	return sum[:n]
}

func plaintextOf(name string, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = name[i%len(name)]
	}
	return out
}

func vectors() error {
	rfcUA, _ := decodeBase64URL("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")
	rfcAS, _ := decodeBase64URL("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
	rfcAuth, _ := decodeBase64URL("BTBZMqHH6r4Tts7J_aSIgg")
	rfcSalt, _ := decodeBase64URL("DGv6ra1nlYgDCS1FRnbzlw")
	type spec struct {
		name               string
		ua, as, auth, salt []byte
		plaintext          []byte
	}
	specs := []spec{{"rfc8291", rfcUA, rfcAS, rfcAuth, rfcSalt, []byte("When I grow up, I want to be a watermelon")}}
	for _, size := range []int{0, 1, 300, 2048, maxPushPlaintext} {
		name := fmt.Sprintf("fixed-%d", size)
		specs = append(specs, spec{name, fixed(name+" ua", 32), fixed(name+" as", 32), fixed(name+" auth", 16), fixed(name+" salt", 16), plaintextOf(name, size)})
	}
	for i := range 8 {
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		ua := key.Bytes()
		auth := make([]byte, 16)
		rand.Read(auth)
		size := []int{5, 64, 777, maxPushPlaintext}[i%4]
		specs = append(specs, spec{fmt.Sprintf("random-%d", i), ua, nil, auth, nil, plaintextOf("random", size)})
	}
	var out File
	for _, s := range specs {
		ua, err := ecdh.P256().NewPrivateKey(s.ua)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		c := Case{Name: s.name, UAPrivate: encodeBase64URL(s.ua), Auth: encodeBase64URL(s.auth), Plaintext: encodeBase64URL(s.plaintext)}
		as, salt := s.as, s.salt
		if as == nil {
			key, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			as, salt = key.Bytes(), make([]byte, 16)
			rand.Read(salt)
		} else {
			c.ASPrivate, c.Salt = encodeBase64URL(as), encodeBase64URL(salt)
		}
		local, err := ecdh.P256().NewPrivateKey(as)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		body, err := encryptPushWith(s.plaintext, ua.PublicKey().Bytes(), s.auth, local, salt)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		c.Body = encodeBase64URL(body)
		out.Cases = append(out.Cases, c)
	}
	return json.MarshalWrite(os.Stdout, out, json.Deterministic(true))
}

// checkToken verifies a VAPID header as a push service does (RFC 8292
// section 3): an ES256 JWT signed with k, for the endpoint's origin,
// expiring 12 hours after it was signed, with the subject as sub.
func checkToken(tok Token) error {
	rest, ok := strings.CutPrefix(tok.Authorization, "vapid t=")
	if !ok {
		return errors.New("no vapid scheme")
	}
	token, k, ok := strings.Cut(rest, ", k=")
	if !ok || k != tok.Public {
		return fmt.Errorf("k = %q", k)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a JWS")
	}
	var header, claims map[string]any
	for i, into := range []*map[string]any{&header, &claims} {
		raw, err := decodeBase64URL(parts[i])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, into); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(header, map[string]any{"typ": "JWT", "alg": "ES256"}) {
		return fmt.Errorf("header %v", header)
	}
	parsed, err := url.Parse(tok.Endpoint)
	if err != nil {
		return err
	}
	want := map[string]any{"aud": origin(parsed), "exp": float64(time.Unix(tok.Now, 0).Add(vapidTokenLifetime).Unix())}
	if tok.Subject != "" {
		want["sub"] = tok.Subject
	}
	if !reflect.DeepEqual(claims, want) {
		return fmt.Errorf("claims %v, want %v", claims, want)
	}
	point, err := decodeBase64URL(k)
	if err != nil {
		return err
	}
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return err
	}
	signature, err := decodeBase64URL(parts[2])
	if err != nil || len(signature) != 64 {
		return errors.New("signature is not r || s")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return errors.New("signature does not verify")
	}
	return nil
}

func check(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var in File
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if len(in.Cases) == 0 || len(in.Tokens) == 0 {
		return errors.New("no cases or no tokens")
	}
	caseFails, tokenFails := 0, 0
	for _, c := range in.Cases {
		ua, _ := decodeBase64URL(c.UAPrivate)
		auth, _ := decodeBase64URL(c.Auth)
		body, _ := decodeBase64URL(c.Body)
		key, err := ecdh.P256().NewPrivateKey(ua)
		var plaintext []byte
		if err == nil {
			plaintext, err = decryptPush(body, key, auth)
		}
		if err == nil && encodeBase64URL(plaintext) != c.Plaintext {
			err = errors.New("plaintext differs")
		}
		if err != nil {
			caseFails++
			fmt.Printf("FAIL case %s: %v\n", c.Name, err)
		}
	}
	for _, tok := range in.Tokens {
		if err := checkToken(tok); err != nil {
			tokenFails++
			fmt.Printf("FAIL token %s %q: %v\n", tok.Endpoint, tok.Subject, err)
		}
	}
	fmt.Printf("go opened %d of %d Rust payloads and verified %d of %d Rust VAPID tokens\n",
		len(in.Cases)-caseFails, len(in.Cases), len(in.Tokens)-tokenFails, len(in.Tokens))
	if caseFails+tokenFails > 0 {
		return fmt.Errorf("%d failures", caseFails+tokenFails)
	}
	return nil
}

func main() {
	var err error
	switch {
	case len(os.Args) == 2 && os.Args[1] == "vectors":
		err = vectors()
	case len(os.Args) == 3 && os.Args[1] == "check":
		err = check(os.Args[2])
	default:
		err = errors.New("usage: webpush vectors | webpush check <file>")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "webpush:", err)
		os.Exit(1)
	}
}
