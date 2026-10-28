// Command webauthn writes the differential vectors for src/webauthn: it runs
// registrations and assertions from a software authenticator, valid and
// mutated, through go-webauthn v0.18.2 configured as aprond configures it,
// and records each verdict, error, and resulting credential.
//
//	go run . > vectors.json
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	rpID        = "example.com"
	origin      = "https://example.com"
	otherOrigin = "https://chat.example.com:8443"
)

// jsonOptions are aprond's (internal/server/server.go).
var jsonOptions = json.JoinOptions(
	json.Deterministic(true),
	json.FormatNilSliceAsNull(true),
	json.FormatNilMapAsNull(true),
)

var b64 = base64.RawURLEncoding

var encMode, _ = cbor.CTAP2EncOptions().EncMode()

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func encode(v any) []byte {
	out, err := encMode.Marshal(v)
	must(err)
	return out
}

func newWebAuthn() *webauthn.WebAuthn {
	w, err := webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "Apron", RPOrigins: []string{origin, otherOrigin}})
	must(err)
	return w
}

type user struct {
	handle      []byte
	name        string
	credentials []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.handle }
func (u *user) WebAuthnName() string                       { return u.name }
func (u *user) WebAuthnDisplayName() string                { return u.name }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type authenticator struct {
	alg    int64
	ec     *ecdsa.PrivateKey
	ed     ed25519.PrivateKey
	rsa    *rsa.PrivateKey
	credID []byte
}

func newAuthenticator(alg int64) *authenticator {
	a := &authenticator{alg: alg, credID: make([]byte, 16)}
	_, _ = rand.Read(a.credID)
	var err error
	switch alg {
	case -7:
		a.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case -35:
		a.ec, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case -36:
		a.ec, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case -8:
		_, a.ed, err = ed25519.GenerateKey(rand.Reader)
	case -257, -37:
		a.rsa, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		panic(alg)
	}
	must(err)
	return a
}

func (a *authenticator) coseKey() map[int]any {
	switch {
	case a.ec != nil:
		size := (a.ec.Curve.Params().BitSize + 7) / 8
		crv := map[int64]int{-7: 1, -35: 2, -36: 3}[a.alg]
		return map[int]any{1: 2, 3: a.alg, -1: crv, -2: a.ec.X.FillBytes(make([]byte, size)), -3: a.ec.Y.FillBytes(make([]byte, size))}
	case a.ed != nil:
		return map[int]any{1: 1, 3: a.alg, -1: 6, -2: []byte(a.ed.Public().(ed25519.PublicKey))}
	default:
		return map[int]any{1: 3, 3: a.alg, -1: a.rsa.N.Bytes(), -2: big.NewInt(int64(a.rsa.E)).Bytes()}
	}
}

func (a *authenticator) sign(data []byte) []byte {
	var (
		sig []byte
		err error
	)
	switch a.alg {
	case -7:
		h := sha256.Sum256(data)
		sig, err = ecdsa.SignASN1(rand.Reader, a.ec, h[:])
	case -35:
		h := sha512.Sum384(data)
		sig, err = ecdsa.SignASN1(rand.Reader, a.ec, h[:])
	case -36:
		h := sha512.Sum512(data)
		sig, err = ecdsa.SignASN1(rand.Reader, a.ec, h[:])
	case -8:
		sig = ed25519.Sign(a.ed, data)
	case -257:
		h := sha256.Sum256(data)
		sig, err = rsa.SignPKCS1v15(rand.Reader, a.rsa, crypto.SHA256, h[:])
	case -37:
		h := sha256.Sum256(data)
		sig, err = rsa.SignPSS(rand.Reader, a.rsa, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	must(err)
	return sig
}

const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
	flagED = 0x80
)

type clientData struct {
	typ, challenge, origin string
	extra                  string // raw members appended after crossOrigin
	raw                    string // replaces the whole clientDataJSON
}

func (c clientData) bytes() []byte {
	if c.raw != "" {
		return []byte(c.raw)
	}
	return []byte(fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":%q,"crossOrigin":false%s}`, c.typ, c.challenge, c.origin, c.extra))
}

type regInput struct {
	a          *authenticator
	client     clientData
	rpHash     []byte
	flags      byte
	counter    uint32
	aaguid     []byte
	credID     []byte // in the authenticator data
	coseKey    []byte
	ext        []byte
	authTail   []byte
	format     string
	attStmt    map[string]any
	packedSelf bool
	packedX5C  bool
	corruptSig bool
	attObj     func(authData []byte, attStmt map[string]any) []byte
	attTail    []byte
	id, rawID  string
	typ        string
	clientExt  string
	transports []string
	attachment string
	jsonTail   string
	extra      func(response map[string]any, authData []byte)
}

func defaultReg(a *authenticator, challenge string) *regInput {
	h := sha256.Sum256([]byte(rpID))
	return &regInput{
		a:       a,
		client:  clientData{typ: "webauthn.create", challenge: challenge, origin: origin},
		rpHash:  h[:],
		flags:   flagUP | flagUV | flagBE | flagBS | flagAT,
		aaguid:  make([]byte, 16),
		credID:  a.credID,
		coseKey: encode(a.coseKey()),
		format:  "none",
		attStmt: map[string]any{},
		id:      b64.EncodeToString(a.credID),
		rawID:   b64.EncodeToString(a.credID),
		typ:     "public-key",
	}
}

func (in *regInput) authData() []byte {
	var b bytes.Buffer
	b.Write(in.rpHash)
	b.WriteByte(in.flags)
	_ = binary.Write(&b, binary.BigEndian, in.counter)
	b.Write(in.aaguid)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(in.credID)))
	b.Write(in.credID)
	b.Write(in.coseKey)
	b.Write(in.ext)
	b.Write(in.authTail)
	return b.Bytes()
}

func attestationCert() (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country: []string{"US"}, Organization: []string{"Apron Test"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Apron Test Authenticator",
		},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2046, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(err)
	return key, der
}

func (in *regInput) credential() []byte {
	clientJSON := in.client.bytes()
	authData := in.authData()
	attStmt := in.attStmt
	if in.packedSelf || in.packedX5C {
		cdh := sha256.Sum256(clientJSON)
		signed := append(append([]byte{}, authData...), cdh[:]...)
		if in.packedX5C {
			key, der := attestationCert()
			h := sha256.Sum256(signed)
			sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
			must(err)
			attStmt = map[string]any{"alg": int64(-7), "sig": sig, "x5c": []any{der}}
		} else {
			sig := in.a.sign(signed)
			if in.corruptSig {
				sig[len(sig)/2] ^= 0x01
			}
			attStmt["alg"] = in.a.alg
			attStmt["sig"] = sig
		}
	}
	var attObj []byte
	if in.attObj != nil {
		attObj = in.attObj(authData, attStmt)
	} else {
		attObj = encode(map[string]any{"fmt": in.format, "attStmt": attStmt, "authData": authData})
	}
	attObj = append(attObj, in.attTail...)
	response := map[string]any{
		"clientDataJSON":    b64.EncodeToString(clientJSON),
		"attestationObject": b64.EncodeToString(attObj),
	}
	if in.transports != nil {
		response["transports"] = in.transports
	}
	if in.extra != nil {
		in.extra(response, authData)
	}
	cred := map[string]any{"id": in.id, "rawId": in.rawID, "type": in.typ, "response": response}
	if in.clientExt != "" {
		cred["clientExtensionResults"] = jsontext.Value(in.clientExt)
	}
	if in.attachment != "" {
		cred["authenticatorAttachment"] = in.attachment
	}
	out, err := json.Marshal(cred, json.Deterministic(true))
	must(err)
	return append(out, in.jsonTail...)
}

type sessionVector struct {
	Challenge            string   `json:"challenge"`
	RPID                 string   `json:"rp_id"`
	Origin               string   `json:"origin"`
	UserID               string   `json:"user_id"`
	AllowedCredentialIDs []string `json:"allowed_credential_ids"`
	UserVerification     string   `json:"user_verification"`
	CredParams           []int64  `json:"cred_params"`
}

func sessionOf(s *webauthn.SessionData) sessionVector {
	v := sessionVector{
		Challenge: s.Challenge, RPID: s.RelyingPartyID, Origin: s.Origin, UserID: b64.EncodeToString(s.UserID),
		UserVerification: string(s.UserVerification), AllowedCredentialIDs: []string{}, CredParams: []int64{},
	}
	for _, id := range s.AllowedCredentialIDs {
		v.AllowedCredentialIDs = append(v.AllowedCredentialIDs, b64.EncodeToString(id))
	}
	for _, p := range s.CredParams {
		v.CredParams = append(v.CredParams, int64(p.Algorithm))
	}
	return v
}

type expect struct {
	OK           bool   `json:"ok"`
	ErrorType    string `json:"error_type"`
	ErrorDetails string `json:"error_details"`
	ErrorInfo    string `json:"error_info"`
	Error        string `json:"error"`
	Credential   string `json:"credential"`
	CloneWarning bool   `json:"clone_warning"`
}

func verdict(err error, credential *webauthn.Credential) expect {
	if err != nil {
		e := expect{Error: err.Error()}
		var pe *protocol.Error
		if errors.As(err, &pe) {
			e.ErrorType, e.ErrorDetails, e.ErrorInfo = pe.Type, pe.Details, pe.DevInfo
		}
		return e
	}
	out, err := json.Marshal(credential, jsonOptions)
	must(err)
	return expect{OK: true, Credential: string(out), CloneWarning: credential.Authenticator.CloneWarning}
}

type registrationVector struct {
	Name       string        `json:"name"`
	UserHandle string        `json:"user_handle"`
	Session    sessionVector `json:"session"`
	Response   string        `json:"response"`
	Expect     expect        `json:"expect"`
}

type regCase struct {
	name   string
	alg    int64
	unbind bool
	mutate func(in *regInput)
}

func register(w *webauthn.WebAuthn, alg int64, unbind bool, mutate func(*regInput)) (registrationVector, *user, *webauthn.Credential, *authenticator) {
	a := newAuthenticator(alg)
	u := &user{handle: []byte(rand.Text()), name: "Ada"}
	opts := []webauthn.RegistrationOption{
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions([]protocol.CredentialDescriptor{}),
	}
	if !unbind {
		opts = append([]webauthn.RegistrationOption{webauthn.WithRegistrationOrigin(origin)}, opts...)
	}
	_, session, err := w.BeginRegistration(u, opts...)
	must(err)
	in := defaultReg(a, session.Challenge)
	if mutate != nil {
		mutate(in)
	}
	raw := in.credential()
	var credential *webauthn.Credential
	parsed, err := protocol.ParseCredentialCreationResponseBytes(raw)
	if err == nil {
		credential, err = w.CreateCredential(u, *session, parsed)
	}
	v := registrationVector{UserHandle: b64.EncodeToString(u.handle), Session: sessionOf(session), Response: string(raw), Expect: verdict(err, credential)}
	return v, u, credential, a
}

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	default:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cborBytes(b []byte) []byte     { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte      { return append(cborHead(3, uint64(len(s))), s...) }
func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func registrationCases() []regCase {
	emptyMap := []byte{0xa0}
	return []regCase{
		{name: "es256-none", alg: -7},
		{name: "es384-none", alg: -35},
		{name: "es512-none", alg: -36},
		{name: "ed25519-none", alg: -8},
		{name: "rs256-none", alg: -257},
		{name: "ps256-none", alg: -37},
		{name: "es256-packed-self", alg: -7, mutate: func(in *regInput) { in.format, in.packedSelf = "packed", true }},
		{name: "es384-packed-self", alg: -35, mutate: func(in *regInput) { in.format, in.packedSelf = "packed", true }},
		{name: "ed25519-packed-self", alg: -8, mutate: func(in *regInput) { in.format, in.packedSelf = "packed", true }},
		{name: "rs256-packed-self", alg: -257, mutate: func(in *regInput) { in.format, in.packedSelf = "packed", true }},
		{name: "ps256-packed-self", alg: -37, mutate: func(in *regInput) { in.format, in.packedSelf = "packed", true }},
		{name: "packed-self-bad-signature", alg: -7, mutate: func(in *regInput) { in.format, in.packedSelf, in.corruptSig = "packed", true, true }},
		{name: "ed25519-packed-self-bad-signature", alg: -8, mutate: func(in *regInput) { in.format, in.packedSelf, in.corruptSig = "packed", true, true }},
		{name: "packed-self-alg-mismatch", alg: -7, mutate: func(in *regInput) {
			in.format = "packed"
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				sig := in.a.sign(append(append([]byte{}, authData...), sha(in.client.bytes())...))
				return encode(map[string]any{"fmt": "packed", "attStmt": map[string]any{"alg": int64(-257), "sig": sig}, "authData": authData})
			}
		}},
		{name: "packed-missing-alg", alg: -7, mutate: func(in *regInput) {
			in.format, in.attStmt = "packed", map[string]any{"sig": []byte{1, 2, 3}}
		}},
		{name: "packed-positive-alg", alg: -7, mutate: func(in *regInput) {
			in.format, in.attStmt = "packed", map[string]any{"alg": uint64(7), "sig": []byte{1, 2, 3}}
		}},
		{name: "packed-sig-not-bytes", alg: -7, mutate: func(in *regInput) {
			in.format, in.attStmt = "packed", map[string]any{"alg": int64(-7), "sig": "text"}
		}},
		{name: "packed-ecdaa", alg: -7, mutate: func(in *regInput) {
			in.format, in.attStmt = "packed", map[string]any{"alg": int64(-7), "sig": []byte{1}, "ecdaaKeyId": []byte{2}}
		}},
		{name: "packed-x5c", alg: -7, mutate: func(in *regInput) { in.format, in.packedX5C = "packed", true }},
		{name: "fmt-unknown", alg: -7, mutate: func(in *regInput) { in.format = "unknown" }},
		{name: "fmt-tpm", alg: -7, mutate: func(in *regInput) { in.format = "tpm" }},
		{name: "fmt-fido-u2f", alg: -7, mutate: func(in *regInput) { in.format = "fido-u2f" }},
		{name: "fmt-apple", alg: -7, mutate: func(in *regInput) { in.format = "apple" }},
		{name: "fmt-android-key", alg: -7, mutate: func(in *regInput) { in.format = "android-key" }},
		{name: "fmt-android-safetynet", alg: -7, mutate: func(in *regInput) { in.format = "android-safetynet" }},
		{name: "fmt-compound", alg: -7, mutate: func(in *regInput) {
			in.format = "compound"
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return encode(map[string]any{"fmt": "compound", "attStmt": []any{}, "authData": authData})
			}
		}},
		{name: "none-with-statement", alg: -7, mutate: func(in *regInput) { in.attStmt = map[string]any{"x": int64(1)} }},
		{name: "none-without-statement", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return encode(map[string]any{"fmt": "none", "authData": authData})
			}
		}},
		{name: "wrong-challenge", alg: -7, mutate: func(in *regInput) { in.client.challenge = b64.EncodeToString(make([]byte, 32)) }},
		{name: "padded-challenge", alg: -7, mutate: func(in *regInput) { in.client.challenge += "=" }},
		{name: "wrong-origin", alg: -7, mutate: func(in *regInput) { in.client.origin = "https://evil.example" }},
		{name: "other-configured-origin", alg: -7, mutate: func(in *regInput) { in.client.origin = otherOrigin }},
		{name: "unbound-other-configured-origin", alg: -7, unbind: true, mutate: func(in *regInput) { in.client.origin = otherOrigin }},
		{name: "origin-default-port", alg: -7, mutate: func(in *regInput) { in.client.origin = "https://example.com:443" }},
		{name: "origin-uppercase", alg: -7, mutate: func(in *regInput) { in.client.origin = "HTTPS://EXAMPLE.COM" }},
		{name: "origin-trailing-slash", alg: -7, mutate: func(in *regInput) { in.client.origin = "https://example.com/" }},
		{name: "origin-other-port", alg: -7, mutate: func(in *regInput) { in.client.origin = "https://example.com:444" }},
		{name: "origin-http", alg: -7, mutate: func(in *regInput) { in.client.origin = "http://example.com" }},
		{name: "wrong-type", alg: -7, mutate: func(in *regInput) { in.client.typ = "webauthn.get" }},
		{name: "cross-origin", alg: -7, mutate: func(in *regInput) {
			in.client.raw = fmt.Sprintf(`{"type":"webauthn.create","challenge":%q,"origin":%q,"crossOrigin":true}`, in.client.challenge, origin)
		}},
		{name: "top-origin-without-cross-origin", alg: -7, mutate: func(in *regInput) { in.client.extra = `,"topOrigin":"https://example.com"` }},
		{name: "token-binding-present", alg: -7, mutate: func(in *regInput) { in.client.extra = `,"tokenBinding":{"status":"present","id":"abc"}` }},
		{name: "token-binding-bad-status", alg: -7, mutate: func(in *regInput) { in.client.extra = `,"tokenBinding":{"status":"bogus"}` }},
		{name: "token-binding-no-status", alg: -7, mutate: func(in *regInput) { in.client.extra = `,"tokenBinding":{}` }},
		{name: "client-data-unknown-member", alg: -7, mutate: func(in *regInput) { in.client.extra = `,"other_keys_can_be_added_here":"x"` }},
		{name: "client-data-folded-keys", alg: -7, mutate: func(in *regInput) {
			in.client.raw = fmt.Sprintf(`{"TYPE":"webauthn.create","Challenge":%q,"oRiGiN":%q}`, in.client.challenge, origin)
		}},
		{name: "client-data-duplicate-challenge", alg: -7, mutate: func(in *regInput) {
			in.client.raw = fmt.Sprintf(`{"type":"webauthn.create","challenge":"AAAA","challenge":%q,"origin":%q}`, in.client.challenge, origin)
		}},
		{name: "client-data-not-json", alg: -7, mutate: func(in *regInput) { in.client.raw = "synthetic" }},
		{name: "client-data-challenge-number", alg: -7, mutate: func(in *regInput) {
			in.client.raw = fmt.Sprintf(`{"type":"webauthn.create","challenge":1,"origin":%q}`, origin)
		}},
		{name: "client-data-cross-origin-string", alg: -7, mutate: func(in *regInput) {
			in.client.raw = fmt.Sprintf(`{"type":"webauthn.create","challenge":%q,"origin":%q,"crossOrigin":"false"}`, in.client.challenge, origin)
		}},
		{name: "wrong-rp-id-hash", alg: -7, mutate: func(in *regInput) { h := sha256.Sum256([]byte("evil.example")); in.rpHash = h[:] }},
		{name: "uv-missing", alg: -7, mutate: func(in *regInput) { in.flags &^= flagUV }},
		{name: "up-missing", alg: -7, mutate: func(in *regInput) { in.flags &^= flagUP }},
		{name: "bs-without-be", alg: -7, mutate: func(in *regInput) { in.flags &^= flagBE }},
		{name: "be-without-bs", alg: -7, mutate: func(in *regInput) { in.flags &^= flagBS }},
		{name: "single-device", alg: -7, mutate: func(in *regInput) { in.flags &^= flagBE | flagBS }},
		{name: "at-missing", alg: -7, mutate: func(in *regInput) { in.flags &^= flagAT }},
		{name: "counter-nonzero", alg: -7, mutate: func(in *regInput) { in.counter = 42 }},
		{name: "aaguid-set", alg: -7, mutate: func(in *regInput) {
			in.aaguid = []byte{0xad, 0xce, 0x00, 0x02, 0x35, 0xbc, 0xc6, 0x0a, 0x64, 0x8b, 0x0b, 0x25, 0xf1, 0xf0, 0x55, 0x03}
		}},
		{name: "auth-data-trailing", alg: -7, mutate: func(in *regInput) { in.authTail = []byte{0} }},
		{name: "auth-data-short", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, attStmt map[string]any) []byte {
				return encode(map[string]any{"fmt": "none", "attStmt": attStmt, "authData": authData[:36]})
			}
		}},
		{name: "auth-data-attested-55", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, attStmt map[string]any) []byte {
				return encode(map[string]any{"fmt": "none", "attStmt": attStmt, "authData": authData[:55]})
			}
		}},
		{name: "credential-id-too-long", alg: -7, mutate: func(in *regInput) {
			in.credID = make([]byte, 1024)
			in.id, in.rawID = b64.EncodeToString(in.credID), b64.EncodeToString(in.credID)
		}},
		{name: "credential-id-max", alg: -7, mutate: func(in *regInput) {
			in.credID = bytes.Repeat([]byte{7}, 1023)
			in.id, in.rawID = b64.EncodeToString(in.credID), b64.EncodeToString(in.credID)
		}},
		{name: "credential-id-overruns", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, attStmt map[string]any) []byte {
				short := append([]byte{}, authData[:55]...)
				short[53], short[54] = 0x01, 0x00
				return encode(map[string]any{"fmt": "none", "attStmt": attStmt, "authData": append(short, 1, 2, 3)})
			}
		}},
		{name: "attestation-object-trailing", alg: -7, mutate: func(in *regInput) { in.attTail = []byte{0x00} }},
		{name: "cose-unsorted-keys", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			in.coseKey = concat([]byte{0xa5}, []byte{0x20, 0x01}, []byte{0x03, 0x26}, []byte{0x01, 0x02},
				[]byte{0x22}, cborBytes(k[-3].([]byte)), []byte{0x21}, cborBytes(k[-2].([]byte)))
		}},
		{name: "cose-nonminimal-int", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			in.coseKey = concat([]byte{0xa5}, []byte{0x18, 0x01, 0x02}, []byte{0x03, 0x26}, []byte{0x20, 0x01},
				[]byte{0x21}, cborBytes(k[-2].([]byte)), []byte{0x22}, cborBytes(k[-3].([]byte)))
		}},
		{name: "cose-extra-float", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			in.coseKey = concat([]byte{0xa6}, []byte{0x01, 0x02}, []byte{0x03, 0x26}, []byte{0x20, 0x01},
				[]byte{0x21}, cborBytes(k[-2].([]byte)), []byte{0x22}, cborBytes(k[-3].([]byte)), []byte{0x05, 0xf9, 0x3c, 0x00})
		}},
		{name: "cose-extra-undefined", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			in.coseKey = concat([]byte{0xa6}, []byte{0x01, 0x02}, []byte{0x03, 0x26}, []byte{0x20, 0x01},
				[]byte{0x21}, cborBytes(k[-2].([]byte)), []byte{0x22}, cborBytes(k[-3].([]byte)), []byte{0x05, 0xf7})
		}},
		{name: "cose-extra-text-key", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			in.coseKey = concat([]byte{0xa6}, []byte{0x01, 0x02}, []byte{0x03, 0x26}, []byte{0x20, 0x01},
				[]byte{0x21}, cborBytes(k[-2].([]byte)), []byte{0x22}, cborBytes(k[-3].([]byte)), cborText("zz"), []byte{0x01})
		}},
		{name: "cose-bytes-key", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			in.coseKey = concat([]byte{0xa6}, []byte{0x01, 0x02}, []byte{0x03, 0x26}, []byte{0x20, 0x01},
				[]byte{0x21}, cborBytes(k[-2].([]byte)), []byte{0x22}, cborBytes(k[-3].([]byte)), cborBytes([]byte{1}), []byte{0x01})
		}},
		{name: "cose-duplicate-key", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			in.coseKey = concat([]byte{0xa6}, []byte{0x01, 0x02}, []byte{0x03, 0x26}, []byte{0x20, 0x01},
				[]byte{0x21}, cborBytes(k[-2].([]byte)), []byte{0x22}, cborBytes(k[-3].([]byte)), []byte{0x18, 0x01, 0x02})
		}},
		{name: "cose-not-a-map", alg: -7, mutate: func(in *regInput) { in.coseKey = []byte{0x80} }},
		{name: "cose-truncated", alg: -7, mutate: func(in *regInput) { in.coseKey = in.coseKey[:20] }},
		{name: "cose-wrong-curve", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			k[-1] = 2
			in.coseKey = encode(k)
		}},
		{name: "cose-wrong-curve-packed", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			k[-1] = 2
			in.coseKey = encode(k)
			in.format, in.packedSelf = "packed", true
		}},
		{name: "cose-point-off-curve", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			y := k[-3].([]byte)
			y[31] ^= 1
			in.coseKey = encode(k)
		}},
		{name: "cose-point-off-curve-packed", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			y := k[-3].([]byte)
			y[31] ^= 1
			in.coseKey = encode(k)
			in.format, in.packedSelf = "packed", true
		}},
		{name: "alg-es256k", alg: -7, mutate: func(in *regInput) {
			k := in.a.coseKey()
			k[3] = int64(-47)
			in.coseKey = encode(k)
		}},
		{name: "alg-ed25519-fully-specified", alg: -8, mutate: func(in *regInput) {
			k := in.a.coseKey()
			k[3] = int64(-19)
			in.coseKey = encode(k)
		}},
		{name: "attestation-object-indefinite-map", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xbf}, cborText("fmt"), cborText("none"), cborText("attStmt"), emptyMap, cborText("authData"), cborBytes(authData), []byte{0xff})
			}
		}},
		{name: "attestation-object-indefinite-bytes", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa3}, cborText("fmt"), cborText("none"), cborText("attStmt"), emptyMap, cborText("authData"), []byte{0x5f}, cborBytes(authData), []byte{0xff})
			}
		}},
		{name: "attestation-object-tag", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xd9, 0xd9, 0xf7, 0xa3}, cborText("fmt"), cborText("none"), cborText("attStmt"), emptyMap, cborText("authData"), cborBytes(authData))
			}
		}},
		{name: "attestation-object-duplicate-key", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa4}, cborText("fmt"), cborText("none"), cborText("attStmt"), emptyMap, cborText("authData"), cborBytes(authData), cborText("fmt"), cborText("none"))
			}
		}},
		{name: "attestation-object-unknown-key", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa4}, cborText("fmt"), cborText("none"), cborText("attStmt"), emptyMap, cborText("authData"), cborBytes(authData), cborText("ep"), []byte{0xf5})
			}
		}},
		{name: "attestation-object-folded-key", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa3}, cborText("FMT"), cborText("none"), cborText("attStmt"), emptyMap, cborText("AuthData"), cborBytes(authData))
			}
		}},
		{name: "attestation-object-int-key", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa4}, cborText("fmt"), cborText("none"), cborText("attStmt"), emptyMap, cborText("authData"), cborBytes(authData), []byte{0x01, 0x02})
			}
		}},
		{name: "attestation-object-fmt-bytes", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa3}, cborText("fmt"), cborBytes([]byte("none")), cborText("attStmt"), emptyMap, cborText("authData"), cborBytes(authData))
			}
		}},
		{name: "attestation-object-auth-data-text", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa3}, cborText("fmt"), cborText("none"), cborText("attStmt"), emptyMap, cborText("authData"), cborText(string(authData)))
			}
		}},
		{name: "attestation-object-fmt-invalid-utf8", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa3}, cborText("fmt"), []byte{0x62, 0xff, 0xfe}, cborText("attStmt"), emptyMap, cborText("authData"), cborBytes(authData))
			}
		}},
		{name: "attestation-object-not-a-map", alg: -7, mutate: func(in *regInput) {
			in.attObj = func([]byte, map[string]any) []byte { return []byte{0x80} }
		}},
		{name: "attestation-object-empty", alg: -7, mutate: func(in *regInput) {
			in.attObj = func([]byte, map[string]any) []byte { return []byte{} }
		}},
		{name: "attestation-object-null-statement", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa3}, cborText("fmt"), cborText("none"), cborText("attStmt"), []byte{0xf6}, cborText("authData"), cborBytes(authData))
			}
		}},
		{name: "statement-too-deep", alg: -7, mutate: func(in *regInput) {
			in.attStmt = map[string]any{"x": []any{[]any{[]any{[]any{int64(1)}}}}}
		}},
		{name: "statement-depth-limit", alg: -7, mutate: func(in *regInput) {
			in.attStmt = map[string]any{"x": []any{[]any{[]any{int64(1)}}}}
		}},
		{name: "statement-reserved-simple", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa3}, cborText("fmt"), cborText("none"), cborText("attStmt"), []byte{0xa1}, cborText("x"), []byte{0xf8, 0x10}, cborText("authData"), cborBytes(authData))
			}
		}},
		{name: "statement-int-key", alg: -7, mutate: func(in *regInput) {
			in.attObj = func(authData []byte, _ map[string]any) []byte {
				return concat([]byte{0xa3}, cborText("fmt"), cborText("none"), cborText("attStmt"), []byte{0xa1, 0x01, 0x02}, cborText("authData"), cborBytes(authData))
			}
		}},
		{name: "extension-output-cred-props", alg: -7, mutate: func(in *regInput) { in.clientExt = `{"credProps":{"rk":true}}` }},
		{name: "extension-output-null", alg: -7, mutate: func(in *regInput) { in.clientExt = `{"credProps":null}` }},
		{name: "extension-output-unknown", alg: -7, mutate: func(in *regInput) { in.clientExt = `{"zz":1,"aa":[true]}` }},
		{name: "extension-output-folded", alg: -7, mutate: func(in *regInput) { in.clientExt = `{"CREDPROPS":{}}` }},
		{name: "extension-output-empty", alg: -7, mutate: func(in *regInput) { in.clientExt = `{}` }},
		{name: "extension-output-null-object", alg: -7, mutate: func(in *regInput) { in.clientExt = `null` }},
		{name: "extension-output-not-object", alg: -7, mutate: func(in *regInput) { in.clientExt = `[]` }},
		{name: "authenticator-extensions", alg: -7, mutate: func(in *regInput) {
			in.flags |= flagED
			in.ext = encode(map[string]any{"credProtect": uint64(2), "minPinLength": uint64(6), "hmac-secret": true, "credBlob": true, "other": "x"})
		}},
		{name: "authenticator-extensions-policy-name", alg: -7, mutate: func(in *regInput) {
			in.flags |= flagED
			in.ext = encode(map[string]any{"credentialProtectionPolicy": uint64(3)})
		}},
		{name: "authenticator-extensions-bad-values", alg: -7, mutate: func(in *regInput) {
			in.flags |= flagED
			in.ext = encode(map[string]any{"credProtect": uint64(9), "minPinLength": int64(-1), "hmac-secret": "x"})
		}},
		{name: "authenticator-extensions-trailing", alg: -7, mutate: func(in *regInput) {
			in.flags |= flagED
			in.ext = append(encode(map[string]any{"credProtect": uint64(2)}), 0x00)
		}},
		{name: "authenticator-extensions-missing", alg: -7, mutate: func(in *regInput) { in.flags |= flagED }},
		{name: "authenticator-extensions-int-key", alg: -7, mutate: func(in *regInput) {
			in.flags |= flagED
			in.ext = []byte{0xa1, 0x01, 0x02}
		}},
		{name: "id-not-matching-raw-id", alg: -7, mutate: func(in *regInput) { in.id = b64.EncodeToString([]byte("other")) }},
		{name: "raw-id-not-matching-auth-data", alg: -7, mutate: func(in *regInput) {
			in.id, in.rawID = b64.EncodeToString([]byte("other")), b64.EncodeToString([]byte("other"))
		}},
		{name: "id-not-base64url", alg: -7, mutate: func(in *regInput) { in.id = "!!" }},
		{name: "id-padded", alg: -7, mutate: func(in *regInput) { in.id += "==" }},
		{name: "raw-id-padded", alg: -7, mutate: func(in *regInput) { in.rawID += "==" }},
		{name: "raw-id-standard-alphabet", alg: -7, mutate: func(in *regInput) {
			in.credID = []byte{0xfb, 0xff, 0xfe, 0x01}
			in.id = b64.EncodeToString(in.credID)
			in.rawID = base64.RawStdEncoding.EncodeToString(in.credID)
		}},
		{name: "type-not-public-key", alg: -7, mutate: func(in *regInput) { in.typ = "password" }},
		{name: "type-missing", alg: -7, mutate: func(in *regInput) { in.typ = "" }},
		{name: "transports", alg: -7, mutate: func(in *regInput) { in.transports = []string{"internal", "cable", "usb", "smoke-signal"} }},
		{name: "attachment-platform", alg: -7, mutate: func(in *regInput) { in.attachment = "platform" }},
		{name: "attachment-unknown", alg: -7, mutate: func(in *regInput) { in.attachment = "elsewhere" }},
		{name: "json-trailing", alg: -7, mutate: func(in *regInput) { in.jsonTail = " {}" }},
		{name: "browser-response-fields", alg: -7, mutate: func(in *regInput) {
			in.extra = func(response map[string]any, authData []byte) {
				response["authenticatorData"] = b64.EncodeToString(authData)
				response["publicKey"] = b64.EncodeToString([]byte("spki"))
				response["publicKeyAlgorithm"] = -7
			}
		}},
		{name: "response-field-wrong-type", alg: -7, mutate: func(in *regInput) {
			in.extra = func(response map[string]any, _ []byte) { response["publicKeyAlgorithm"] = "x" }
		}},
		{name: "extension-output-mistyped", alg: -7, mutate: func(in *regInput) { in.clientExt = `{"appid":"yes"}` }},
		{name: "json-trailing-space", alg: -7, mutate: func(in *regInput) { in.jsonTail = " \n" }},
	}
}

func sha(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

type assertionVector struct {
	Name       string        `json:"name"`
	UserHandle string        `json:"user_handle"`
	Stored     string        `json:"stored"`
	Session    sessionVector `json:"session"`
	Response   string        `json:"response"`
	Expect     expect        `json:"expect"`
}

type asnInput struct {
	a          *authenticator
	client     clientData
	rpHash     []byte
	flags      byte
	counter    uint32
	ext        []byte
	authTail   []byte
	authData   func(full []byte) []byte
	sig        func(sig []byte) []byte
	id, rawID  string
	typ        string
	userHandle *string
	clientExt  string
	attachment string
	jsonTail   string
}

type asnCase struct {
	name      string
	alg       int64
	reg       func(in *regInput)
	mutate    func(in *asnInput)
	storedFix func(c *webauthn.Credential)
}

func assertionCases() []asnCase {
	return []asnCase{
		{name: "es256", alg: -7},
		{name: "es384", alg: -35},
		{name: "es512", alg: -36},
		{name: "ed25519", alg: -8},
		{name: "rs256", alg: -257},
		{name: "ps256", alg: -37},
		{name: "packed-registration", alg: -7, reg: func(in *regInput) { in.format, in.packedSelf = "packed", true }},
		{name: "wrong-challenge", alg: -7, mutate: func(in *asnInput) { in.client.challenge = b64.EncodeToString(make([]byte, 32)) }},
		{name: "wrong-origin", alg: -7, mutate: func(in *asnInput) { in.client.origin = "https://evil.example" }},
		{name: "other-configured-origin", alg: -7, mutate: func(in *asnInput) { in.client.origin = otherOrigin }},
		{name: "wrong-type", alg: -7, mutate: func(in *asnInput) { in.client.typ = "webauthn.create" }},
		{name: "cross-origin", alg: -7, mutate: func(in *asnInput) {
			in.client.raw = fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q,"crossOrigin":true,"topOrigin":"https://top.example"}`, in.client.challenge, origin)
		}},
		{name: "client-data-not-json", alg: -7, mutate: func(in *asnInput) { in.client.raw = "{" }},
		{name: "wrong-rp-id-hash", alg: -7, mutate: func(in *asnInput) { h := sha256.Sum256([]byte("evil.example")); in.rpHash = h[:] }},
		{name: "uv-missing", alg: -7, mutate: func(in *asnInput) { in.flags &^= flagUV }},
		{name: "up-missing", alg: -7, mutate: func(in *asnInput) { in.flags &^= flagUP }},
		{name: "bad-signature", alg: -7, mutate: func(in *asnInput) {
			in.sig = func(s []byte) []byte { s[6] ^= 1; return s }
		}},
		{name: "ed25519-bad-signature", alg: -8, mutate: func(in *asnInput) {
			in.sig = func(s []byte) []byte { s[10] ^= 1; return s }
		}},
		{name: "rs256-bad-signature", alg: -257, mutate: func(in *asnInput) {
			in.sig = func(s []byte) []byte { s[10] ^= 1; return s }
		}},
		{name: "ps256-bad-signature", alg: -37, mutate: func(in *asnInput) {
			in.sig = func(s []byte) []byte { s[10] ^= 1; return s }
		}},
		{name: "signature-trailing-bytes", alg: -7, mutate: func(in *asnInput) {
			in.sig = func(s []byte) []byte { return append(s, 0) }
		}},
		{name: "signature-long-form-length", alg: -7, mutate: func(in *asnInput) {
			in.sig = func(s []byte) []byte { return append([]byte{0x30, 0x81, s[1]}, s[2:]...) }
		}},
		{name: "signature-nonminimal-integer", alg: -7, mutate: func(in *asnInput) {
			in.sig = func(s []byte) []byte {
				rLen := int(s[3])
				r := s[4 : 4+rLen]
				rest := s[4+rLen:]
				body := concat([]byte{0x02, byte(rLen + 1), 0x00}, r, rest)
				return concat([]byte{0x30, byte(len(body))}, body)
			}
		}},
		{name: "signature-raw-p1363", alg: -7, mutate: func(in *asnInput) {
			in.sig = func(s []byte) []byte {
				var parsed struct{ R, S *big.Int }
				_, err := asn1.Unmarshal(s, &parsed)
				must(err)
				return append(parsed.R.FillBytes(make([]byte, 32)), parsed.S.FillBytes(make([]byte, 32))...)
			}
		}},
		{name: "signature-empty", alg: -7, mutate: func(in *asnInput) { in.sig = func([]byte) []byte { return []byte{} } }},
		{name: "counter-advance", alg: -7, reg: func(in *regInput) { in.counter = 10 }, mutate: func(in *asnInput) { in.counter = 11 }},
		{name: "counter-regression", alg: -7, reg: func(in *regInput) { in.counter = 10 }, mutate: func(in *asnInput) { in.counter = 5 }},
		{name: "counter-equal", alg: -7, reg: func(in *regInput) { in.counter = 10 }, mutate: func(in *asnInput) { in.counter = 10 }},
		{name: "counter-zero", alg: -7},
		{name: "counter-from-zero", alg: -7, mutate: func(in *asnInput) { in.counter = 1 }},
		{name: "counter-to-zero", alg: -7, reg: func(in *regInput) { in.counter = 10 }, mutate: func(in *asnInput) { in.counter = 0 }},
		{name: "be-mismatch", alg: -7, mutate: func(in *asnInput) { in.flags &^= flagBE | flagBS }},
		{name: "be-gained", alg: -7, reg: func(in *regInput) { in.flags &^= flagBE | flagBS }, mutate: func(in *asnInput) { in.flags |= flagBE }},
		{name: "bs-without-be", alg: -7, reg: func(in *regInput) { in.flags &^= flagBE | flagBS }, mutate: func(in *asnInput) { in.flags |= flagBS }},
		{name: "bs-cleared", alg: -7, mutate: func(in *asnInput) { in.flags &^= flagBS }},
		{name: "single-device", alg: -7, reg: func(in *regInput) { in.flags &^= flagBE | flagBS },
			mutate: func(in *asnInput) { in.flags &^= flagBE | flagBS }},
		{name: "uv-sticky", alg: -7, storedFix: func(c *webauthn.Credential) { c.Flags.UserVerified = false }},
		{name: "user-handle-missing", alg: -7, mutate: func(in *asnInput) { in.userHandle = new(string) }},
		{name: "user-handle-absent", alg: -7, mutate: func(in *asnInput) { in.userHandle = nil }},
		{name: "user-handle-mismatch", alg: -7, mutate: func(in *asnInput) { s := b64.EncodeToString([]byte("someone-else")); in.userHandle = &s }},
		{name: "unknown-credential", alg: -7, mutate: func(in *asnInput) {
			in.id, in.rawID = b64.EncodeToString([]byte("unknown")), b64.EncodeToString([]byte("unknown"))
		}},
		{name: "id-not-matching-raw-id", alg: -7, mutate: func(in *asnInput) { in.id = b64.EncodeToString([]byte("other")) }},
		{name: "id-not-base64url", alg: -7, mutate: func(in *asnInput) { in.id = "*" }},
		{name: "id-empty", alg: -7, mutate: func(in *asnInput) { in.id = "" }},
		{name: "type-not-public-key", alg: -7, mutate: func(in *asnInput) { in.typ = "password" }},
		{name: "auth-data-trailing", alg: -7, mutate: func(in *asnInput) { in.authTail = []byte{0} }},
		{name: "auth-data-short", alg: -7, mutate: func(in *asnInput) { in.authData = func(full []byte) []byte { return full[:36] } }},
		{name: "auth-data-extensions", alg: -7, mutate: func(in *asnInput) {
			in.flags |= flagED
			in.ext = encode(map[string]any{"credBlob": []byte{1, 2}})
		}},
		{name: "auth-data-extensions-bad", alg: -7, mutate: func(in *asnInput) {
			in.flags |= flagED
			in.ext = []byte{0xbf, 0xff}
		}},
		{name: "auth-data-attested", alg: -7, mutate: func(in *asnInput) { in.flags |= flagAT }},
		{name: "extension-output", alg: -7, mutate: func(in *asnInput) { in.clientExt = `{"appid":true}` }},
		{name: "extension-output-empty", alg: -7, mutate: func(in *asnInput) { in.clientExt = `{}` }},
		{name: "attachment", alg: -7, mutate: func(in *asnInput) { in.attachment = "cross-platform" }},
		{name: "json-trailing", alg: -7, mutate: func(in *asnInput) { in.jsonTail = "x" }},
		{name: "stored-key-off-curve", alg: -7, reg: func(in *regInput) {
			k := in.a.coseKey()
			y := k[-3].([]byte)
			y[31] ^= 1
			in.coseKey = encode(k)
		}},
		{name: "stored-key-wrong-curve", alg: -7, reg: func(in *regInput) {
			k := in.a.coseKey()
			k[-1] = 2
			in.coseKey = encode(k)
		}},
		{name: "stored-key-canonicalized", alg: -7, reg: func(in *regInput) {
			k := in.a.coseKey()
			in.coseKey = concat([]byte{0xa5}, []byte{0x20, 0x01}, []byte{0x03, 0x26}, []byte{0x01, 0x02},
				[]byte{0x22}, cborBytes(k[-3].([]byte)), []byte{0x21}, cborBytes(k[-2].([]byte)))
		}},
	}
}

func assert(w *webauthn.WebAuthn, c asnCase) assertionVector {
	reg, u, credential, a := register(w, c.alg, false, c.reg)
	if !reg.Expect.OK {
		panic(fmt.Sprintf("assertion %s: registration failed: %s", c.name, reg.Expect.Error))
	}
	if c.storedFix != nil {
		c.storedFix(credential)
	}
	stored, err := json.Marshal(credential, jsonOptions)
	must(err)
	var reloaded webauthn.Credential
	must(json.Unmarshal(stored, &reloaded))
	u.credentials = []webauthn.Credential{reloaded}

	assertion, session, err := w.BeginDiscoverableLogin(webauthn.WithLoginOrigin(origin), webauthn.WithUserVerification(protocol.VerificationRequired))
	must(err)
	_ = assertion
	h := sha256.Sum256([]byte(rpID))
	handle := b64.EncodeToString(u.handle)
	in := &asnInput{
		client:     clientData{typ: "webauthn.get", challenge: session.Challenge, origin: origin},
		rpHash:     h[:],
		flags:      byte(credential.Flags.ProtocolValue()) &^ flagAT,
		id:         b64.EncodeToString(credential.ID),
		rawID:      b64.EncodeToString(credential.ID),
		typ:        "public-key",
		userHandle: &handle,
	}
	in.flags |= flagUP | flagUV
	if c.mutate != nil {
		c.mutate(in)
	}
	var authData bytes.Buffer
	authData.Write(in.rpHash)
	authData.WriteByte(in.flags)
	_ = binary.Write(&authData, binary.BigEndian, in.counter)
	authData.Write(in.ext)
	authData.Write(in.authTail)
	ad := authData.Bytes()
	if in.authData != nil {
		ad = in.authData(ad)
	}
	clientJSON := in.client.bytes()
	sig := a.sign(append(append([]byte{}, ad...), sha(clientJSON)...))
	if in.sig != nil {
		sig = in.sig(sig)
	}
	response := map[string]any{
		"clientDataJSON":    b64.EncodeToString(clientJSON),
		"authenticatorData": b64.EncodeToString(ad),
		"signature":         b64.EncodeToString(sig),
	}
	if in.userHandle != nil {
		response["userHandle"] = *in.userHandle
	}
	cred := map[string]any{"id": in.id, "rawId": in.rawID, "type": in.typ, "response": response}
	if in.clientExt != "" {
		cred["clientExtensionResults"] = jsontext.Value(in.clientExt)
	}
	if in.attachment != "" {
		cred["authenticatorAttachment"] = in.attachment
	}
	raw, err := json.Marshal(cred, json.Deterministic(true))
	must(err)
	raw = append(raw, in.jsonTail...)

	var result *webauthn.Credential
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err == nil {
		_, result, err = w.ValidatePasskeyLogin(func(id, userHandle []byte) (webauthn.User, error) {
			if !bytes.Equal(id, reloaded.ID) || !bytes.Equal(userHandle, u.handle) {
				return nil, errors.New("unknown credential")
			}
			return u, nil
		}, *session, parsed)
	}
	return assertionVector{
		Name: c.name, UserHandle: handle, Stored: string(stored), Session: sessionOf(session),
		Response: string(raw), Expect: verdict(err, result),
	}
}

type optionsVector struct {
	Name       string        `json:"name"`
	UserHandle string        `json:"user_handle"`
	UserName   string        `json:"user_name"`
	Exclusions []exclusion   `json:"exclusions"`
	Session    sessionVector `json:"session"`
	PublicKey  string        `json:"public_key"`
}

type exclusion struct {
	ID         string   `json:"id"`
	Transports []string `json:"transports"`
}

func options(w *webauthn.WebAuthn) []optionsVector {
	var out []optionsVector
	for _, c := range []struct {
		name       string
		exclusions []exclusion
	}{
		{name: "register"},
		{name: "register-with-exclusions", exclusions: []exclusion{
			{ID: b64.EncodeToString([]byte("credential-1")), Transports: []string{"internal", "hybrid"}},
			{ID: b64.EncodeToString([]byte("credential-2")), Transports: []string{}},
		}},
	} {
		u := &user{handle: []byte(rand.Text()), name: "Ada Lovelace"}
		descriptors := make([]protocol.CredentialDescriptor, 0, len(c.exclusions))
		for _, e := range c.exclusions {
			id, err := b64.DecodeString(e.ID)
			must(err)
			credential := webauthn.Credential{ID: id, AttestationFormat: "none"}
			for _, t := range e.Transports {
				credential.Transport = append(credential.Transport, protocol.AuthenticatorTransport(t))
			}
			descriptors = append(descriptors, credential.Descriptor())
		}
		creation, session, err := w.BeginRegistration(u,
			webauthn.WithRegistrationOrigin(origin),
			webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey:      protocol.ResidentKeyRequirementRequired,
				UserVerification: protocol.VerificationRequired,
			}), webauthn.WithExclusions(descriptors))
		must(err)
		creation.Response.Timeout = 120000
		publicKey, err := json.Marshal(creation.Response, jsonOptions)
		must(err)
		if c.exclusions == nil {
			c.exclusions = []exclusion{}
		}
		out = append(out, optionsVector{Name: c.name, UserHandle: b64.EncodeToString(u.handle), UserName: u.name,
			Exclusions: c.exclusions, Session: sessionOf(session), PublicKey: string(publicKey)})
	}
	assertion, session, err := w.BeginDiscoverableLogin(webauthn.WithLoginOrigin(origin), webauthn.WithUserVerification(protocol.VerificationRequired))
	must(err)
	assertion.Response.Timeout = 120000
	publicKey, err := json.Marshal(assertion.Response, jsonOptions)
	must(err)
	out = append(out, optionsVector{Name: "login", Exclusions: []exclusion{}, Session: sessionOf(session), PublicKey: string(publicKey)})
	return out
}

type fixtureVector struct {
	Name     string `json:"name"`
	Response string `json:"response"`
	Expect   expect `json:"expect"`
}

func fixtures() []fixtureVector {
	dir := os.Getenv("APRON_GO_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		must(err)
		dir = filepath.Join(home, "Developer/forks/apron-server-go")
	}
	data, err := os.ReadFile(filepath.Join(dir, "testdata/apron/tests/fixtures/webauthn.json"))
	must(err)
	var fixture struct {
		Cases []struct {
			Name   string `json:"name"`
			Finish *struct {
				Params struct {
					Credential jsontext.Value `json:"credential"`
				} `json:"params"`
			} `json:"finish"`
		} `json:"cases"`
	}
	must(json.Unmarshal(data, &fixture))
	var out []fixtureVector
	for _, c := range fixture.Cases {
		if c.Finish == nil {
			continue
		}
		raw := []byte(c.Finish.Params.Credential)
		must((*jsontext.Value)(&raw).Compact())
		_, err := protocol.ParseCredentialCreationResponseBytes(raw)
		out = append(out, fixtureVector{Name: c.Name, Response: string(raw), Expect: verdict(err, nil)})
	}
	return out
}

type vectors struct {
	Generator     string               `json:"generator"`
	RPID          string               `json:"rp_id"`
	RPOrigins     []string             `json:"rp_origins"`
	Options       []optionsVector      `json:"options"`
	Registrations []registrationVector `json:"registrations"`
	Assertions    []assertionVector    `json:"assertions"`
	Fixtures      []fixtureVector      `json:"fixtures"`
}

func main() {
	w := newWebAuthn()
	v := vectors{
		Generator: "tools/differential/webauthn (go-webauthn v0.18.2)",
		RPID:      rpID, RPOrigins: []string{origin, otherOrigin},
		Options:  options(w),
		Fixtures: fixtures(),
	}
	names := map[string]bool{}
	for _, c := range registrationCases() {
		if names[c.name] {
			panic("duplicate case " + c.name)
		}
		names[c.name] = true
		r, _, _, _ := register(w, c.alg, c.unbind, c.mutate)
		r.Name = c.name
		v.Registrations = append(v.Registrations, r)
	}
	for _, c := range assertionCases() {
		v.Assertions = append(v.Assertions, assert(w, c))
	}
	out, err := json.Marshal(v, jsontext.WithIndent("  "), json.Deterministic(true))
	must(err)
	if !strings.HasSuffix(string(out), "\n") {
		out = append(out, '\n')
	}
	_, err = os.Stdout.Write(out)
	must(err)
}
