// Command crossopen drives a running aprond over WebSocket with the software
// authenticator of internal/server/webauthn_test.go, so a database one
// implementation wrote can be checked under the other:
//
//	crossopen register <ws-url> <origin> <state.json>  registers a guest's passkey; prints user_id and token
//	crossopen resume <ws-url> <origin> <token>         resumes the token; prints user_id
//	crossopen login <ws-url> <origin> <state.json>     signs in with the stored passkey; prints user_id
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"
	"github.com/fxamacker/cbor/v2"
)

type state struct {
	Key     []byte `json:"key"`
	ID      []byte `json:"id"`
	Handle  string `json:"handle"`
	Counter uint32 `json:"counter"`
}

type conn struct {
	ws  *websocket.Conn
	ctx context.Context
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func dial(url, origin string) *conn {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {origin}}})
	if err != nil {
		fail("dial: %v", err)
	}
	c := &conn{ws, ctx}
	if frame := c.read(); frame["method"] != "server" {
		fail("first frame: %v", frame)
	}
	return c
}

func (c *conn) read() map[string]any {
	_, data, err := c.ws.Read(c.ctx)
	if err != nil {
		fail("read: %v", err)
	}
	var frame map[string]any
	if err := json.Unmarshal(data, &frame); err != nil {
		fail("frame: %v", err)
	}
	return frame
}

// call sends a request and returns its result, skipping notifications.
func (c *conn) call(id string, params map[string]any) map[string]any {
	data, _ := json.Marshal(map[string]any{"method": "auth", "id": id, "params": params})
	if err := c.ws.Write(c.ctx, websocket.MessageText, data); err != nil {
		fail("write: %v", err)
	}
	for {
		frame := c.read()
		if frame["id"] != id {
			continue
		}
		result, ok := frame["result"].(map[string]any)
		if !ok {
			fail("%s: %v", id, frame)
		}
		return result
	}
}

func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func clientData(kind, challenge, origin string) []byte {
	data, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return data
}

func challenge(options map[string]any) string {
	return options["public_key"].(map[string]any)["challenge"].(string)
}

func register(url, origin, path string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fail("key: %v", err)
	}
	s := state{ID: []byte(rand.Text())}
	if s.Key, err = x509.MarshalECPrivateKey(key); err != nil {
		fail("key: %v", err)
	}
	c := dial(url, origin)
	c.call("guest", map[string]any{"scheme": "guest"})
	options := c.call("begin", map[string]any{"scheme": "webauthn", "action": "register", "step": "begin", "name": "Cross Open"})
	s.Handle = options["public_key"].(map[string]any)["user"].(map[string]any)["id"].(string)
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	hash := sha256.Sum256([]byte("localhost"))
	data := append(hash[:], 0x45, 0, 0, 0, 0)
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(s.ID)))
	data = append(data, s.ID...)
	data = append(data, cose...)
	attestation, _ := cbor.Marshal(map[string]any{"fmt": "none", "authData": data, "attStmt": map[string]any{}})
	result := c.call("finish", map[string]any{
		"scheme": "webauthn", "action": "register", "step": "finish", "challenge_id": options["challenge_id"],
		"credential": map[string]any{
			"id": b64(s.ID), "rawId": b64(s.ID), "type": "public-key", "clientExtensionResults": map[string]any{},
			"response": map[string]any{"clientDataJSON": b64(clientData("webauthn.create", challenge(options), origin)), "attestationObject": b64(attestation)},
		},
	})
	saved, _ := json.Marshal(s)
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		fail("state: %v", err)
	}
	fmt.Println(result["you"].(map[string]any)["user_id"], result["token"])
}

func resume(url, origin, token string) {
	result := dial(url, origin).call("resume", map[string]any{"scheme": "token", "token": token})
	fmt.Println(result["you"].(map[string]any)["user_id"])
}

func login(url, origin, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail("state: %v", err)
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		fail("state: %v", err)
	}
	key, err := x509.ParseECPrivateKey(s.Key)
	if err != nil {
		fail("key: %v", err)
	}
	s.Counter++
	c := dial(url, origin)
	options := c.call("begin", map[string]any{"scheme": "webauthn", "action": "login", "step": "begin"})
	client := clientData("webauthn.get", challenge(options), origin)
	hash := sha256.Sum256([]byte("localhost"))
	data := append(hash[:], 0x05)
	data = binary.BigEndian.AppendUint32(data, s.Counter)
	clientHash := sha256.Sum256(client)
	signed := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, signed[:])
	if err != nil {
		fail("sign: %v", err)
	}
	result := c.call("finish", map[string]any{
		"scheme": "webauthn", "action": "login", "step": "finish", "challenge_id": options["challenge_id"],
		"credential": map[string]any{
			"id": b64(s.ID), "rawId": b64(s.ID), "type": "public-key", "clientExtensionResults": map[string]any{},
			"response": map[string]any{"clientDataJSON": b64(client), "authenticatorData": b64(data), "signature": b64(signature), "userHandle": s.Handle},
		},
	})
	saved, _ := json.Marshal(s)
	_ = os.WriteFile(path, saved, 0o600)
	fmt.Println(result["you"].(map[string]any)["user_id"])
}

func main() {
	if len(os.Args) != 5 {
		fail("usage: crossopen register|resume|login <ws-url> <origin> <state.json|token>")
	}
	switch os.Args[1] {
	case "register":
		register(os.Args[2], os.Args[3], os.Args[4])
	case "resume":
		resume(os.Args[2], os.Args[3], os.Args[4])
	case "login":
		login(os.Args[2], os.Args[3], os.Args[4])
	default:
		fail("unknown mode %s", os.Args[1])
	}
}
