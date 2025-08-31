package verisig

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const actorHandlerTemplate = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    {
      "manuallyApprovesFollowers": "as:manuallyApprovesFollowers",
      "toot": "http://joinmastodon.org/ns#",
      "featured": {
        "@id": "toot:featured",
        "@type": "@id"
      },
      "featuredTags": {
        "@id": "toot:featuredTags",
        "@type": "@id"
      },
      "alsoKnownAs": {
        "@id": "as:alsoKnownAs",
        "@type": "@id"
      },
      "movedTo": {
        "@id": "as:movedTo",
        "@type": "@id"
      },
      "schema": "http://schema.org#",
      "PropertyValue": "schema:PropertyValue",
      "value": "schema:value",
      "discoverable": "toot:discoverable",
      "Device": "toot:Device",
      "Ed25519Signature": "toot:Ed25519Signature",
      "Ed25519Key": "toot:Ed25519Key",
      "Curve25519Key": "toot:Curve25519Key",
      "EncryptedMessage": "toot:EncryptedMessage",
      "publicKeyBase64": "toot:publicKeyBase64",
      "deviceId": "toot:deviceId",
      "claim": {
        "@type": "@id",
        "@id": "toot:claim"
      },
      "fingerprintKey": {
        "@type": "@id",
        "@id": "toot:fingerprintKey"
      },
      "identityKey": {
        "@type": "@id",
        "@id": "toot:identityKey"
      },
      "devices": {
        "@type": "@id",
        "@id": "toot:devices"
      },
      "messageFranking": "toot:messageFranking",
      "messageType": "toot:messageType",
      "cipherText": "toot:cipherText",
      "suspended": "toot:suspended",
      "memorial": "toot:memorial",
      "indexable": "toot:indexable",
      "Hashtag": "as:Hashtag",
      "focalPoint": {
        "@container": "@list",
        "@id": "toot:focalPoint"
      }
    }
  ],
  "id": "https://social.matej-lach.me/user/MatejLach",
  "type": "Person",
  "following": "https://social.matej-lach.me/user/MatejLach/following",
  "followers": "https://social.matej-lach.me/user/MatejLach/followers",
  "inbox": "https://social.matej-lach.me/user/MatejLach/inbox",
  "outbox": "https://social.matej-lach.me/user/MatejLach/outbox",
  "featured": "https://social.matej-lach.me/user/MatejLach/collections/featured",
  "featuredTags": "https://social.matej-lach.me/user/MatejLach/collections/tags",
  "preferredUsername": "MatejLach",
  "name": "Matej Ľach  ✅",
  "summary": "<p>Free software enthusiast, <a href=\\"https://social.matej-lach.me/tags/golang\\" class=\\"mention hashtag\\" rel=\\"tag\\"><span>#golang</span></a>, <a href=\\"https://social.matej-lach.me/tags/rustlang\\" class=\\"mention hashtag\\" rel=\\"tag\\"><span>#rustlang</span></a>, <a href=\\"https://social.matej-lach.me/tags/swiftlang\\" class=\\"mention hashtag\\" rel=\\"tag\\"><span>#swiftlang</span></a>  . Working on a question/answer <a href=\\"https://social.matej-lach.me/tags/ActivityPub\\" class=\\"mention hashtag\\" rel=\\"tag\\"><span>#ActivityPub</span></a> server. <a href=\\"https://social.matej-lach.me/tags/systemd\\" class=\\"mention hashtag\\" rel=\\"tag\\"><span>#systemd</span></a> aficionado :-)</p>",
  "url": "https://social.matej-lach.me/@MatejLach",
  "manuallyApprovesFollowers": false,
  "discoverable": true,
  "indexable": false,
  "published": "2017-10-26T00:00:00Z",
  "memorial": false,
  "devices": "https://social.matej-lach.me/user/MatejLach/collections/devices",
  "publicKey": {
    "id": "https://social.matej-lach.me/user/MatejLach#main-key",
    "owner": "https://social.matej-lach.me/user/MatejLach",
    "publicKeyPem": "%s"
  },
  "tag": [
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/golang",
      "name": "#golang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/activitypub",
      "name": "#activitypub"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/rustlang",
      "name": "#rustlang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/swiftlang",
      "name": "#swiftlang"
    },
    {
      "type": "Hashtag",
      "href": "https://social.matej-lach.me/tags/systemd",
      "name": "#systemd"
    }
  ],
  "attachment": [],
  "endpoints": {
    "sharedInbox": "https://social.matej-lach.me/inbox"
  },
  "icon": {
    "type": "Image",
    "mediaType": "image/png",
    "url": "https://social.matej-lach.me/system/accounts/avatars/000/000/001/original/6e9242b03795bf80.png"
  },
  "image": {
    "type": "Image",
    "mediaType": "image/png",
    "url": "https://social.matej-lach.me/system/accounts/headers/000/000/001/original/f18240c45b0ac254.png"
  }
}`

func TestReqSignature(t *testing.T) {
	// table of test cases
	tests := []struct {
		name           string
		actorPath      string // path on the test server that serves the actor JSON
		endpointPath   string // path to the endpoint on the mock server that we want to hit
		reqMethod      string
		reqDate        string // the 'Date' header of the request
		body           string
		keys           []string
		pubKeyName     string
		wantValid      bool
		reqNoOlderThan int // the number of hours since the request was made for which it is still considered valid
		expectedErr    error
	}{
		{
			name:         "valid signature – happy path",
			actorPath:    "/user/me",
			endpointPath: "/inbox",
			reqMethod:    http.MethodPost,
			reqDate:      time.Now().UTC().Format(http.TimeFormat),
			body:         "some toot",
			keys: func() []string {
				privPEM, pubPEM := generatePEMEncodedRSAKeyPair(t)
				return []string{privPEM, pubPEM}
			}(),
			pubKeyName:     "main-key",
			wantValid:      true,
			reqNoOlderThan: 12,
		},
		{
			name:         "request too old",
			actorPath:    "/user/me",
			endpointPath: "/inbox",
			reqMethod:    http.MethodPost,
			reqDate:      time.Now().Add(time.Hour * time.Duration(-15)).Format(http.TimeFormat),
			body:         "some toot",
			keys: func() []string {
				privPEM, pubPEM := generatePEMEncodedRSAKeyPair(t)
				return []string{privPEM, pubPEM}
			}(),
			pubKeyName:     "main-key",
			reqNoOlderThan: 12,
			expectedErr:    errors.New("incoming request is too old to process"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// key pair for each test
			privKeyPEM, pubKeyPEM := tc.keys[0], tc.keys[1]

			// Build the actor JSON with the generated public key.
			actorJSON := fmt.Sprintf(actorHandlerTemplate, pubKeyPEM)

			// Start a test server that serves the actor JSON.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/ld+json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(actorJSON))
			}))
			defer server.Close()

			// Construct the request that will be signed.
			reqURL := server.URL + tc.endpointPath
			req, err := http.NewRequest(tc.reqMethod, reqURL, strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("creating request: %v", err)
			}
			req.Header.Set("date", tc.reqDate)

			// Sign the request using the key ID and the private key.
			keyID, _ := url.Parse(fmt.Sprintf("%s%s#%s", server.URL, tc.actorPath, tc.pubKeyName))
			if err := SignRequest(context.Background(), req, keyID, privKeyPEM); err != nil {
				t.Fatalf("signing request: %v", err)
			}

			// Verify the signature.
			valid, err := ReqHasValidSignature(context.Background(), req, pubKeyPEM, tc.reqNoOlderThan)
			if tc.expectedErr != nil && err == nil {
				t.Fatalf("expected an error but got none")
			}
			if tc.expectedErr == nil && err != nil {
				t.Fatalf("did not expect an error but got: %v", err)
			}
			assert.Equal(t, tc.wantValid, valid, "signature validity mismatch")
		})
	}
}

func generatePEMEncodedRSAKeyPair(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	var privBuf bytes.Buffer
	var pubBuf bytes.Buffer

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}

	// Private key
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(&privBuf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}); err != nil {
		t.Fatalf("encoding private key: %v", err)
	}

	// Public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	if err := pem.Encode(&pubBuf, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	}); err != nil {
		t.Fatalf("encoding public key: %v", err)
	}

	return privBuf.String(), pubBuf.String()
}
