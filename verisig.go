package verisig

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MatejLach/activitystreams"
	"github.com/MatejLach/httpsignatures-go"
)

const (
	requestDateHeader   = "date"
	requestTargetHeader = "(request-target)"
	requestHostHeader   = "host"
	requestDigestHeader = "digest"
)

// ReqHasValidSignature validates the signature of POST requests by default
// reqAuthorPubKeyPem can optionally be specified to be the public key (RSA-SHA256 PEM format) of the actor sending the request, if it is empty, the key is fetched using http.Get
// maxReqHoursOld is the maximum number of hours that can pass since a request was first made for it to still be considered valid
func ReqHasValidSignature(ctx context.Context, req *http.Request, reqAuthorPubKeyPem string, maxReqHoursOld int) (bool, error) {
	var err error

	// verify the request body digest
	if req.Method == http.MethodPost && req.Body != nil {
		gotDigestB64 := req.Header.Get("Digest")
		if gotDigestB64 == "" {
			return false, fmt.Errorf("digest header value should not be empty for a POST request with a non-nil body")
		}

		digestAlgoSplit := strings.SplitN(gotDigestB64, "=", 2)
		if len(digestAlgoSplit) != 2 || digestAlgoSplit[0] != "sha-256" {
			return false, fmt.Errorf("mailformed request digest header; expected a sha-256 digest of the request body")
		}

		gotDigest, err := base64.StdEncoding.DecodeString(digestAlgoSplit[1])
		if err != nil {
			return false, err
		}

		computedDigestB64, err := calculateRequestBodySha256Digest(ctx, req)
		if err != nil {
			return false, err
		}

		computedDigest, err := base64.StdEncoding.DecodeString(computedDigestB64)
		if err != nil {
			return false, err
		}

		if string(gotDigest) != string(computedDigest) {
			return false, fmt.Errorf("digest header value does not match computed digest of the request body")
		}
	}

	// verify the signature
	var comparisonHeader []string
	gotSignature := req.Header.Get("Signature")
	if gotSignature == "" {
		return false, fmt.Errorf("no Signature header found")
	}

	gotSignature = strings.ReplaceAll(gotSignature, ", ", ",")
	sigParts := strings.Split(gotSignature, ",")
	sigMap := make(map[string]string, 3)
	for _, part := range sigParts {
		prefix := strings.Split(part, "=")[0]
		switch prefix {
		case "keyId":
			sigMap["keyId"] = trimQuotes(strings.TrimPrefix(part, "keyId="))
		case "headers":
			sigMap["headers"] = strings.TrimPrefix(part, "headers=")
		case "signature":
			sigMap["signature"] = trimQuotes(strings.TrimPrefix(part, "signature="))
		}
	}

	gotHeaders := strings.Split(sigMap["headers"], " ")
	for idx, sigHeader := range gotHeaders {
		gotHeaders[idx] = trimQuotes(sigHeader)
	}

	if reqAuthorPubKeyPem == "" {
		sendingActorId, err := url.Parse(sigMap["keyId"])
		if err != nil {
			return false, err
		}

		reqActor, err := getActor(sendingActorId)
		if err != nil {
			return false, err
		}

		reqAuthorPubKeyPem = reqActor.PublicKey.PublicKeyPem
	}

	sendingActorPubKey, err := pubKeyFromString(reqAuthorPubKeyPem)
	if err != nil {
		return false, err
	}

	// reconstruct the signed headers from the plaintext headers sent as part of the request
	for _, sigHeader := range gotHeaders {
		if sigHeader == requestTargetHeader {
			switch req.Method {
			case http.MethodGet:
				comparisonHeader = append(comparisonHeader, fmt.Sprintf("%s: %s", requestTargetHeader, requestTarget(req)))
			case http.MethodPost:
				comparisonHeader = append(comparisonHeader, fmt.Sprintf("%s: post /inbox", requestTargetHeader))
			}
		} else {
			comparisonHeader = append(comparisonHeader, fmt.Sprintf("%s: %s", sigHeader, req.Header.Get(strings.ToUpper(sigHeader))))
		}
	}

	comparisonHeaderDigest := sha256.Sum256([]byte(strings.Join(comparisonHeader, "\n")))

	// verify that Date is no more than 12 hours old
	reqDate, err := http.ParseTime(req.Header.Get("Date"))
	if err != nil {
		return false, err
	}

	if reqDate.Before(time.Now().Add(time.Hour * time.Duration(-maxReqHoursOld))) {
		return false, fmt.Errorf("incoming request is too old to process")
	}

	// the signature is base64 encoded in addition to being encrypted with the sending actor's private key
	decodedSig, err := base64.StdEncoding.DecodeString(sigMap["signature"])
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(sendingActorPubKey, crypto.SHA256, comparisonHeaderDigest[:], decodedSig)
	if err == nil {
		return true, nil
	}

	return false, err
}

func SignRequest(ctx context.Context, req *http.Request, keyId *url.URL, privateKeyPem string) error {
	req.Header.Set(requestTargetHeader, requestTarget(req))
	req.Header.Set(requestHostHeader, req.URL.Host)

	signHeaders := []string{requestTargetHeader, requestHostHeader, requestDateHeader}

	if req.Method == http.MethodPost && req.Body != nil {
		if req.Header.Get(requestDigestHeader) == "" {
			reqBodyDigest, err := calculateRequestBodySha256Digest(ctx, req)
			if err != nil {
				return err
			}
			req.Header.Set(requestDigestHeader, fmt.Sprintf("sha-256=%s", reqBodyDigest))
		}
		signHeaders = append(signHeaders, requestDigestHeader)
	}

	sign := httpsignatures.NewSigner(httpsignatures.AlgorithmRsaSha256, signHeaders...)
	return sign.SignRequest(keyId.String(), privateKeyPem, req, false)
}

func pubKeyFromString(publicKey string) (*rsa.PublicKey, error) {
	if publicKey == "" {
		return nil, fmt.Errorf("canot convert an emptpy string to a public key")
	}

	pemBlock, _ := pem.Decode([]byte(publicKey))
	if pemBlock == nil {
		return nil, fmt.Errorf("cannot parse RSA public key; invalid input")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key block is not a valid public key")
	}

	return rsaPubKey, nil
}

// getActor fetches and parses an AS2.0 Actor authoring a given request, given their fully qualified ID
func getActor(reqActorId *url.URL) (*activitystreams.Actor, error) {
	var reqActor activitystreams.Actor
	actorResp, err := http.Get(reqActorId.String())
	if err != nil {
		return nil, err
	}
	defer actorResp.Body.Close()

	err = json.NewDecoder(actorResp.Body).Decode(&reqActor)
	if err != nil {
		return nil, err
	}

	return &reqActor, nil
}

func requestTarget(req *http.Request) string {
	var rUrl string
	if req.URL != nil {
		rUrl = req.URL.RequestURI()
	}

	return fmt.Sprintf("%s %s", strings.ToLower(req.Method), rUrl)
}

// calculateRequestBodySha256Digest computes the sha256 sum of the given request body and base64 encodes the result
func calculateRequestBodySha256Digest(ctx context.Context, req *http.Request) (string, error) {
	var err error

	// don't consume the original request
	rClone := req.Clone(ctx)
	if req.Body != nil {
		rClone.Body, err = req.GetBody()
		if err != nil {
			return "", err
		}
	}

	if rClone.Body == nil {
		return "", fmt.Errorf("cannot calculate digest of an empty request body")
	}

	reqBody, err := io.ReadAll(rClone.Body)
	if err != nil {
		return "", err
	}

	bodyDigest := sha256.Sum256(reqBody)
	return base64.StdEncoding.EncodeToString(bodyDigest[:]), nil
}

func trimQuotes(input string) string {
	return strings.Trim(strings.TrimSpace(input), `"'`)
}
