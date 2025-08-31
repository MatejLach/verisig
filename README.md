# verisig


`verisig` is a Go library allowing everyone to easily add Mastodon/ActivityPub-compatible HTTP signature to any HTTP request as well 
as verify the validity of a request's signature originating from an ActivityPub server.  

## Usage

[![Go Reference](https://pkg.go.dev/badge/github.com/MatejLach/verisig.svg)](https://pkg.go.dev/github.com/MatejLach/verisig)

### Signing requests

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	// ...

	"github.com/MatejLach/verisig"
)

func main() {
	// ...
	// req is the outgoing request you want to sign
	// server is i.e. an example ActivityPub server you're making the request to
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/user/me", server.URL), nil)
	if err != nil {
		// error handling
	}

	// public key ID of the Actor authoring the outgoing request
	keyID, err := url.Parse("http://127.0.0.1:45243/user/me#main-key")
	if err != nil {
		// error handling
	}
	
	// private key of the Actor authoring the outgoing request, in PEM format
	privKeyPEM := "-----BEGIN RSA PRIVATE KEY----- ...  -----END RSA PRIVATE KEY-----"

	// sign req
	err = verisig.SignRequest(context.Background(), req, keyID, privKeyPEM)
	if err != nil {
		// error handling
	}
}
```

### Verifying requests

```go
package main

import (
	"context"
	// ...

	"github.com/MatejLach/verisig"
)

func main() {
	// ...
	// req is the incoming request whose signature you want to verify
	reqSignatureIsValid, err := verisig.ReqHasValidSignature(context.Background(), req, "", 12)
	if err != nil {
		// error handling
	}
}
```

See the test suite for a more complete example. 

## Contributing

Pull requests and bug reports are welcome.
