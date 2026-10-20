package guided

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type pages func(*http.Request) (*http.Response, error)

func (p pages) RoundTrip(r *http.Request) (*http.Response, error) { return p(r) }

func answering(status int, location, body string, seen *url.Values) *http.Client {
	return &http.Client{Transport: pages(func(r *http.Request) (*http.Response, error) {
		*seen = r.URL.Query()
		header := http.Header{}
		if location != "" {
			header.Set("Location", location)
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

func TestProvidersTellWhetherTheyAcceptAReturnAddress(t *testing.T) {
	ctx := context.Background()
	redirect := CallbackURL("control.example.org", "google")
	var seen url.Values
	ok, err := GoogleAccepts(ctx, answering(302, "https://accounts.google.com/v3/signin/identifier?x=1", "", &seen), "id.apps.googleusercontent.com", redirect)
	if !ok || err != nil || seen.Get("redirect_uri") != redirect || seen.Get("client_id") != "id.apps.googleusercontent.com" {
		t.Fatalf("registered Google address: %v %v %v", ok, err, seen)
	}
	if ok, err := GoogleAccepts(ctx, answering(302, "https://accounts.google.com/signin/oauth/error?authError=x", "", &seen), "id", redirect); ok || err != nil {
		t.Fatalf("unregistered Google address: %v %v", ok, err)
	}
	if _, err := GoogleAccepts(ctx, answering(200, "", "<html>", &seen), "id", redirect); err == nil {
		t.Fatal("a page Google never sends must not count as an answer")
	}

	redirect = CallbackURL("control.example.org", "apple")
	if ok, err := AppleAccepts(ctx, answering(200, "", "<html>Sign in with Apple</html>", &seen), "org.example.signin", redirect); !ok || err != nil || seen.Get("redirect_uri") != redirect {
		t.Fatalf("registered Apple address: %v %v", ok, err)
	}
	for _, code := range []string{"invalid_request", "invalid_client"} {
		if ok, err := AppleAccepts(ctx, answering(200, "", `{"errorMessage":"x","errorCode":"`+code+`"}`, &seen), "org.example.signin", redirect); ok || err != nil {
			t.Fatalf("Apple %s: %v %v", code, ok, err)
		}
	}
	if _, err := AppleAccepts(ctx, answering(503, "", "", &seen), "org.example.signin", redirect); err == nil {
		t.Fatal("an Apple outage must not count as an answer")
	}
}
