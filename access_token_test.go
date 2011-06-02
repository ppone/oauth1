package oauth1

import (
	"crypto/rand"
	"http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignRequestQuery(t *testing.T) {
	realRandReader := rand.Reader
	rand.Reader = &mockRandReader{"abcdefghijklmnop"}

	token := NewAccessToken("abcd", "efgh", "ijkl", "mnop")
	request, _ := http.NewRequest("GET", "http://host.net/resource?a=b&c=d", nil)
	token.SignRequestQuery(request)
	params, _ := http.ParseQuery(request.URL.RawQuery)
	assertEqual("abcd", params["oauth_consumer_key"][0], t)
	assertEqual("HMAC-SHA1", params["oauth_signature_method"][0], t)
	assertEqual(strconv.Itoa64(time.Seconds()), params["oauth_timestamp"][0], t)
	assertEqual("ijkl", params["oauth_token"][0], t)
	assertEqual("1.0", params["oauth_version"][0], t)
	assertEqual("6162636465666768696a6b6c6d6e6f70", params["oauth_nonce"][0], t)
	assertEqual("b", params["a"][0], t)
	assertEqual("d", params["c"][0], t)
	// FIXME: can't verify oauth_signature without being able to mock out the timestamp.

	rand.Reader = realRandReader
}

func TestSignRequestHeader(t *testing.T) {
	realRandReader := rand.Reader
	rand.Reader = &mockRandReader{"abcdefghijklmnop"}

	token := NewAccessToken("abcd", "efgh", "ijkl", "mnop")
	request, _ := http.NewRequest("GET", "http://host.net/resource?a=b&c=d", nil)
	token.SignRequestHeader(request)
	for _, pair := range strings.Split(request.Header.Get("Authorization"), ",", -1) {
		keyValue := strings.Split(pair, "=", 2)
		switch keyValue[0] {
		case "oauth_consumer_key":
			assertEqual("\"abcd\"", keyValue[1], t)
		case "oauth_signature_method":
			assertEqual("\"HMAC-SHA1\"", keyValue[1], t)
		case "oauth_timestamp":
			assertEqual("\"" + strconv.Itoa64(time.Seconds()) + "\"", keyValue[1], t)
		case "oauth_token":
			assertEqual("\"ijkl\"", keyValue[1], t)
		case "oauth_nonce":
			assertEqual("\"6162636465666768696a6b6c6d6e6f70\"", keyValue[1], t)
		// FIXME: can't verify oauth_signature without being able to mock out the timestamp.
		}
	}

	rand.Reader = realRandReader
}

func TestSignedQueryMap(t *testing.T) {
	realRandReader := rand.Reader
	rand.Reader = &mockRandReader{"abcdefghijklmnop"}

	token := NewAccessToken("abcd", "efgh", "ijkl", "mnop")
	request, _ := http.NewRequest("GET", "http://host.net/resource?a=b&c=d", nil)
	params := token.signedQueryMap(request)
	assertEqual("abcd", params["oauth_consumer_key"][0], t)
	assertEqual("HMAC-SHA1", params["oauth_signature_method"][0], t)
	assertEqual(strconv.Itoa64(time.Seconds()), params["oauth_timestamp"][0], t)
	assertEqual("ijkl", params["oauth_token"][0], t)
	assertEqual("1.0", params["oauth_version"][0], t)
	assertEqual("6162636465666768696a6b6c6d6e6f70", params["oauth_nonce"][0], t)
	assertEqual("b", params["a"][0], t)
	assertEqual("d", params["c"][0], t)
	// FIXME: can't verify oauth_signature without being able to mock out the timestamp.

	rand.Reader = realRandReader
}

func TestSignatureBaseString(t *testing.T) {
	assertEqual("GET&http%3A%2F%2Fhost.net%2FResource&A%3Db%26c%3DD", signatureBaseString("get", "hTtP", "HOST.NET", "/Resource", "A=b&c=D"), t)
	assertEqual("GET&http%3A%2F%2Fhost.net%2F&", signatureBaseString("get", "http", "host.net:80", "/", ""), t)
	assertEqual("GET&http%3A%2F%2Fhost.net%3A81%2F&", signatureBaseString("get", "http", "host.net:81", "/", ""), t)
	assertEqual("GET&https%3A%2F%2Fhost.net%2F&", signatureBaseString("get", "https", "host.net:443", "/", ""), t)
	assertEqual("GET&https%3A%2F%2Fhost.net%3A444%2F&", signatureBaseString("get", "https", "host.net:444", "/", ""), t)
}

func TestEncodeSortedQuery(t *testing.T) {
	params, _ := http.ParseQuery("tango=t&bravo=b&juliet=j&charlie=c")
	assertEqual("bravo=b&charlie=c&juliet=j&tango=t", encodeSortedQuery(params), t)
	params, _ = http.ParseQuery("delta=yankee&alpha=foxtrot&delta=alpha&alpha=kilo")
	assertEqual("alpha=foxtrot&alpha=kilo&delta=alpha&delta=yankee", encodeSortedQuery(params), t)
	assertEqual("", encodeSortedQuery(make(map[string][]string)), t)
}

func assertEqual(expected, got interface{}, t *testing.T) {
	if expected != got {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

type mockRandReader struct {
	mockData string
}

func (r mockRandReader) Read(b []byte) (n int, err os.Error) {
	rdr := strings.NewReader(r.mockData)
	return rdr.Read(b)
}
