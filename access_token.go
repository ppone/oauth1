package oauth1

/*
It uses the escape and isEscapable function that are taken from https://github.com/mrjones/oauth/blob/master/oauth.go
*/

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

//Need to use a custom escape function, currently Go does not have any offical packages that can escape url based on the
//requirements for the Oauth spec
func escape(s string) string {
	t := make([]byte, 0, 3*len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isEscapable(c) {
			t = append(t, '%')
			t = append(t, "0123456789ABCDEF"[c>>4])
			t = append(t, "0123456789ABCDEF"[c&15])
		} else {
			t = append(t, s[i])
		}
	}
	return string(t)
}

func isEscapable(b byte) bool {
	return !('A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~')

}

type AccessToken struct {
	ConsumerKey string
	Token       string
	Hash        hash.Hash
}

// Creates a new access token.
func NewAccessToken(consumerKey, consumerSecret, token, secret string) *AccessToken {
	key := url.QueryEscape(consumerSecret) + "&" + url.QueryEscape(secret)
	return &AccessToken{consumerKey, token, hmac.New(sha1.New, []byte(key))}
}

// Signs an HTTP request. The authorization is set in the Authorization header.
func (t AccessToken) SignRequestHeader(request *http.Request) {
	params := t.signedQueryMap(request)
	header := "OAuth realm=\"\""
	for k, v := range params {
		if strings.Index(k, "oauth_") == 0 {
			header += ","
			header += k
			header += "=\""
			header += v[0]
			header += "\""
		}
	}
	request.Header.Set("Authorization", header)
}

// Parses the request's query and adds OAuth authorization parameters to the resulting map.
func (t AccessToken) signedQueryMap(request *http.Request) url.Values {
	params, _ := url.ParseQuery(request.URL.RawQuery)

	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)

	params["oauth_consumer_key"] = []string{t.ConsumerKey}
	params["oauth_nonce"] = []string{hex.EncodeToString(nonceBytes)}
	params["oauth_signature_method"] = []string{"HMAC-SHA1"}
	params["oauth_timestamp"] = []string{strconv.Itoa(time.Now().Second())}
	params["oauth_token"] = []string{t.Token}
	params["oauth_version"] = []string{"1.0"}

	sigBase := signatureBaseString(request.Method, request.URL.Scheme, request.URL.Host, request.URL.Path, encodeSortedQuery(params))
	t.Hash.Reset()
	t.Hash.Write([]byte(sigBase))
	rawSignature := t.Hash.Sum(nil)
	signature := make([]byte, base64.StdEncoding.EncodedLen(len(rawSignature)))
	base64.StdEncoding.Encode(signature, rawSignature)
	params["oauth_signature"] = []string{string(signature)}

	return params
}

// Computes the signature base string for the given HTTP method and URL components.
func signatureBaseString(method, scheme, host, path, sortedQuery string) string {
	scheme = strings.ToLower(scheme)
	hostAndPort := strings.Split(host, ":")
	baseURI := scheme + "://" + strings.ToLower(hostAndPort[0])
	if len(hostAndPort) == 2 {
		if (scheme == "http" && hostAndPort[1] != "80") || (scheme == "https" && hostAndPort[1] != "443") {
			baseURI += ":" + hostAndPort[1]
		}
	}
	baseURI += path

	return strings.ToUpper(method) + "&" + escape(baseURI) + "&" + escape(sortedQuery)
}

// Given a map like the one returned by url.ParseQuery, returns an encoded query string that is
// sorted by key and value.
func encodeSortedQuery(queryMap map[string][]string) string {
	if len(queryMap) == 0 {
		return ""
	}

	pairs := make(orderedPairs, len(queryMap))
	i := 0
	for k, v := range queryMap {
		sort.Strings(v)
		pairs[i] = make([]interface{}, 2)
		pairs[i][0] = k
		pairs[i][1] = v
		i += 1
	}
	sort.Sort(pairs)

	var queryStr string
	for _, pair := range pairs {
		k, _ := pair[0].(string)
		vv, _ := pair[1].([]string)
		for _, v := range vv {
			queryStr += escape(k)
			queryStr += "="
			queryStr += escape(v)
			queryStr += "&"
		}
	}
	return strings.TrimRight(queryStr, "&")
}

// orderedPairs is used by encodeSortedQuery to enable sorting of key-values pairs, i.e.
// [[k [v v …]] [k [v v …]] …]
type orderedPairs [][]interface{}

func (o orderedPairs) Len() int {
	return len(o)
}

func (o orderedPairs) Less(i, j int) bool {
	oi, _ := o[i][0].(string)
	oj, _ := o[j][0].(string)
	return oi < oj
}

func (o orderedPairs) Swap(i, j int) {
	tmp := o[i]
	o[i] = o[j]
	o[j] = tmp
}
