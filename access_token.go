package oauth1

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AccessToken struct {
	ConsumerKey string
	Token       string
	Hash        hash.Hash
}

// Creates a new access token.
func NewAccessToken(consumerKey, consumerSecret, token, secret string) *AccessToken {
	key := http.URLEscape(consumerSecret) + "&" + http.URLEscape(secret)
	return &AccessToken{consumerKey, token, hmac.NewSHA1([]byte(key))}
}

// Signs an HTTP request. The authorization is appened to the query in the URL.
func (t AccessToken) SignRequestQuery(request *http.Request) {
	params := t.signedQueryMap(request)
	request.URL.RawQuery = http.EncodeQuery(params)
	request.RawURL = request.URL.String()
	request.URL, _ = http.ParseURL(request.RawURL)
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
			header += http.URLEscape(v[0])
			header += "\""
		}
	}
	request.Header.Set("Authorization", header)
}

// Parses the request's query and adds OAuth authorization parameters to the resulting map.
func (t AccessToken) signedQueryMap(request *http.Request) map[string][]string {
	params, _ := http.ParseQuery(request.URL.RawQuery)

	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)

	params["oauth_consumer_key"] = []string{t.ConsumerKey}
	params["oauth_nonce"] = []string{hex.EncodeToString(nonceBytes)}
	params["oauth_signature_method"] = []string{"HMAC-SHA1"}
	params["oauth_timestamp"] = []string{strconv.Itoa64(time.Seconds())}
	params["oauth_token"] = []string{t.Token}
	params["oauth_version"] = []string{"1.0"}

	sigBase := signatureBaseString(request.Method, request.URL.Scheme, request.URL.Host, request.URL.Path, encodeSortedQuery(params))
	t.Hash.Reset()
	t.Hash.Write([]byte(sigBase))
	rawSignature := t.Hash.Sum()
	signature := make([]byte, base64.StdEncoding.EncodedLen(len(rawSignature)))
	base64.StdEncoding.Encode(signature, rawSignature)
	params["oauth_signature"] = []string{string(signature)}

	return params
}

// Computes the signature base string for the given HTTP method and URL components.
func signatureBaseString(method, scheme, host, path, sortedQuery string) string {
	scheme = strings.ToLower(scheme)
	hostAndPort := strings.Split(host, ":", 2)
	baseURI := scheme + "://" + strings.ToLower(hostAndPort[0])
	if len(hostAndPort) == 2 {
		if (scheme == "http" && hostAndPort[1] != "80") || (scheme == "https" && hostAndPort[1] != "443") {
			baseURI += ":" + hostAndPort[1]
		}
	}
	baseURI += path
	return strings.ToUpper(method) + "&" + http.URLEscape(baseURI) + "&" + http.URLEscape(sortedQuery)
}

// Given a map like the one returned by http.ParseQuery, returns an encoded query string that is
// sorted by key and value.
func encodeSortedQuery(queryMap map[string][]string) string {
	if len(queryMap) == 0 {
		return ""
	}

	pairs := make(orderedPairs, len(queryMap))
	i := 0
	for k, v := range queryMap {
		sort.SortStrings(v)
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
		k = http.URLEscape(k)
		for _, v := range vv {
			queryStr += http.URLEscape(k)
			queryStr += "="
			queryStr += http.URLEscape(v)
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
