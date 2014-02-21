package oauth1

/*
@author: Parag Patel

This code is heavily based on https://github.com/DanaDanger/oauth1

It uses the escape and isEscapable function that are taken from https://github.com/mrjones/oauth/blob/master/oauth.go

This code adds a authentication header to your requests.   It will not pull tokens from the server.   You need at a minimum a consumer key and
consumer address.

TODO: The unit tests at access_token_test.go need to be redone, though they are all passing currently

Go Verison Supported: 1.2

Here is some example code that might you might use. You must encode the url parameters before creating a request.  I use a custom functions that
encodes them EncodeURLParameters.  Here we just use 1 function and 1 method from oauth1, NewAccessToken, and SignRequestHeader.   That is all you need.


	token := oauth1.NewAccessToken("consumer_Key", "consumer_secret", "", "")
	urlstring := EncodeURLParameters("http://api.v3.factual.com/t/restaurants-us?q=Coffee,\"Los Angeles\"&limit=1")
	request, err := http.NewRequest("GET", urlstring, nil)
	client := &http.Client{}

	if err != nil {
		fmt.Println("ERROR: ", err)
	}

	token.SignRequestHeader(request)

	result, err := client.Do(request)

	if err != nil {
		fmt.Println("ERROR: ", err)
	}

	content, err := ioutil.ReadAll(result.Body)

	defer result.Body.Close()

	if err != nil {
		fmt.Println("ERROR: ", err)
	}

	fmt.Println(content)


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
	fmt.Println("DEBUGGING OAUTH1 v4")
	fmt.Println(escape("http://api.v3.factual.com/t/restaurants-us?geo={\"$circle\":{\"$center\":[34.06021,-118.41828],\"$meters\": 5000}})"))
	fmt.Println(url.QueryUnescape("http://api.v3.factual.com/t/restaurants-us?geo={\"$circle\":{\"$center\":[34.06021,-118.41828],\"$meters\": 5000}})"))
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
