This is a simple OAuth 1 client library. It does not handle the authorization phase.  At a minimum you need the consumer key and
consumer secret.

It uses the escape and isEscapable function that are taken from https://github.com/mrjones/oauth/blob/master/oauth.go

This code adds a authentication header to your requests.   It will not pull tokens from the server.   You need at a minimum a consumer key and
consumer address.

TODO: The unit tests at access_token_test.go need to be redone, though they are all passing currently

Go Verison Supported: 1.2+

Here is some example code that might you might use. You must encode the url parameters before creating a request.  I use a custom functions that
encodes them EncodeURLParameters.  Here we just use 1 function and 1 method from oauth1, NewAccessToken, and SignRequestHeader.   That is all you need.




```Go
package main

import (
  "http"
  "oauth1"
)

func main() {
  client := new(http.Client)
  token := oauth1.NewAccessToken("consumer key", "consumer secret", "token", "token secret")

  request, err := http.NewRequest("GET", "https://api.twitter.com/1/statuses/home_timeline.json", nil)
  if err == nil {
    token.SignRequestQuery(request)
    response, err := client.Do(request)
```


