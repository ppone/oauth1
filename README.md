This is a simple OAuth 1 client library. It does not handle the authorization phase.  At a minimum you need the consumer key and consumer secret.

This code adds a authentication header to your requests.   It will not pull tokens from the server.   You need at a minimum a consumer key and consumer secret.

TODO: The unit tests at access_token_test.go need to be redone, though they are all passing currently

Go Verison Supported: 1.2+.  You can install the package locally if you prefer not to import the github by using goimport (https://github.com/ppone/goimport), a python utilty to install you local go package code.



Example
================================


Here is some example code that might you might use. You must encode the url parameters before creating a request.  I use a custom functions that encodes them using EncodeURLParameters.  Here we just use 1 function and 1 method from oauth1, NewAccessToken, and SignRequestHeader.   That is all you need.

```Go

package main

import "oauth1"
import "fmt"
import "net/http"
import "net/url"
import "io/ioutil"

func EncodeURLParameters(urlstring string) string {
	encodedURLValue, err := url.Parse(urlstring)
	if err != nil {
		panic("Could not parse the url")
	}
	encodedURLValue.RawQuery = encodedURLValue.Query().Encode()

	return encodedURLValue.String()
}

func main() {

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
	}
	
```



