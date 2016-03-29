package auth

import (
	"bytes"
	"net/http"
	"testing"
)

func TestCanonicalString(t *testing.T) {
	a := Config{
		RootURL:     "/api/v1",
		SignHeaders: []string{"date", "content-type", "content-md5"},
	}

	var jsonStr = []byte(`{"test": 2}`)
	req, err := http.NewRequest("POST", "https://10.9.53.80/api/v1/groups", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Errorf("Couldn't create new http request: %s", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("content-md5", "123rgesrgert234")
	req.Header.Set("date", "1985")

	sExpected := "POST\n123rgesrgert234\napplication/json\n1985\n/api/v1/groups"
	s := a.CanonicalString(req.Method, req.URL, req.Header)

	if s != sExpected {
		t.Errorf("\nGOT\n****\n%s\n****\nEXPECTED\n****\n%s\n****\n", s, sExpected)
	}
}

func TestMd5(t *testing.T) {
	a := Config{
		RootURL:     "/api/v1",
		SignHeaders: []string{"date", "content-type", "content-md5"},
	}

	// MD5 		2F08071F7A18BC196D2EAECA8499F5D1
	// Base64 	MmYwODA3MWY3YTE4YmMxOTZkMmVhZWNhODQ5OWY1ZDE=
	var jsonStr = []byte(`{"test": 2}`)
	req, err := http.NewRequest("POST", "https://10.9.53.80/api/v1/groups", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Errorf("Couldn't create new http request: %s", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("content-md5", "123rgesrgert234")
	req.Header.Set("date", "1985")

	sExpected := "MmYwODA3MWY3YTE4YmMxOTZkMmVhZWNhODQ5OWY1ZDE="
	s, err := a.CalcMD5(req)
	if err != nil {
		t.Errorf("Error calculating md5 hash: %s", err)
	}

	if s != sExpected {
		t.Errorf("\nGOT\n****\n%v\n****\nEXPECTED\n****\n%v\n****\n", s, sExpected)
	}
}
