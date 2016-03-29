package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Main object
type Config struct {
	RootURL      string
	PrivateKey   string
	PublicID     string
	SignHeaders  []string
	AllowedPaths map[string]string
	DB           *sql.DB
}

type authReader struct {
	*bytes.Buffer
}

// So that it implements the io.ReadCloser interface
func (ar authReader) Close() error { return nil }

// Constuct canonical string of the request
//
// StringToSign = HTTP-Verb + "\n" +
//    Content-MD5 + "\n" +
//    Content-Type + "\n" +
//    Date + "\n" +
//    CanonicalizedResource;
//
// Example
//
// POST
// MDMyNjFlYWJkYTc4ZGEwNTc4NWZiZjYyZWI2YjUzYjU=
// application/json
// Wed, 21 Jan 2015 07:01:02 GMT
// /api/v1/groups/modes
func (a *Config) CanonicalString(m string, u *url.URL, h http.Header) string {
	var s string

	m = strings.ToUpper(m)

	// Add method
	s += m + "\n"

	// Sort headers
	sort.Strings(a.SignHeaders)

	for _, val := range a.SignHeaders {
		// If method is GET and header is content-type, set the value to empty
		if strings.ToLower(val) == "content-type" && m == "GET" {
			s += "\n"
		} else {
			s += h.Get(val) + "\n"
		}

	}

	// Add canonized resource

	// Get path starting from root-url
	// e.q.
	//	url: http://localhost/test/api/v1/groups/modes
	//	root_url: api/v1
	//	path: test/api/v1/groups/modes
	//	=> adds a path api/v1/groups/modes
	s += u.Path[strings.LastIndex(u.Path, a.RootURL):]

	// Sort and append query parameters
	var keys []string
	for k := range u.Query() {
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		s += "?"
		for i, k := range keys {
			s += k + "=" + u.Query().Get(k)
			if i != len(keys)-1 {
				s += "&"
			}
		}
	}

	fmt.Printf("Query params: %v\n", keys)
	fmt.Println("######################")
	fmt.Println("#   String to sign   #")
	fmt.Println("######################")
	fmt.Println(s)
	fmt.Println("######################")
	return s
}

// Construct request's signature
//
// Signature = Base64( HMAC-SHA256( PrivateAPIKey, UTF-8-Encoding-Of( StringToSign ) ) );
func (a *Config) GetSignature(r *http.Request, apiKey string) (string, error) {
	cs := a.CanonicalString(r.Method, r.URL, r.Header)
	key := []byte(apiKey)
	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(cs))
	if err != nil {
		return "", errors.New("Couldn't calculate hmac hash")
	}

	fmt.Printf("\nHMAC-SHA256: %s\n", hex.EncodeToString(h.Sum(nil)))
	return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(h.Sum(nil)))), nil
}

// AddAuth calculates authorization information and adds it to Authorization-header
func (a *Config) AddAuth(r *http.Request) error {
	// Date in RFC 1123
	t := time.Now().UTC()
	r.Header.Set("date", t.Format(http.TimeFormat))

	// Content-MD5 if POST or PUT
	if strings.ToUpper(r.Method) == "POST" || strings.ToUpper(r.Method) == "PUT" {
		hash, err := a.CalcMD5(r)
		if err != nil {
			return err
		}
		r.Header.Set("content-md5", hash)
	}
	if strings.ToUpper(r.Method) == "GET" {
		r.Header.Set("content-type", "")
	}

	id := base64.StdEncoding.EncodeToString([]byte(a.PublicID))
	signature, err := a.GetSignature(r, a.PrivateKey)
	if err != nil {
		return err
	}

	r.Header.Set("Authorization", "VPS "+id+":"+signature)
	return nil
}

// ParseAuthHeader will return public id and signature in base64 decoded format
func (a *Config) ParseAuthHeader(h string) (string, string, error) {
	d := strings.Split(h, " ")
	if len(d) != 2 {
		er := fmt.Sprintf("Couldn't parse authorization header: Splitted length 1 is %d\n", len(d))
		return "", "", errors.New(er)
	}

	//scheme := d[0]
	temp := strings.Split(d[1], ":")
	if len(temp) != 2 {
		er := fmt.Sprintf("Couldn't parse authorization header: Splitted length 2 is %d\n", len(temp))
		return "", "", errors.New(er)
	}

	id, err := base64.StdEncoding.DecodeString(temp[0])
	if err != nil {
		return "", "", errors.New("Couldn't decode public id: " + err.Error())
	}
	hash, err := base64.StdEncoding.DecodeString(temp[1])
	if err != nil {
		return "", "", errors.New("Couldn't decode hash: " + err.Error())
	}

	// Trimming needed?
	return string(id), string(hash), nil
}

// CheckDates will check if request's date is within 10 minutes of current datetime
func (a *Config) CheckDates(reqDate string) (bool, error) {
	t, err := time.Parse(http.TimeFormat, reqDate)
	if err != nil {
		er := fmt.Sprintf("Couldn't format request's date to datetime: %s\n", err.Error())
		return false, errors.New(er)
	}

	cur := time.Now().UTC()

	diff := cur.Sub(t.UTC())
	fmt.Printf("Datetime difference is %s\n", diff.String())
	if diff.Hours() >= 1 {
		return false, nil
	} else if diff.Minutes() > 10 || diff.Minutes() < -10 {
		return false, nil
	} else {
		return true, nil
	}
}

// CheckHash will compare public hash against private hash and returns true if they are a match
func (a *Config) CheckHash(r *http.Request, publicHash, privateKey string) (bool, error) {
	cs := a.CanonicalString(r.Method, r.URL, r.Header)
	key := []byte(privateKey)
	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(cs))
	if err != nil {
		return false, errors.New("Couldn't calculate hmac hash")
	}

	calcHash := hex.EncodeToString(h.Sum(nil))

	if calcHash == publicHash {
		return true, nil
	} else {
		return false, nil
	}
}

// Calculates content-md5 of the request body
func (a *Config) CalcMD5(r *http.Request) (string, error) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", errors.New("Couldn't read request's body")
	}
	// Get 2 copies of the request body
	bOrig := authReader{bytes.NewBuffer(buf)}
	bHash := authReader{bytes.NewBuffer(buf)}

	hash := md5.New()
	_, err = io.WriteString(hash, bHash.String())
	if err != nil {
		return "", errors.New("Couldn't write hash")
	}
	// Set the original body back to request's body
	r.Body = bOrig
	return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(hash.Sum(nil)))), nil
}

// PrivateHash will return private hash from database for given id
func (a *Config) PrivateHash(id string) (string, string, error) {
	var privateHash string
	var class string
	stmt, err := a.DB.Prepare("select apikey, class from apikeys where publicid=?")
	if err != nil {
		return "", "", err
	}
	defer stmt.Close()
	err = stmt.QueryRow(id).Scan(&privateHash, &class)
	return privateHash, class, err
}

// Authenticate is a HTTP middleware that will check if request has proper authorization header
func (a *Config) Authenticate(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authenticate request
		authHeader := r.Header.Get("Authorization")
		contentMD5 := r.Header.Get("Content-MD5")
		date := r.Header.Get("Date")

		if authHeader == "" || date == "" {
			w.WriteHeader(400)
			fmt.Fprintf(w, "Authorization or Date header is not found!")
			return
		}

		validTime, err := a.CheckDates(date)
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "%s\n", err.Error())
			return
		}
		if !validTime {
			w.WriteHeader(401)
			fmt.Fprintf(w, "Date is not between 10 minutes\n")
			return
		}

		publicId, publicHash, err := a.ParseAuthHeader(authHeader)
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "%s\n", err.Error())
			return
		}
		privateHash, class, err := a.PrivateHash(publicId)
		if err == sql.ErrNoRows {
			w.WriteHeader(401)
			fmt.Fprintf(w, "Authentication denied\n")
			return
		} else if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "%s\n", err.Error())
			return
		}

		// Check if class is allowed to access this path
		// Currently path must match exactly
		allowedClasses, found := a.AllowedPaths[r.URL.Path]
		if found {
			// Public id's class is not allowed for this path
			if !strings.Contains(allowedClasses, class) {
				w.WriteHeader(401)
				fmt.Fprintf(w, "Authentication denied! Path is not allowed.\n")
				return
			}
		}

		validHash, err := a.CheckHash(r, publicHash, privateHash)
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "%s\n", err.Error())
			return
		}
		if !validHash {
			w.WriteHeader(401)
			fmt.Fprintf(w, "Authentication denied: Hash missmatch\n")
			return
		}

		if strings.ToUpper(r.Method) == "POST" || strings.ToUpper(r.Method) == "PUT" {
			reqContentMD5, err := a.CalcMD5(r)
			if err != nil {
				w.WriteHeader(400)
				fmt.Fprintf(w, "%s\n", err.Error())
				return
			}
			if reqContentMD5 != contentMD5 {
				w.WriteHeader(401)
				fmt.Fprintf(w, "Authentication denied: Content-MD5 doesn't match\n")
				return
			}
		}

		h.ServeHTTP(w, r)
	})
}
