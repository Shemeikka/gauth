# gauth
Authentication library written in Go.

## Authentication

This authentication method is based on [Amazon AWS REST authentication](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html). 

API uses Authorization-header with following format: "SCHEME public_id:signature".

Example:

    "Authorization: VPS MTIzMjE0MTIzMg==:aHU5Ru1DykQh88JjO9bs1Kk0ybv3D1bTEEUo+1SYPg4="

Header's value is formed from scheme, public id, and hmac hash.

- Scheme: VPS
- Public ID: Base64 encoded sender's id
- Signature: Base64 encoded hmac hash
 - HMAC-SHA256 (RFC 4868)

### Workflow

1. Check if date is within allowed limit
2. Check signature
3. Check content-md5 hash if set

### Root-URL

Root-url is /api/vX.

X is API version number.

### Signature

Signature is used for authenticating sender and validating the integrity of the request. Both sender and receiver will calculate signature using same details and if signatures don't match, request is denied and HTTP 401 - Unauthorized is returned.

Signature is Base64 encoded HMAC-SHA256 hash in hex-format.

Format:

    Signature = Base64( HMAC-SHA256( PrivateAPIKey, UTF-8-Encoding-Of( StringToSign ) ) )

StringToSign has following format:

    StringToSign = HTTP-Verb + "\n" +
		Content-MD5 + "\n" +
		Content-Type + "\n" +
		Date + "\n" +
		CanonicalizedResource;

- HTTP-verb: Used HTTP method in capital letters. Newline is added to the end.
 - E.q. GET
- Mandatory headers
 - content-md5: Base64 encoded MD5-hash of the request's body. With GET-method, this is empty string (""). Newline is added to the end.
 - content-type: Content type for the request, e.q. application/json. With GET-method, this is empty string (""). Newline is added to the end.
 - date: Datetime in format Sun, 06 Nov 1994 08:49:37 GMT (RFC 1123). Newline is added to the end.
 - CanonicalizedResource: Target route and with GET-method, also parameters are included.

Example where content-md5 and content-type are empty (""):

    GET
    
    
    Tue, 29 Jul 2014 07:09:12 GMT
    /api/hello/tete?testi

###### CanonicalizedResource

How to build:

1. Create an empty string
2. Add root-url to this string
3. Add resource path without parameters to this string
  - e.q. "/hello/world"
4. Sort query parameters
5. URL decode parameters and their values
6. Add ? to this string
7. Add query parameters to this string in format parametername=parametervalue&parametername=parametervalue
  - If parameter has multiple values, separate those with comma (,)
    - E.q.parametername=parametervalue,parametervalue2&parametername=parametervalue,parametervalue2

Target:

	https://www.example.com/api/hello/world?testi=1234&name=tester

CanonicalizedResource:

	/api/hello/world?testi=1234&name=tester
