package auth

import (
	"fmt"
	"testing"

	"github.com/kloudlite/container-registry-authorizer/admin"
)

func TestAuthorizer(t *testing.T) {
	type input struct {
		accountName string // accountname
		userName    string // username
		path        string // /v2/<accountName>/<repoName>/blobs/<digest> , /v2/<accountName>/<repoName>/manifests/<reference>
		method      string // GET, POST, PUT, DELETE
		secretKey   string // secret key
		access      string // read, read_write
		expiry      string // 1h, 1d, 1w, 1m, 1y
	}

	type testCase struct {
		input    input
		expected error
	}

	testCases := []testCase{
		{
			input{
				"test", "test", "/v2/", "GET", "secret", "read", "1d",
			},
			nil,
		},

		{
			input{
				"sample", "test", "/v2/", "POST", "secret", "read", "1d",
			},
			fmt.Errorf("Invalid access"),
		},
		{
			input{
				"sampleacc", "test", "/v2/sampleacc/abc/blobs:slkdfj", "POST", "secret", "read", "1d",
			},
			fmt.Errorf("Invalid access"),
		},
		{
			input{
				"sampleacc", "test", "/v2/sampleacc/abc/blobs:slkdfj", "GET", "secret", "read", "1d",
			},
			nil,
		},
		{
			input{
				"sampleacc", "test", "/v2/sampleacc/abc/manifests:slkdfj", "PUT", "secret", "read_write", "1d",
			},
			nil,
		},

		{
			input{
				"sampleacc", "test", "/v2/sampleacc/abc/manifests:slkdfj", "PUT", "secret", "read", "1d",
			},
			fmt.Errorf("Invalid access"),
		},
	}

	for _, tc := range testCases {

		expiry, err := admin.GetExpirationTime(tc.input.expiry)
		if err != nil {
			t.Errorf("Error getting expiration time: %v", err.Error())
		}

		s, err := admin.GenerateToken(tc.input.userName, tc.input.accountName, tc.input.access, expiry, tc.input.secretKey)
		if err != nil {
			t.Errorf("Error generating token: %v", err)
		}

		result := authorizer(tc.input.userName, s, tc.input.path, tc.input.method, tc.input.secretKey)

		if tc.expected != result {
			if result != nil && tc.expected != nil {
				fmt.Println("ignored [", "output:", result.Error(), "expected:", tc.expected.Error(), "]")
				continue
			}
			t.Errorf("Expected %v but got %v", tc.expected, result)
		}
	}

	fmt.Println("")
}
