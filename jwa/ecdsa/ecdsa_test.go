package ecdsa

import (
	"testing"

	_ "crypto/sha256"

	"github.com/KalleDK/go-jwt/jwa/test"
	"github.com/KalleDK/go-jwt/jwt"
)

const es256Pub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`

const es256Priv = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----`

const es384Pub = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----`

const es384Priv = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
-----END PRIVATE KEY-----`

const es512Pub = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----`

const es512Priv = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga
9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN
v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear
jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12
ew==
-----END PRIVATE KEY-----`

func Test_ECDSA(t *testing.T) {

	fixtures := test.JWAFixtures{
		jwt.ES256: {
			Public:  es256Pub,
			Private: es256Priv,
			Header:  `eyJhbGciOiJFUzI1NiJ9`,
			Signatures: map[string]string{
				"Short":  `pYvhcg4aluUvhsOBbeLr8h71uotrvnZSVJOzY0WetOGxc1o5tbuH4RATxsiNIX7H7C6vv4yfBI5Soc9xYQg85w`,
				"Medium": `rjgllxIZlNJTWYkImHYbbNP5QOvCh7AaYZKVYu9vOPiD4e9TwIxU3Zko8awjomMSBHhtRosi6sQHBngy9CQk3g`,
				"Long":   `kSw_kKJycXssa2fD15VgB84dmwwx54WOqFDbAD8vBLBdxfaftKFEOu__ZdrNefQ3FepBATYiZIokCV9nXGJKnQ`,
			},
		},
		jwt.ES384: {
			Public:  es384Pub,
			Private: es384Priv,
			Header:  `eyJhbGciOiJFUzM4NCJ9`,
			Signatures: map[string]string{
				"Short":  `sA7Louzt7HnRbRqiPIdFNrQWE4pqBPK-bcFO3w6pQ0GyM5pyWLic9C0lLvYESiQR1cVxxpmIjdAkUD34PJdwdfYfDcXnoe-1WN7qIU-IUhz2Ry6P0Ai8WmOp5RdBROZK`,
				"Medium": `u7iKd_YWUx3zKkeQ3T98v56Kk7DddKkftvaDyHZVNhAZOldSzYQkwqeehMmTNv6Yp7vo5MuHuK0hEJdpCfWiF_QkeHfAQdjyt80bKvSNYxOj_sWjeE8EyidQvP1YEseT`,
				"Long":   `9nMVCNm6BAy-QECHMtKu3zoTtKBdKeP8EYeqkepgQWpRnfnm9RV9URa7kvgySwXE0CJ6TUiCzuKW6CCNrXEi1x2CDkbM5Ek73eg5xTzHgm7OYvOp1XPbPQqSCa0aFwTI`,
			},
		},
		jwt.ES512: {
			Public:  es512Pub,
			Private: es512Priv,
			Header:  `eyJhbGciOiJFUzUxMiJ9`,
			Signatures: map[string]string{
				"Short":  `Ac4dmwcyLYubIRtNXdMxolV2SU7IJaWss7DSYLAQmxqT1GRzlWDEkWRtKAzuE9GE2XJYmVZU5DFJEFIO8deCv1luATubU74u_CmvVK1se_JzVo2ANOeXVsT4OkCohNPMxM8hhE6LrESG3Bsd-wGGJqYud9BEl8GlJ330pO3FodHXeiZf`,
				"Medium": `AHWYz2lN_7pmZGFcvt4lQJs5fZsXg69PEhfTqfr5W0xEqcYzhBl_F-6sbhXM86lade_Nb30ywrzTWqrMvI82od0gABbCDEGTZR-r7gcjfR49mkhstk0PmOk-PfjTugVtpLzLgwVbNuhWi_fARxBXtjwS5fUuOruA3ZytoPJzZiiNrw9V`,
				"Long":   `ARMG8rJ4H2I3DlY5BYaCV3np5w6J4nbU1fzH1bZEDGzk_inPBeE2eZQEBgfrdbqNcQTEUk4U4NTvseYD-g-PB_uTAU85aE3wVXgPKQXFvvsVa-A0Vui9fgupk-C1cL5_A--dWVYL1OCS-kiZoE-EW0GCJc7H0ygr8K8mOfzk6U8537Zj`,
			},
		},
	}

	test.TestFixtures(t, fixtures)
}
