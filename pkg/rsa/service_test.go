// Copyright 2018 SumUp Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/os/ostest"
)

func TestService_ReadPublicKeyFromPath(t *testing.T) {
	t.Run(
		"when reading 'publicKeyPath' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			publicKeyPathArg := "/tmp/example.pub"

			fakeError := errors.New("fakePublicKeyReadError")

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				publicKeyPathArg,
			).Return(
				nil,
				fakeError,
			)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPublicKeyFromPath(publicKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"unable to read file contents of public key",
			)

			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"when reading 'publicKeyPath' fails due to contents not being PEM-formatted, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			publicKeyPathArg := "/tmp/example.pub"
			// NOTE: Valid public key content, but not PEM-formatted.
			publicKeyContents := []byte(
				`MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFfrDbBAwSEYU7f77tHpmM2A0NiF
KAA0+sw3TpTo0GXhxueMgtgS3iJs5Nq97ix7YKxDjUMRx8W78o4ALLWNcoHLe96G
AdpaWfdQ1OdE933CwWtAQBwZuBT9qQKQ549lhti+xECr+/ImnY2v4mEJ0QcRMGXy
jmOSPbzP/LUC93k7AgMBAAE=`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				publicKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPublicKeyFromPath(publicKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errDecodePublicKeyPem, actualErr)
		},
	)

	t.Run(
		"when reading 'publicKeyPath' fails due to not being `PUBLIC KEY` PEM "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			publicKeyPathArg := "/tmp/example.pub"
			// NOTE: Valid public key content and PEM, but not `PUBLIC KEY` PEM.
			publicKeyContents := []byte(`-----BEGIN EXAMPLE KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHx5RWxAM67HKBYFcv1mvZcDCSN3
bCAAMnIa9hUCE/uUg7zSZCarsNNhtnFjEX8uxckFnIlgiDsaGWiF4HzWkNNwxeYD
av8ZKPx3mf060L6c0P8XSc+21F97ZdxKDlSp95Tl1rPcEBn30AB5Dqt2Cur9pPf6
00kSRujAYay9Kom/AgMBAAE=
-----END EXAMPLE KEY-----`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				publicKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPublicKeyFromPath(publicKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errDecodePublicKeyPem, actualErr)
		},
	)

	t.Run(
		"when contents of 'publicKeyPath' are actually private key contents, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			publicKeyPathArg := "/tmp/example.pub"
			publicKeyContents := []byte(`-----BEGIN PUBLIC KEY-----
MIIBPAIBAAJBAIPLh1pCCHNgGWQVg3BgisEXibkEfx/y/TFp17yF01YsG5G22Vmb
Dk3JfK5fSO0Lm3t8t2bAewkJUtCfSkETcQUCAwEAAQJANZhf25F81EZhLPUetWVd
J7bFt+qfM8PhuOV86NpXHfRMECSGRVVDdlhoBjoUW1kO4X1wD97GW5N56L3fMVNV
xQIhANwFm6UV1JtwC6MCTvMkRL9Xl+4YC1A1IX+LY2zeP1PfAiEAmViiMql3CnJt
ud8Rm2bhtxEXpwz/Pmt+avrZj68hd5sCIQC3c6WXPGCNShspy57wdGkt8WcoirvE
IMjRg/NeruC2mQIhAIwefTclumyFWtX4irIhNCZ/K8mtCp4SwxUl2h58vGv5AiEA
s/oC2WeIW+KwL2as5+Sw/KcoN3PqYxOLhMVaPiQAk2g=
-----END PUBLIC KEY-----`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				publicKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPublicKeyFromPath(publicKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), "unable to parse PKIX public key")
		},
	)

	t.Run(
		"when parsing PKI public key contents of 'publicKeyPath' returns a non-RSA key, "+
			" it returns an error",
		func(t *testing.T) {
			t.Parallel()

			publicKeyPathArg := "/tmp/example.pub"
			// NOTE: Valid PEM public key contents, but actually it's a DSA pub key.
			publicKeyContents := []byte(`-----BEGIN PUBLIC KEY-----
MIIBtjCCASsGByqGSM44BAEwggEeAoGBAMfDsznR087cLPHzNzEikcPiYm01T+NI
EbjFKUaeTYZT4PkVh12M1k8/czIViIUbS4eKcHonFwFXMqYjwAbkr6neKNN1aEDY
F90QnWxfH+BvA9oNGv0lgRhDE6x/DzlQ8KhspzZxYGZFW5BuXRFMzK9i5zqpkLCw
yMFQ4fJgqo3/AhUAtv0toxwUVNwWzLMzzgzArKsZVO8CgYBgugOcxddyUh5Y8NFC
VXJUdR4frmsTf6zuJbWzRGujnl6dtGFT2xN14+htgrb8ZiZ9bgSlSs6bCtGEB/so
fmRrgjQ4MMp59VZp9YHie8L4me1X7YJgwXbaqZ6id4z/oCQNHXakPA8m8Y8acXhA
wkq6dBjb8oHzjGnPTMB0TlqgogOBhAACgYA9whkbi4JFq1Z/K5EF6P057HgdVfD2
cz0bw2VgxOATuXSdrcgB4FRP88ydSJDROwa5nJpwMUetm/dx+NFpFZvvtQaxu2Bu
yLFYANLfKPhCO3BXaXKzJalArhQVHkyaIxc0g44OTSoOP/dzLIJwjsEMZ8QWjq6k
GSTih+PADTxTig==
-----END PUBLIC KEY-----`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				publicKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPublicKeyFromPath(publicKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errInvalidRsaPublicKey, actualErr)
		},
	)

	t.Run(
		"when parsing RSA public key contents of 'publicKeyPath' succeeds, "+
			"it returns a rsa public key",
		func(t *testing.T) {
			t.Parallel()

			publicKeyPathArg := "/tmp/example.pub"
			publicKeyContents := []byte(`-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHx5RWxAM67HKBYFcv1mvZcDCSN3
bCAAMnIa9hUCE/uUg7zSZCarsNNhtnFjEX8uxckFnIlgiDsaGWiF4HzWkNNwxeYD
av8ZKPx3mf060L6c0P8XSc+21F97ZdxKDlSp95Tl1rPcEBn30AB5Dqt2Cur9pPf6
00kSRujAYay9Kom/AgMBAAE=
-----END PUBLIC KEY-----`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				publicKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPublicKeyFromPath(publicKeyPathArg)
			require.Nil(t, actualErr)

			assert.IsType(t, actualReturn, &rsa.PublicKey{})
		},
	)
}

func TestService_ReadPrivateKeyFromPath(t *testing.T) {
	t.Run(
		"when reading 'privateKeyPath' fails, it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privateKeyPathArg := "/tmp/example.key"

			fakeError := errors.New("fakePrivateKeyReadError")

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				privateKeyPathArg,
			).Return(
				nil,
				fakeError,
			)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPrivateKeyFromPath(privateKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Contains(
				t,
				actualErr.Error(),
				"unable to read file contents of private key",
			)

			osExecutor.AssertExpectations(t)
		},
	)

	t.Run(
		"when reading 'privateKeyPath' fails due to contents not being PEM-formatted, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privateKeyPathArg := "/tmp/example.priv"
			// NOTE: Valid private key content, but not PEM-formatted.
			publicKeyContents := []byte(
				`MIIBOgIBAAJBAJQLU9xk5/WFv+QnJueh/Sofc7FGnErTP6IUqe9VKuXwfzYWgz2u
ZZGmq5QuePqiHY7DMBhLKIhH0hgnIPrAmUUCAwEAAQJAA3sktKj2v1IuyemVw5qO
fmAQ81kqsaO3+lKsEEGbaZ6trsY8hzIZPdT1QsDEAKMmnd2jAqwa2AKf4wXZU00G
fQIhAPJngOVPpb3Mov6Qs9Pwjfup2oQ6XgBZJ8TATgNCQrqLAiEAnFj7EdBb+liA
QT7yoNG8ireDr/f9L3l4x8uEAHUnBW8CIQDFzwC4H864m41G/v5ALUUv4OOYk6ix
0A9L10HSFvgtEQIgIT+m/O3TcZS6iaWKUXro3pMSNSzGsf7iGZMFGlfPmY8CIAtM
o55+P6HmCYiZX6ObBEr3PBMBCOKGki4uNllHBHSW`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				privateKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPrivateKeyFromPath(privateKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errDecodePrivateKeyPem, actualErr)
		},
	)

	t.Run(
		"when reading 'privateKeyPath' fails due to not being `RSA PRIVATE KEY` PEM "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privateKeyPathArg := "/tmp/example.priv"
			// NOTE: Valid private key content and PEM, but not `RSA PRIVATE KEY` PEM.
			publicKeyContents := []byte(`-----BEGIN EXAMPLE KEY-----
MIIBOgIBAAJBAJQLU9xk5/WFv+QnJueh/Sofc7FGnErTP6IUqe9VKuXwfzYWgz2u
ZZGmq5QuePqiHY7DMBhLKIhH0hgnIPrAmUUCAwEAAQJAA3sktKj2v1IuyemVw5qO
fmAQ81kqsaO3+lKsEEGbaZ6trsY8hzIZPdT1QsDEAKMmnd2jAqwa2AKf4wXZU00G
fQIhAPJngOVPpb3Mov6Qs9Pwjfup2oQ6XgBZJ8TATgNCQrqLAiEAnFj7EdBb+liA
QT7yoNG8ireDr/f9L3l4x8uEAHUnBW8CIQDFzwC4H864m41G/v5ALUUv4OOYk6ix
0A9L10HSFvgtEQIgIT+m/O3TcZS6iaWKUXro3pMSNSzGsf7iGZMFGlfPmY8CIAtM
o55+P6HmCYiZX6ObBEr3PBMBCOKGki4uNllHBHSW
-----END EXAMPLE KEY-----`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				privateKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPrivateKeyFromPath(privateKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Equal(t, errDecodePrivateKeyPem, actualErr)
		},
	)

	t.Run(
		"when contents of 'privateKeyPath' are actually public key contents, "+
			"it returns an error",
		func(t *testing.T) {
			t.Parallel()

			privateKeyPathArg := "/tmp/example.priv"
			publicKeyContents := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHx5RWxAM67HKBYFcv1mvZcDCSN3
bCAAMnIa9hUCE/uUg7zSZCarsNNhtnFjEX8uxckFnIlgiDsaGWiF4HzWkNNwxeYD
av8ZKPx3mf060L6c0P8XSc+21F97ZdxKDlSp95Tl1rPcEBn30AB5Dqt2Cur9pPf6
00kSRujAYay9Kom/AgMBAAE=
-----END RSA PRIVATE KEY-----`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				privateKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPrivateKeyFromPath(privateKeyPathArg)
			require.Nil(t, actualReturn)

			assert.Contains(t, actualErr.Error(), "unable to parse PKCS1 private key")
		},
	)

	t.Run(
		"when contents of 'privateKeyPath' are RSA private key contents, "+
			"it returns rsa private key",
		func(t *testing.T) {
			t.Parallel()

			privateKeyPathArg := "/tmp/example.priv"
			publicKeyContents := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAJQLU9xk5/WFv+QnJueh/Sofc7FGnErTP6IUqe9VKuXwfzYWgz2u
ZZGmq5QuePqiHY7DMBhLKIhH0hgnIPrAmUUCAwEAAQJAA3sktKj2v1IuyemVw5qO
fmAQ81kqsaO3+lKsEEGbaZ6trsY8hzIZPdT1QsDEAKMmnd2jAqwa2AKf4wXZU00G
fQIhAPJngOVPpb3Mov6Qs9Pwjfup2oQ6XgBZJ8TATgNCQrqLAiEAnFj7EdBb+liA
QT7yoNG8ireDr/f9L3l4x8uEAHUnBW8CIQDFzwC4H864m41G/v5ALUUv4OOYk6ix
0A9L10HSFvgtEQIgIT+m/O3TcZS6iaWKUXro3pMSNSzGsf7iGZMFGlfPmY8CIAtM
o55+P6HmCYiZX6ObBEr3PBMBCOKGki4uNllHBHSW
-----END RSA PRIVATE KEY-----`)

			osExecutor := ostest.NewFakeOsExecutor(t)
			osExecutor.On(
				"ReadFile",
				privateKeyPathArg,
			).Return(publicKeyContents, nil)

			svc := NewRsaService(osExecutor)
			actualReturn, actualErr := svc.ReadPrivateKeyFromPath(privateKeyPathArg)
			require.Nil(t, actualErr)

			assert.IsType(t, actualReturn, &rsa.PrivateKey{})
		},
	)
}

func TestService_EncryptPKCS1v15(t *testing.T) {
	t.Run(
		"it uses builtin `rsaEncryptPKCS1v15`",
		func(t *testing.T) {
			called := false
			var calledRand io.Reader
			var calledPub *rsa.PublicKey
			var calledMsg []byte

			calledReturnBytes := []byte{1, 2, 3}
			var calledReturnErr error

			realRsaEncryptPKCS1v15 := rsaEncryptPKCS1v15
			defer func() {
				rsaEncryptPKCS1v15 = realRsaEncryptPKCS1v15
			}()

			rsaEncryptPKCS1v15 = func(
				rand io.Reader,
				pub *rsa.PublicKey,
				msg []byte,
			) (bytes []byte, e error) {
				called = true
				calledRand = rand
				calledPub = pub
				calledMsg = msg

				return calledReturnBytes, calledReturnErr
			}

			randArg := bytes.NewReader(
				bytes.NewBufferString("1234").Bytes(),
			)
			pubArg := &rsa.PublicKey{}
			msgArg := bytes.NewBufferString("mymsg")

			svc := NewRsaService(&os.RealOsExecutor{})

			actualBytes, err := svc.EncryptPKCS1v15(randArg, pubArg, msgArg.Bytes())
			require.NoError(t, err)

			assert.True(t, called)
			assert.Equal(t, calledRand, randArg)
			assert.Equal(t, calledPub, pubArg)
			assert.Equal(t, calledMsg, msgArg.Bytes())
			assert.Equal(t, calledReturnBytes, actualBytes)
		},
	)
}

func TestService_DecryptPKCS1v15(t *testing.T) {
	t.Run(
		"it uses builtin `rsaDecryptPKCS1v15`",
		func(t *testing.T) {
			called := false
			var calledRand io.Reader
			var calledPriv *rsa.PrivateKey
			var calledCiphertext []byte

			calledReturnBytes := []byte{1, 2, 3}
			var calledReturnErr error

			realRsaDecryptPKCS1v15 := rsaDecryptPKCS1v15
			defer func() {
				rsaDecryptPKCS1v15 = realRsaDecryptPKCS1v15
			}()

			rsaDecryptPKCS1v15 = func(
				rand io.Reader,
				priv *rsa.PrivateKey,
				ciphertext []byte,
			) (bytes []byte, e error) {
				called = true
				calledRand = rand
				calledPriv = priv
				calledCiphertext = ciphertext

				return calledReturnBytes, calledReturnErr
			}

			randArg := bytes.NewReader(
				bytes.NewBufferString("1234").Bytes(),
			)
			privArg := &rsa.PrivateKey{}
			ciphertextArg := bytes.NewBufferString("mymsg")

			svc := NewRsaService(&os.RealOsExecutor{})

			actualBytes, err := svc.DecryptPKCS1v15(randArg, privArg, ciphertextArg.Bytes())
			require.NoError(t, err)

			assert.True(t, called)
			assert.Equal(t, calledRand, randArg)
			assert.Equal(t, calledPriv, privArg)
			assert.Equal(t, calledCiphertext, ciphertextArg.Bytes())
			assert.Equal(t, calledReturnBytes, actualBytes)
		},
	)
}

func TestService_EncryptOAEP(t *testing.T) {
	t.Run(
		"it uses builtin `rsaEncryptOAEP`",
		func(t *testing.T) {
			called := false
			var calledHash hash.Hash
			var calledRand io.Reader
			var calledPub *rsa.PublicKey
			var calledMsg []byte
			var calledLabel []byte

			calledReturnBytes := []byte{1, 2, 3}
			var calledReturnErr error

			realRsaEncryptOAEP := rsaEncryptOAEP
			defer func() {
				rsaEncryptOAEP = realRsaEncryptOAEP
			}()

			rsaEncryptOAEP = func(
				hash hash.Hash,
				rand io.Reader,
				pub *rsa.PublicKey,
				msg,
				label []byte,
			) (bytes []byte, e error) {
				called = true
				calledHash = hash
				calledRand = rand
				calledPub = pub
				calledMsg = msg
				calledLabel = label

				return calledReturnBytes, calledReturnErr
			}

			hashArg := sha256.New()
			randArg := bytes.NewReader(
				bytes.NewBufferString("1234").Bytes(),
			)
			pubArg := &rsa.PublicKey{}
			msgArg := bytes.NewBufferString("mymsg")
			labelArg := []byte("exampleLabel")

			svc := NewRsaService(&os.RealOsExecutor{})

			actualBytes, err := svc.EncryptOAEP(hashArg, randArg, pubArg, msgArg.Bytes(), labelArg)
			require.NoError(t, err)

			assert.True(t, called)
			assert.Equal(t, calledHash, hashArg)
			assert.Equal(t, calledRand, randArg)
			assert.Equal(t, calledPub, pubArg)
			assert.Equal(t, calledMsg, msgArg.Bytes())
			assert.Equal(t, calledLabel, labelArg)
			assert.Equal(t, calledReturnBytes, actualBytes)
		},
	)
}
