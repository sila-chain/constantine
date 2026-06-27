/** Constantine
 *  Copyright (c) 2018-2019    Status Research & Development GmbH
 *  Copyright (c) 2020-Present Mamy André-Ratsimbazafy
 *  Licensed and distributed under either of
 *    * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
 *    * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
 *  at your option. This file may not be copied, modified, or distributed except according to those terms.
 */

package constantine

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Threadpool smoke test
// ----------------------------------------------------------

func TestThreadpool(t *testing.T) {
	tp := ThreadpoolNew(runtime.NumCPU())
	tp.Shutdown()
}

// Sila SIP-4844 KZG tests
// ----------------------------------------------------------
//
// Source: https://github.com/ethereum/c-kzg-4844

var (
	trustedSetupFile             = "../constantine/commitments_setups/trusted_setup_sila_kzg4844_reference.dat"
	testDir                      = "../tests/protocol_sila_sip4844_deneb_kzg"
	blobToKZGCommitmentTests     = filepath.Join(testDir, "blob_to_kzg_commitment/*/*/*")
	computeKZGProofTests         = filepath.Join(testDir, "compute_kzg_proof/*/*/*")
	computeBlobKZGProofTests     = filepath.Join(testDir, "compute_blob_kzg_proof/*/*/*")
	verifyKZGProofTests          = filepath.Join(testDir, "verify_kzg_proof/*/*/*")
	verifyBlobKZGProofTests      = filepath.Join(testDir, "verify_blob_kzg_proof/*/*/*")
	verifyBlobKZGProofBatchTests = filepath.Join(testDir, "verify_blob_kzg_proof_batch/*/*/*")
)

func fromHexImpl(dst []byte, input []byte) error {
	s := string(input)
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(bytes) != len(dst) {
		return errors.New(
			"Length of input doesn't match expected length.",
		)
	}
	copy(dst, bytes)
	return nil
}

func (dst *SilaKzgCommitment) UnmarshalText(input []byte) error {
	return fromHexImpl(dst[:], input)
}
func (dst *SilaKzgProof) UnmarshalText(input []byte) error {
	return fromHexImpl(dst[:], input)
}
func (dst *SilaBlob) UnmarshalText(input []byte) error {
	return fromHexImpl(dst[:], input)
}
func (dst *SilaKzgChallenge) UnmarshalText(input []byte) error {
	return fromHexImpl(dst[:], input)
}
func (dst *SilaKzgEvalAtChallenge) UnmarshalText(input []byte) error {
	return fromHexImpl(dst[:], input)
}

func TestBlobToKzgCommitment(t *testing.T) {
	fmt.Println("Running test for path: ", blobToKZGCommitmentTests)
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
		}
		Output *SilaKzgCommitment `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tests, err := filepath.Glob(blobToKZGCommitmentTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var blob SilaBlob
			err = blob.UnmarshalText([]byte(test.Input.Blob))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			commitment, err := ctx.BlobToKzgCommitment(blob)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, test.Output[:], commitment[:])
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestComputeKzgProof(t *testing.T) {
	fmt.Println("Running test for path: ", computeKZGProofTests)
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
			Z    string `yaml:"z"`
		}
		Output *[]string `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tests, err := filepath.Glob(computeKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var blob SilaBlob
			err = blob.UnmarshalText([]byte(test.Input.Blob))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var z SilaKzgChallenge
			err = z.UnmarshalText([]byte(test.Input.Z))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			proof, y, err := ctx.ComputeKzgProof(blob, z)
			if err == nil {
				require.NotNil(t, test.Output)
				var expectedProof SilaKzgProof
				err = expectedProof.UnmarshalText([]byte((*test.Output)[0]))
				require.NoError(t, err)
				require.Equal(t, expectedProof[:], proof[:])
				var expectedY SilaKzgEvalAtChallenge
				err = expectedY.UnmarshalText([]byte((*test.Output)[1]))
				require.NoError(t, err)
				require.Equal(t, expectedY[:], y[:])
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestVerifyKzgProof(t *testing.T) {
	fmt.Println("Running test for path: ", verifyKZGProofTests)
	type Test struct {
		Input struct {
			Commitment string `yaml:"commitment"`
			Z          string `yaml:"z"`
			Y          string `yaml:"y"`
			Proof      string `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tests, err := filepath.Glob(verifyKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var commitment SilaKzgCommitment
			err = commitment.UnmarshalText([]byte(test.Input.Commitment))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var z SilaKzgChallenge
			err = z.UnmarshalText([]byte(test.Input.Z))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var y SilaKzgEvalAtChallenge
			err = y.UnmarshalText([]byte(test.Input.Y))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var proof SilaKzgProof
			err = proof.UnmarshalText([]byte(test.Input.Proof))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			valid, err := ctx.VerifyKzgProof(commitment, z, y, proof)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, valid)
			} else {
				if test.Output != nil {
					require.Equal(t, *test.Output, valid)
				}
			}
		})
	}
}

func TestComputeBlobKzgProof(t *testing.T) {
	fmt.Println("Running test for path: ", computeBlobKZGProofTests)
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			Commitment string `yaml:"commitment"`
		}
		Output *SilaKzgProof `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tests, err := filepath.Glob(computeBlobKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var blob SilaBlob
			err = blob.UnmarshalText([]byte(test.Input.Blob))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var commitment SilaKzgCommitment
			err = commitment.UnmarshalText([]byte(test.Input.Commitment))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			proof, err := ctx.ComputeBlobKzgProof(blob, commitment)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, test.Output[:], proof[:])
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestVerifyBlobKzgProof(t *testing.T) {
	fmt.Println("Running test for path: ", verifyBlobKZGProofTests)
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			Commitment string `yaml:"commitment"`
			Proof      string `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tests, err := filepath.Glob(verifyBlobKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var blob SilaBlob
			err = blob.UnmarshalText([]byte(test.Input.Blob))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var commitment SilaKzgCommitment
			err = commitment.UnmarshalText([]byte(test.Input.Commitment))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var proof SilaKzgProof
			err = proof.UnmarshalText([]byte(test.Input.Proof))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			valid, err := ctx.VerifyBlobKzgProof(blob, commitment, proof)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, valid)
			} else {
				if test.Output != nil {
					require.Equal(t, *test.Output, valid)
				}
			}
		})
	}
}

func TestVerifyBlobKzgProofBatch(t *testing.T) {
	fmt.Println("Running test for path: ", verifyBlobKZGProofBatchTests)
	type Test struct {
		Input struct {
			Blobs       []string `yaml:"blobs"`
			Commitments []string `yaml:"commitments"`
			Proofs      []string `yaml:"proofs"`
		}
		Output *bool `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	var secureRandomBytes [32]byte
	_, _ = rand.Read(secureRandomBytes[:])

	tests, err := filepath.Glob(verifyBlobKZGProofBatchTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var blobs []SilaBlob
			for _, b := range test.Input.Blobs {
				var blob SilaBlob
				err = blob.UnmarshalText([]byte(b))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				blobs = append(blobs, blob)
			}

			var commitments []SilaKzgCommitment
			for _, c := range test.Input.Commitments {
				var commitment SilaKzgCommitment
				err = commitment.UnmarshalText([]byte(c))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				commitments = append(commitments, commitment)
			}

			var proofs []SilaKzgProof
			for _, p := range test.Input.Proofs {
				var proof SilaKzgProof
				err = proof.UnmarshalText([]byte(p))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				proofs = append(proofs, proof)
			}

			valid, err := ctx.VerifyBlobKzgProofBatch(blobs, commitments, proofs, secureRandomBytes)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, valid)
			} else {
				if test.Output != nil {
					require.Equal(t, *test.Output, valid)
				}
			}
		})
	}
}

// Sila SIP-4844 KZG tests - Parallel
// ----------------------------------------------------------

func createTestThreadpool(t *testing.T) Threadpool {
	// Ensure all C function are called from the same OS thread
	// to avoid messing up the threadpool Thread-Local-Storage.
	// Be sure to not use t.Run are subtests are run on separate goroutine as well
	runtime.LockOSThread()
	tp := ThreadpoolNew(runtime.NumCPU())

	// Register a cleanup function
	t.Cleanup(func() {
		tp.Shutdown()
		runtime.UnlockOSThread()
	})

	return tp
}

func TestBlobToKzgCommitmentParallel(t *testing.T) {
	fmt.Println("Running test for path: ", blobToKZGCommitmentTests)
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
		}
		Output *SilaKzgCommitment `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tp := createTestThreadpool(t)
	ctx.SetThreadpool(tp)

	tests, err := filepath.Glob(blobToKZGCommitmentTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		// Don't use t.Run() with parallel C code to not mess up thread-local storage
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		var blob SilaBlob
		err = blob.UnmarshalText([]byte(test.Input.Blob))
		if err != nil {
			require.Nil(t, test.Output)
			continue
		}

		commitment, err := ctx.BlobToKzgCommitmentParallel(blob)
		if err == nil {
			require.NotNil(t, test.Output)
			require.Equal(t, test.Output[:], commitment[:])
		} else {
			require.Nil(t, test.Output)
		}
	}
}

func TestComputeKzgProofParallel(t *testing.T) {
	fmt.Println("Running test for path: ", computeKZGProofTests)
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
			Z    string `yaml:"z"`
		}
		Output *[]string `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tp := createTestThreadpool(t)
	ctx.SetThreadpool(tp)

	tests, err := filepath.Glob(computeKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		// Don't use t.Run() with parallel C code to not mess up thread-local storage
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		var blob SilaBlob
		err = blob.UnmarshalText([]byte(test.Input.Blob))
		if err != nil {
			require.Nil(t, test.Output)
			continue
		}

		var z SilaKzgChallenge
		err = z.UnmarshalText([]byte(test.Input.Z))
		if err != nil {
			require.Nil(t, test.Output)
			continue
		}

		proof, y, err := ctx.ComputeKzgProofParallel(blob, z)
		if err == nil {
			require.NotNil(t, test.Output)
			var expectedProof SilaKzgProof
			err = expectedProof.UnmarshalText([]byte((*test.Output)[0]))
			require.NoError(t, err)
			require.Equal(t, expectedProof[:], proof[:])
			var expectedY SilaKzgEvalAtChallenge
			err = expectedY.UnmarshalText([]byte((*test.Output)[1]))
			require.NoError(t, err)
			require.Equal(t, expectedY[:], y[:])
		} else {
			require.Nil(t, test.Output)
		}
	}
}

func TestComputeBlobKzgProofParallel(t *testing.T) {
	fmt.Println("Running test for path: ", computeBlobKZGProofTests)
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			Commitment string `yaml:"commitment"`
		}
		Output *SilaKzgProof `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tp := createTestThreadpool(t)
	ctx.SetThreadpool(tp)

	tests, err := filepath.Glob(computeBlobKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		// Don't use t.Run() with parallel C code to not mess up thread-local storage
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		var blob SilaBlob
		err = blob.UnmarshalText([]byte(test.Input.Blob))
		if err != nil {
			require.Nil(t, test.Output)
			continue
		}

		var commitment SilaKzgCommitment
		err = commitment.UnmarshalText([]byte(test.Input.Commitment))
		if err != nil {
			require.Nil(t, test.Output)
			continue
		}

		proof, err := ctx.ComputeBlobKzgProofParallel(blob, commitment)
		if err == nil {
			require.NotNil(t, test.Output)
			require.Equal(t, test.Output[:], proof[:])
		} else {
			require.Nil(t, test.Output)
		}
	}
}

func TestVerifyBlobKzgProofParallel(t *testing.T) {
	fmt.Println("Running test for path: ", verifyBlobKZGProofTests)
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			Commitment string `yaml:"commitment"`
			Proof      string `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tp := createTestThreadpool(t)
	ctx.SetThreadpool(tp)

	tests, err := filepath.Glob(verifyBlobKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		// Don't use t.Run() with parallel C code to not mess up thread-local storage
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		var blob SilaBlob
		err = blob.UnmarshalText([]byte(test.Input.Blob))
		if err != nil {
			require.Nil(t, test.Output)
			continue
		}

		var commitment SilaKzgCommitment
		err = commitment.UnmarshalText([]byte(test.Input.Commitment))
		if err != nil {
			require.Nil(t, test.Output)
			continue
		}

		var proof SilaKzgProof
		err = proof.UnmarshalText([]byte(test.Input.Proof))
		if err != nil {
			require.Nil(t, test.Output)
			continue
		}

		valid, err := ctx.VerifyBlobKzgProofParallel(blob, commitment, proof)
		if err == nil {
			require.NotNil(t, test.Output)
			require.Equal(t, *test.Output, valid)
		} else {
			if test.Output != nil {
				require.Equal(t, *test.Output, valid)
			}
		}
	}
}

func TestVerifyBlobKzgProofBatchParallel(t *testing.T) {
	fmt.Println("Running test for path: ", verifyBlobKZGProofBatchTests)
	type Test struct {
		Input struct {
			Blobs       []string `yaml:"blobs"`
			Commitments []string `yaml:"commitments"`
			Proofs      []string `yaml:"proofs"`
		}
		Output *bool `yaml:"output"`
	}

	ctx, tsErr := SilaKzgContextNew(trustedSetupFile)
	require.NoError(t, tsErr)
	defer ctx.Delete()

	tp := createTestThreadpool(t)
	ctx.SetThreadpool(tp)

	var secureRandomBytes [32]byte
	_, _ = rand.Read(secureRandomBytes[:])

	tests, err := filepath.Glob(verifyBlobKZGProofBatchTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		// Don't use t.Run() with parallel C code to not mess up thread-local storage
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		var blobs []SilaBlob
		for _, b := range test.Input.Blobs {
			var blob SilaBlob
			err = blob.UnmarshalText([]byte(b))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}
			blobs = append(blobs, blob)
		}

		var commitments []SilaKzgCommitment
		for _, c := range test.Input.Commitments {
			var commitment SilaKzgCommitment
			err = commitment.UnmarshalText([]byte(c))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}
			commitments = append(commitments, commitment)
		}

		var proofs []SilaKzgProof
		for _, p := range test.Input.Proofs {
			var proof SilaKzgProof
			err = proof.UnmarshalText([]byte(p))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}
			proofs = append(proofs, proof)
		}

		valid, err := ctx.VerifyBlobKzgProofBatchParallel(blobs, commitments, proofs, secureRandomBytes)
		if err == nil {
			require.NotNil(t, test.Output)
			require.Equal(t, *test.Output, valid)
		} else {
			if test.Output != nil {
				require.Equal(t, *test.Output, valid)
			}
		}
	}
}
