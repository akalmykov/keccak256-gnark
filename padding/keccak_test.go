package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func createByteArray(size int, fill byte) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = fill
	}
	return b
}

func TestPreimageGROTH16Only(t *testing.T) {
	assert := test.NewAssert(t)

	//assert.ProverFailed(&circuit, &Keccak256Circuit{
	//	Hash:     42,
	//	PreImage: 42,
	//})

	bytes := createByteArray(20, 88)
	Keccak256(bytes)
	assert.ProverSucceeded(&Keccak256Circuit{PreImage: make([]frontend.Variable, 3)}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			uint64(6369296867788652241),
			uint64(6989174940168908071),
			uint64(9770456023708964694),
			uint64(16734836981162548877),
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())

}
