package main

import (
	"testing"
)

func createByteArray(size int, fill byte) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = fill
	}
	return b
}

func TestPreimage(t *testing.T) {
	//assert := test.NewAssert(t)
	//
	//var circuit Keccak256Circuit

	//assert.ProverFailed(&circuit, &Keccak256Circuit{
	//	Hash:     42,
	//	PreImage: 42,
	//})

	//assert.ProverSucceeded(&circuit, &Keccak256Circuit{
	//	PreImage: createByteArray(20, 80),
	//	Hash:     [4]frontend.Variable{6369296867788652241, 6989174940168908071, 9770456023708964694, 16734836981162548877},
	//}, test.WithCurves(ecc.BN254))

}
