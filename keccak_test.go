package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	main2 "keccak/geth_keccak_reference"
	"testing"
)

func createByteArray(size int, fill byte) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = fill
	}
	return b
}

func Test20BytesPreimageGROTH16Only(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 136
	bytes := createByteArray(preImageByteLength, 88)
	fvs := packBytesInFrontendVars(bytes)
	hash := packBytesInUint64s(main2.Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage:           make([]frontend.Variable, len(fvs)),
		PreImageByteLength: preImageByteLength,
	}, &Keccak256Circuit{
		PreImage: fvs,
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

//func Test500BytesPreimageGROTH16Only(t *testing.T) {
//	assert := test.NewAssert(t)
//	bytes := createByteArray(500, 255)
//	hash := packBytesInUint64s(Keccak256(bytes))
//	assert.ProverSucceeded(&Keccak256Circuit{PreImage: make([]frontend.Variable, 3)}, &Keccak256Circuit{
//		PreImage: packBytesInFrontendVars(bytes),
//		Hash: [4]frontend.Variable{
//			hash[0], //uint64(6369296867788652241),
//			hash[1],
//			hash[2],
//			hash[3],
//		},
//	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
//}
