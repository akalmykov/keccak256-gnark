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
func packBytesInFrontendVars(bytes []byte) []frontend.Variable {
	fvs := make([]frontend.Variable, len(bytes))
	for i := range fvs {
		fvs[i] = bytes[i]
	}
	return fvs
}

func Test20BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 20
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

func TestAllBackends(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 20
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254))
}

func TestFail(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 20
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	hash[0] += 1
	assert.ProverFailed(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

func Test32BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 32
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

func Test120BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 120
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

func Test128BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 128
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

func Test136BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 136
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

func Test196BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 196
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

func Test256BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 256
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
		Hash: [4]frontend.Variable{
			hash[0],
			hash[1],
			hash[2],
			hash[3],
		},
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerialization())
}

func Test272BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 136 * 2
	bytes := createByteArray(preImageByteLength, 88)
	hash := packBytesInUint64s(Keccak256(bytes))
	assert.ProverSucceeded(&Keccak256Circuit{
		PreImage: make([]frontend.Variable, len(bytes)),
	}, &Keccak256Circuit{
		PreImage: packBytesInFrontendVars(bytes),
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
