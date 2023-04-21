package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

//func TestAllBackends(t *testing.T) {
//	assert := test.NewAssert(t)
//	preImageByteLength := 20
//	bytes := createByteArray(preImageByteLength, 88)
//	hash := packBytesInUint64s(Keccak256(bytes))
//	assert.ProverSucceeded(&Keccak256Circuit{
//		PreImage: make([]frontend.Variable, len(bytes)),
//	}, &Keccak256Circuit{
//		PreImage: packBytesInFrontendVars(bytes),
//		Hash: [4]frontend.Variable{
//			hash[0],
//			hash[1],
//			hash[2],
//			hash[3],
//		},
//	}, test.WithCurves(ecc.BN254))
//}

func TestEmptyPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	bytes := make([]byte, 0)
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

func Test1BytePreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 1
	bytes := createByteArray(preImageByteLength, 0xff)
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

func Test8BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 8
	bytes := createByteArray(preImageByteLength, 0xff)
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

func Test64BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 8
	bytes := createByteArray(preImageByteLength, 0xff)
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

func Test32BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 32
	bytes := createByteArray(preImageByteLength, 16)
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
	bytes := createByteArray(preImageByteLength, 0)
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
	bytes := createByteArray(preImageByteLength, 0xff)
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
	bytes := createByteArray(preImageByteLength, 55)
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
	bytes := createByteArray(preImageByteLength, 44)
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
	bytes := createByteArray(preImageByteLength, 33)
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
	bytes := createByteArray(preImageByteLength, 11)
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

func Test500BytesPreimage(t *testing.T) {
	assert := test.NewAssert(t)
	preImageByteLength := 500
	bytes := createByteArray(preImageByteLength, 0xff)
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
