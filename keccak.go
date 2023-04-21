package main

import (
	"encoding/binary"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type Keccak256Circuit struct {
	PreImage []frontend.Variable  // byte array
	Hash     [4]frontend.Variable `gnark:",public"`
}

func padWith0x1(api frontend.API, i1 frontend.Variable, pos int) frontend.Variable {
	lastUint64Binary := api.ToBinary(i1, 64)
	lastUint64Binary[(pos)*8] = 1
	return api.FromBinary(lastUint64Binary...)
}

func (c *Keccak256Circuit) Define(api frontend.API) error {
	uapi := newUint64API(api)
	inputSizeInBytes := len(c.PreImage)
	inputSizeInUint64 := (inputSizeInBytes + 8 - 1) / 8

	var state [25]frontend.Variable
	for i := range state {
		state[i] = 0
	}

	paddedPreImageLength := inputSizeInUint64 + 17 - (inputSizeInUint64 % 17)
	paddedPreImage := make([]frontend.Variable, paddedPreImageLength)
	for i := 0; i < inputSizeInUint64; i++ {
		binUint64 := make([]frontend.Variable, 0)
		for j := 0; j < 8; j++ {
			if i*8+j < inputSizeInBytes {
				binUint64 = append(binUint64, api.ToBinary(c.PreImage[i*8+j], 8)...)
			} else {
				binUint64 = append(binUint64, api.ToBinary(0, 8)...)
			}
		}
		paddedPreImage[i] = api.FromBinary(binUint64...)
	}
	for i := inputSizeInUint64; i < paddedPreImageLength; i++ {
		paddedPreImage[i] = 0
	}

	lastUint64ByteCount := inputSizeInBytes % 8
	if lastUint64ByteCount > 0 {
		paddedPreImage[inputSizeInUint64-1] = padWith0x1(api, paddedPreImage[inputSizeInUint64-1], lastUint64ByteCount)
	} else {
		paddedPreImage[inputSizeInUint64] = padWith0x1(api, paddedPreImage[inputSizeInUint64], lastUint64ByteCount)
	}

	toPad := api.ToBinary(paddedPreImage[paddedPreImageLength-1], 64)
	toPad[63] = 1
	paddedPreImage[paddedPreImageLength-1] = api.FromBinary(toPad...)

	for i := 0; i < len(paddedPreImage); i += 17 {
		for j := 0; j < 17; j++ {
			state[j] = uapi.fromUint64(uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(paddedPreImage[i+j])))
		}
		state = keccakf.Permute(api, state)
	}

	var Z [4]frontend.Variable
	for j := 0; j < 4; j++ {
		Z[j] = state[j]
	}

	for j := 0; j < 4; j++ {
		api.AssertIsEqual(Z[j], c.Hash[j])
	}
	return nil
}

func packBytesInUint64s(bytes []byte) []uint64 {
	n := len(bytes)
	uint64Input := make([]uint64, n/8)
	for i := 0; i < n/8; i += 1 {
		uint64Input[i] = binary.LittleEndian.Uint64(bytes[i*8 : (i+1)*8])
	}
	remainder := make([]byte, n%8)
	if len(remainder) > 0 {
		copy(remainder, bytes[:n%8])
		last64Uint := append(remainder, make([]byte, 8-n%8)...)
		uint64Input = append(uint64Input, binary.LittleEndian.Uint64(last64Uint))
	}
	return uint64Input
}

func main() {
	n := 128
	byteInput := make([]byte, n)
	for i := range byteInput {
		byteInput[i] = 0xff
	}

	circuit := Keccak256Circuit{PreImage: make([]frontend.Variable, n)}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition
	assignment := Keccak256Circuit{
		PreImage: make([]frontend.Variable, n),
	}

	for i := range assignment.PreImage {
		assignment.PreImage[i] = byteInput[i]
	}

	assignment.Hash[0] = uint64(7034071582072284571)
	assignment.Hash[1] = uint64(9476740265178284515)
	assignment.Hash[2] = uint64(13709023776379649456)
	assignment.Hash[3] = uint64(1129769768123533517)

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
