package main

import (
	"encoding/binary"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/permutation/keccakf"
	"unsafe"
)

const inputSizeInBytes = 100 // 136 * 2
const inputSizeInUint64 = (inputSizeInBytes + 8 - 1) / 8

// PLAN:
// Develop a circuit pad(input []frontend.Variable, byteLength int) that:
//		- takes the last (len(input)%17) and stores the rest somewhere
//		- use ToBinary to decompose this^ into bits
// 		- pad the bitstring with 10*1 starting from 8*byteLength
//		- group the result into blocks of 64 (use FromBinary?)
//		- return []frontend.Variable where each frontend.Variable is a uint64
// Pass this (and the first 17*n Variables) to the circuit we've already written.

type NaiveKeccak256Circuit struct {
	PreImage []frontend.Variable // unit64 array
	// PreImageSizeInBytes frontend.Variable
	Expected [4]frontend.Variable // (256 bits)/(64 bits/uint64) = 4 uint64s
}

func (c *NaiveKeccak256Circuit) Define(api frontend.API) error {
	uapi := newUint64API(api)

	//var in []frontend.Variable
	//for i := 0; i < (inputSize / 8); i += 1 {
	//	in = append(in, api.FromBinary(api.ToBinary(c.PreImage[i*8:i+8], 64), 64))
	//
	//}
	// paddedInput := make([]frontend.Variable, inputSizeInUint64)

	var state [25]frontend.Variable // 25*64=1600 bit
	for i := range state {
		state[i] = 0
		api.AssertIsEqual(state[i], 0)
	}

	paddedPreImage := make([]frontend.Variable, inputSizeInUint64)
	for i := 0; i < inputSizeInUint64; i++ {
		paddedPreImage[i] = c.PreImage[i]
		api.AssertIsEqual(paddedPreImage[i], c.PreImage[i])
	}

	// 1. Do I need to pad to make input a multiple of 17 uints64?
	//paddingStartIndex := inputSizeInUint64 - 1
	if inputSizeInUint64%17 > 0 {
		for i := 0; i < 17-(inputSizeInUint64%17)-1; i++ { // 17 - 13%17 = 14-
			paddedPreImage = append(paddedPreImage, uint64(0))
			api.AssertIsEqual(paddedPreImage[inputSizeInUint64+i], 1)
		}
		paddedPreImage = append(paddedPreImage, uint64(9223372036854775808))
		api.AssertIsEqual(paddedPreImage[len(paddedPreImage)-1], uint64(9223372036854775808))

		if inputSizeInBytes%8 == 0 {
			paddedPreImage[inputSizeInUint64-1] = uint64(1)
		}
	}

	// 1. Do I need to pad with 1 inside the last uint64?
	emptyBytesInLastUint64 := inputSizeInBytes % 8
	if emptyBytesInLastUint64 > 0 {
		lastUint64Binary := api.ToBinary(paddedPreImage[inputSizeInUint64-1], 64)
		lastUint64Binary[64-(emptyBytesInLastUint64)*8] = 1
		// 1.1 Do I need to pad with 128 inside the last uint64?
		if inputSizeInUint64%17 == 0 {
			lastUint64Binary[64-7] = 1
		}
		paddedPreImage[inputSizeInUint64-1] = api.FromBinary(lastUint64Binary...)
	}
	for i := 0; i < len(paddedPreImage); i++ {
		api.Println(fmt.Sprintf("[%d]: ", i), paddedPreImage[i])
	}

	//  0 1 2 3 4 5 6 7
	// [a,b,c,d,e,0,0,0]
	// [a,b,c,d,e,1,0,0]

	// 1. Do I need to pad outside the last uint64? I.e. adding more unit64s to fill PreImage up to multiple 17
	//if len(paddedPreImage)%17 > 0 {
	//	paddingSize := inputSizeInUint64 - inputSizeInUint64%17
	//	for i := inputSizeInUint64; i < paddedPreImageSize; i++ {
	//
	//	}
	//}
	//for i := 0; i < inputSizeInUint64; i++ {
	//	paddedPreImage[i] = c.PreImage[i]
	//}

	for i := 0; i < inputSizeInUint64; i += 17 {
		for j := 0; j < 17; j++ {
			state[j] = uapi.fromUint64(uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(paddedPreImage[i+j])))
		}
		// S = Keccak-f[r+c](S)
		state = keccakf.Permute(api, state)
	}

	//var buf [17]frontend.Variable
	//buf[0] = 1
	//api.AssertIsEqual(buf[0], 1)
	//for j := 1; j < 16; j++ {
	//	buf[j] = 0
	//	api.AssertIsEqual(buf[j], 0)
	//}
	//buf[16] = uint64(9223372036854775808) // [0,0,0,0,0,0,128] in little endian
	//api.AssertIsEqual(buf[16], uint64(9223372036854775808))
	//for j := 0; j < 17; j++ {
	//	state[j] = uapi.fromUint64(uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(buf[j])))
	//}
	//state = keccakf.Permute(api, state)

	var Z [4]frontend.Variable
	for j := 0; j < 4; j++ {
		Z[j] = state[j]
	}

	for j := 0; j < 4; j++ {
		api.AssertIsEqual(Z[j], c.Expected[j])
	}
	return nil
}

func main() {
	n := inputSizeInBytes
	byteInput := make([]byte, n)
	for i := range byteInput {
		byteInput[i] = 0
	}
	uint64Input := (*[inputSizeInBytes / 8]uint64)(unsafe.Pointer(&byteInput[0]))[: n/8 : n/8]
	remainder := make([]byte, n%8)
	if len(remainder) > 0 {
		copy(remainder, byteInput[:n%8])
		last64Uint := append(remainder, make([]byte, 8-n%8)...)
		uint64Input = append(uint64Input, binary.LittleEndian.Uint64(last64Uint))
	}

	// data := binary.BigEndian.Uint64(mySlice)
	circuit := NaiveKeccak256Circuit{PreImage: make([]frontend.Variable, inputSizeInUint64)}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition

	assignment := NaiveKeccak256Circuit{
		PreImage: make([]frontend.Variable, inputSizeInUint64),
	}

	// 1. Arbitrary length but divisible into 136 byte blocks (17*64 units)
	// 2. Arbitrary length but divisible into 64 uints (padding needed)
	// 3. Arbitrary length in bytes
	// assignment.PreImageSizeInBytes = inputSizeInBytes
	for i := range assignment.PreImage {
		assignment.PreImage[i] = uint64Input[i]
	}
	//for i := range assignment.In {

	// convert it to []uint64 ?? => is this ok?
	// assignment.In = make([]frontend.Variable, 17)

	//assignment.Expected[0] = uint64(14102500177593761960)
	//assignment.Expected[1] = uint64(1751238265316416354)
	//assignment.Expected[2] = uint64(10191991164706561650)
	//assignment.Expected[3] = uint64(9074021743222020896)

	//uint64  0: 15692495994270334865
	//uint64  1: 6307481890028256528
	//uint64  2: 12466496089941296042
	//uint64  3: 12076360432795841956

	assignment.Expected[0] = uint64(15692495994270334865)
	assignment.Expected[1] = uint64(6307481890028256528)
	assignment.Expected[2] = uint64(12466496089941296042)
	assignment.Expected[3] = uint64(12076360432795841956)

	//var uint64{58, 89, 18, 167, 197, 250, 160, 110, 228, 254, 144, 98, 83, 227, 57, 70, 122, 156, 232, 125, 83, 60, 101, 190, 60, 21, 203, 35, 28, 219, 37, 249}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
