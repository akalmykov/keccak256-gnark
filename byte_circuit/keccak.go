package main

import (
	"encoding/binary"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

// const inputSizeInBytes = 20 // 136 * 2

// PLAN:
// Develop a circuit pad(input []frontend.Variable, byteLength int) that:
//		- takes the last (len(input)%17) and stores the rest somewhere
//		- use ToBinary to decompose this^ into bits
// 		- pad the bitstring with 10*1 starting from 8*byteLength
//		- group the result into blocks of 64 (use FromBinary?)
//		- return []frontend.Variable where each frontend.Variable is a uint64
// Pass this (and the first 17*n Variables) to the circuit we've already written.

type Keccak256Circuit struct {
	PreImage []frontend.Variable  // unit64 array
	Hash     [4]frontend.Variable `gnark:",public"`
}

func remainder(api frontend.API, i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	return api.Sub(i1, api.Mul(api.Div(i1, i2), i2))
}

func padWith0x1(api frontend.API, i1 frontend.Variable, pos frontend.Variable) frontend.Variable {
	toPad := api.ToBinary(i1, 64)
	for i := 0; i < 64; i++ {
		toPad[i] = api.Select(api.Cmp(i, api.Mul(pos, 8)), 1, toPad[i])
	}
	return api.FromBinary(toPad...)
}

func padWith0x80(api frontend.API, i1 frontend.Variable) frontend.Variable {
	toPad := api.ToBinary(i1, 64)
	toPad[64-7] = 1
	return api.FromBinary(toPad...)
}

func (c *Keccak256Circuit) Define(api frontend.API) error {
	uapi := newUint64API(api)
	inputSizeInBytes := len(c.PreImage) // (inputSizeInBytes + 8 - 1) / 8
	inputSizeInUint64 := (inputSizeInBytes + 8 - 1) / 8
	//	api.AssertIsLessOrEqual(c.PreImageByteLength, api.Mul(inputSizeInUint64, 8))

	//	api.Println("inputSizeInUint64=", inputSizeInUint64)
	var state [25]frontend.Variable // 25*64=1600 bit
	for i := range state {
		state[i] = 0
		// api.AssertIsEqual(state[i], 0)
	}

	//fillerBytesInLastUint64 := remainder(api, inputSizeInBytes, 8)
	//indexToPadWith1Selector := api.Cmp(fillerBytesInLastUint64, 0)
	//lastElementIndex := api.Sub(inputSizeInUint64, 1)
	//firstAddedElementIndex := inputSizeInUint64
	//indexToPadWith1 := api.Add(api.Mul(lastElementIndex, indexToPadWith1Selector), api.Mul(firstAddedElementIndex, api.Sub(1, indexToPadWith1Selector)))
	//
	//paddedLength := inputSizeInUint64 + 17 - (inputSizeInUint64 % 17)
	//paddedPreImage := make([]frontend.Variable, paddedLength)
	//for i := 0; i < inputSizeInUint64; i++ {
	//	paddedPreImage[i] = c.PreImage[i]
	//	api.AssertIsEqual(paddedPreImage[i], c.PreImage[i])
	//}
	//paddedPreImage[inputSizeInUint64-1] = api.Select(
	//	api.Cmp(indexToPadWith1, inputSizeInUint64-1),
	//	paddedPreImage[inputSizeInUint64-1],
	//	padWith0x1(api, paddedPreImage[inputSizeInUint64-1], fillerBytesInLastUint64))
	//for i := inputSizeInUint64; i < paddedLength; i++ {
	//	paddedPreImage[i] = 0
	//	api.AssertIsEqual(paddedPreImage[i], 0)
	//}
	//
	//paddedPreImage[inputSizeInUint64] = api.Select(
	//	api.Cmp(inputSizeInUint64, indexToPadWith1),
	//	padWith0x1(api, paddedPreImage[inputSizeInUint64], 0),
	//	paddedPreImage[inputSizeInUint64])
	//
	//if inputSizeInUint64%17 > 0 {
	//	paddedPreImage[paddedLength-1] = padWith0x80(api, paddedPreImage[paddedLength-1])
	//	api.AssertIsEqual(paddedPreImage[paddedLength-1], uint64(9223372036854775808))
	//} else {
	//	paddedPreImage[inputSizeInUint64-1] = padWith0x80(api, paddedPreImage[inputSizeInUint64-1])
	//}

	// 1. Do I need to pad to make input a multiple of 17 uints64?
	//paddingStartIndex := inputSizeInUint64 - 1

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

	emptyBytesInLastUint64 := inputSizeInBytes % 8
	if emptyBytesInLastUint64 > 0 {
		lastUint64Binary := api.ToBinary(paddedPreImage[inputSizeInUint64-1], 64)
		lastUint64Binary[(emptyBytesInLastUint64)*8] = 1
		paddedPreImage[inputSizeInUint64-1] = api.FromBinary(lastUint64Binary...)
	} else {
		lastUint64Binary := api.ToBinary(paddedPreImage[inputSizeInUint64], 64)
		lastUint64Binary[(emptyBytesInLastUint64)*8] = 1
		paddedPreImage[inputSizeInUint64] = api.FromBinary(lastUint64Binary...)
	}

	toPad := api.ToBinary(paddedPreImage[paddedPreImageLength-1], 64)
	toPad[63] = 1
	paddedPreImage[paddedPreImageLength-1] = api.FromBinary(toPad...)

	//for i := 0; i < inputSizeInUint64; i++ {
	//	paddedPreImage[i] = c.PreImage[i]
	//	api.AssertIsEqual(paddedPreImage[i], c.PreImage[i])
	//}

	//if inputSizeInUint64%17 > 0 {
	//	//paddingUint := api.Sub(1, api.Cmp(remainder(api, inputSizeInBytes, 8), 0))
	//	for i := 0; i < 17-(inputSizeInUint64%17)-1; i++ {
	//		paddedPreImage = append(paddedPreImage, uint64(0))
	//		api.AssertIsEqual(paddedPreImage[inputSizeInUint64+i], 0)
	//	}
	//	paddedPreImage = append(paddedPreImage, uint64(9223372036854775808))
	//	api.AssertIsEqual(paddedPreImage[len(paddedPreImage)-1], uint64(9223372036854775808))
	//
	//	if inputSizeInBytes%8 == 0 {
	//		paddedPreImage[inputSizeInUint64] = uint(1) // TODO fix, for 120/128 bytes, overrite when 1 uint64 is added
	//		//api.Sub(1, api.Cmp(api.Sub(inputSizeInBytes, api.Div(inputSizeInBytes, 8)), 0))
	//		// paddedPreImage[inputSizeInUint64] = api.Sub(1, api.Cmp(remainder(api, inputSizeInBytes, 8), 0))
	//	}
	//}

	//// 1. Do I need to pad with 1 inside the last uint64?
	//emptyBytesInLastUint64 := inputSizeInBytes % 8
	//if emptyBytesInLastUint64 > 0 {
	//	lastUint64Binary := api.ToBinary(paddedPreImage[inputSizeInUint64-1], 64)
	//	// lastUint64Binary[64-(emptyBytesInLastUint64)*8] = 1
	//	lastUint64Binary[(emptyBytesInLastUint64)*8] = 1 //150
	//	// 1.1 Do I need to pad with 128 inside the last uint64?
	//	// api.Println(lastUint64Binary...)
	//	if inputSizeInUint64%17 == 0 {
	//		lastUint64Binary[64-7] = 1
	//	}
	//	paddedPreImage[inputSizeInUint64-1] = api.FromBinary(lastUint64Binary...)
	//}
	//
	//// if no padding needed, we add an 10*128 padding for 17 uints
	//if inputSizeInBytes%136 == 0 {
	//	paddedPreImage = append(paddedPreImage, uint64(1))
	//	api.AssertIsEqual(paddedPreImage[inputSizeInUint64], 1)
	//	for j := 1; j < 16; j++ {
	//		paddedPreImage = append(paddedPreImage, uint64(0))
	//		api.AssertIsEqual(paddedPreImage[inputSizeInUint64+j], 0)
	//	}
	//	paddedPreImage = append(paddedPreImage, uint64(9223372036854775808))
	//	api.AssertIsEqual(paddedPreImage[inputSizeInUint64+17-1], uint64(9223372036854775808))
	//}

	//for i := range paddedPreImage {
	//	api.Println(fmt.Sprintf("[%d]: ", i), paddedPreImage[i])
	//}
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
		byteInput[i] = 88
	}
	//test := packBytesInUint64s(byteInput)
	//test[0] = 0
	//fvInput := packBytesInFrontendVars(byteInput)
	//inputSizeInUint64 := (20 + 8 - 1) / 8
	//uint64Input := (*[inputSizeInBytes / 8]uint64)(unsafe.Pointer(&byteInput[0]))[: n/8 : n/8]
	//remainder := make([]byte, n%8)
	//if len(remainder) > 0 {
	//	copy(remainder, byteInput[:n%8])
	//	last64Uint := append(remainder, make([]byte, 8-n%8)...)
	//	uint64Input = append(uint64Input, binary.LittleEndian.Uint64(last64Uint))
	//}

	// data := binary.BigEndian.Uint64(mySlice)
	circuit := Keccak256Circuit{PreImage: make([]frontend.Variable, n)}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition

	assignment := Keccak256Circuit{
		PreImage: make([]frontend.Variable, n),
	}

	// 1. Arbitrary length but divisible into 136 byte blocks (17*64 units)
	// 2. Arbitrary length but divisible into 64 uints (padding needed)
	// 3. Arbitrary length in bytes
	// assignment.PreImageSizeInBytes = inputSizeInBytes
	for i := range assignment.PreImage {
		assignment.PreImage[i] = byteInput[i]
	}
	//for i := range assignment.In {

	// convert it to []uint64 ?? => is this ok?
	// assignment.In = make([]frontend.Variable, 17)

	//assignment.Hash[0] = uint64(14102500177593761960)
	//assignment.Hash[1] = uint64(1751238265316416354)
	//assignment.Hash[2] = uint64(10191991164706561650)
	//assignment.Hash[3] = uint64(9074021743222020896)

	//uint64  0: 15692495994270334865
	//uint64  1: 6307481890028256528
	//uint64  2: 12466496089941296042
	//uint64  3: 12076360432795841956

	//assignment.Hash[0] = uint64(15692495994270334865)
	//assignment.Hash[1] = uint64(6307481890028256528)
	//assignment.Hash[2] = uint64(12466496089941296042)
	//assignment.Hash[3] = uint64(12076360432795841956)
	assignment.Hash[0] = uint64(8133000113850975698)
	assignment.Hash[1] = uint64(14975830184694368523)
	assignment.Hash[2] = uint64(8330139369825885006)
	assignment.Hash[3] = uint64(5716127063702906175)

	//var uint64{58, 89, 18, 167, 197, 250, 160, 110, 228, 254, 144, 98, 83, 227, 57, 70, 122, 156, 232, 125, 83, 60, 101, 190, 60, 21, 203, 35, 28, 219, 37, 249}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
