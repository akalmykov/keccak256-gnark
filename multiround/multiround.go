package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

// PLAN:
// Develop a circuit pad(input []frontend.Variable, byteLength int) that:
//		- takes the last (len(input)%17) and stores the rest somewhere
//		- use ToBinary to decompose this^ into bits
// 		- pad the bitstring with 10*1 starting from 8*byteLength
//		- group the result into blocks of 64 (use FromBinary?)
//		- return []frontend.Variable where each frontend.Variable is a uint64
// Pass this (and the first 17*n Variables) to the circuit we've already written.

const inputSize = 17 * 5

type NaiveKeccak256Circuit struct {
	In         [inputSize]frontend.Variable // (1088 bits)/(64 bits/uint64) = 17 uint64s
	ByteLength int
	Expected   [4]frontend.Variable // (256 bits)/(64 bits/uint64) = 4 uint64s
}

func (c *NaiveKeccak256Circuit) Define(api frontend.API) error {
	uapi := newUint64API(api)

	// x := api.ToBinary(frontend.Variable(9), 1)
	// api.Println(x)
	// y := api.ToBinary(frontend.Variable(9), 4)[0]
	// api.Println(y)
	// z := api.ToBinary(frontend.Variable(9), 500)[0]
	// api.Println(z)

	var state [25]frontend.Variable // 25*64=1600 bit
	for i := range state {
		state[i] = 0
		api.AssertIsEqual(state[i], 0)
	}

	for i := 0; i < inputSize; i += 17 {
		for j := 0; j < 17; j++ {
			state[j] = uapi.fromUint64(uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(c.In[i+j])))
		}
		// S = Keccak-f[r+c](S)
		state = keccakf.Permute(api, state)
	}

	var buf [17]frontend.Variable
	buf[0] = 1
	api.AssertIsEqual(buf[0], 1)
	for j := 1; j < 16; j++ {
		buf[j] = 0
		api.AssertIsEqual(buf[j], 0)
	}
	buf[16] = uint64(9223372036854775808) // [0,0,0,0,0,0,128] in little endian
	api.AssertIsEqual(buf[16], uint64(9223372036854775808))
	for j := 0; j < 17; j++ {
		state[j] = uapi.fromUint64(uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(buf[j])))
	}
	state = keccakf.Permute(api, state)

	var Z [4]frontend.Variable
	for j := 0; j < 4; j++ {
		Z[j] = state[j]
		api.Println("Z[j]", Z[j])
	}

	for j := 0; j < 4; j++ {
		api.AssertIsEqual(Z[j], c.Expected[j])
	}
	return nil
}

func PadUint64s101AfterByte(api frontend.API, input []frontend.Variable, byteLength int) []frontend.Variable {
	// Assumes the input is a list of uint64s.
	var bytesLeft int = (136 - (byteLength % 136)) % 8
	var uint64sLeft int = (136 - (byteLength % 136)) / 8

	var bitPad []frontend.Variable

	var firstByte [8]frontend.Variable
	firstByte[0] = frontend.Variable(1)
	for i := 1; i < 8; i++ {
		firstByte[i] = frontend.Variable(0)
	}

	var middleByte [8]frontend.Variable
	for i := 0; i < 8; i++ {
		middleByte[i] = 0
	}

	var lastByte [8]frontend.Variable
	for i := 0; i < 7; i++ {
		lastByte[i] = 0
	}
	lastByte[7] = 1

	var firstAndLastByte [8]frontend.Variable
	firstAndLastByte[0] = 1
	for i := 0; i < 7; i++ {
		firstAndLastByte[i] = 0
	}
	firstAndLastByte[7] = 1

	if bytesLeft == 1 && uint64sLeft == 0 {
		bitPad = firstAndLastByte[:]
	} else if bytesLeft == 2 && uint64sLeft == 0 {
		bitPad = append(firstByte[:], lastByte[:])
	} else if bytesLeft == 3 && uint64sLeft == 0 {
		bitPad = append(append(firstByte[:], middleByte[:]), lastByte[:])
	} else if bytesLeft == 1 && uint64sLeft != 0 {
		bitPad = firstByte[:]
	} else if bytesLeft == 2 && uint64sLeft != 0 {
		bitPad = append(firstByte[:], middleByte[:])
	} else if bytesLeft == 3 && uint64sLeft != 0 {
		bitPad = append(append(firstByte[:], middleByte[:]), middleByte[:])
	} else {

	}

	var uint64Pad []frontend.Variable
	var firstUint64 frontend.Variable = frontend.Variable(9223372036854775808)
	var middleUint64 frontend.Variable = frontend.Variable(0)
	var lastUint64 frontend.Variable = frontend.Variable(1)
	var firstAndLastUint64 frontend.Variable = frontend.Variable(9223372036854775809)

	if bytesLeft == 0 && uint64sLeft == 1 {
		uint64Pad.append(firstAndLastUint64)
	} else if bytesLeft == 0 && uint64sLeft >= 2 {
		uint64Pad.append(firstUint64)
		for i := 0; i < uint64sLeft-2; i++ {
			uint64Pad.append(middleUint64)
		}
		uint64Pad.append(lastUint64)
	} else if bytesLeft != 0 && uint64sLeft != 0 {
		for i := 0; i < uint64sLeft-1; i++ {
			uint64Pad.append(middleUint64)
		}
		uint64Pad.append(lastUint64)
	} else {

	}

	if bytesLeft != 0 {
		var incompleteUint64 frontend.Variable = input[byteLength/8]
		var incompleteBits []frontend.Variable = api.ToBinary(incompleteUint64)
		var completeBits []frontend.Variable = append(incompleteBits[:], bitPad[:])
		var completeUint64 frontend.Variable = api.FromBinary(completeBits)
		// TODO: take off the last (incomplete) uint64 of input, then
		// put completeUint64 at the end.
	}

	if uint64sLeft != 0 {
		var output []frontend.Variable = append(input[:], uint64Pad[:])
	}

	return output

}

func main() {
	// compiles our circuit into a R1CS
	var circuit NaiveKeccak256Circuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition

	assignment := NaiveKeccak256Circuit{}

	// 1. Arbitrary length but divisible into 136 byte blocks (17*64 units)
	// 2. Arbitrary length but divisible into 64 uints (padding needed)
	// 3. Arbitrary length in bytes

	//for i := range assignment.State {
	//	assignment.State[i] = 0
	//}
	for i := range assignment.In {
		assignment.In[i] = 0
	}
	assignment.Expected[0] = uint64(2700785146922948057)
	assignment.Expected[1] = uint64(16877546023442210549)
	assignment.Expected[2] = uint64(17561289794945050041)
	assignment.Expected[3] = uint64(15480597146993018223)
	//var uint64{58, 89, 18, 167, 197, 250, 160, 110, 228, 254, 144, 98, 83, 227, 57, 70, 122, 156, 232, 125, 83, 60, 101, 190, 60, 21, 203, 35, 28, 219, 37, 249}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
