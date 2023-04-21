package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

const inputSize = 17 * 2

type NaiveKeccak256Circuit struct {
	In       []frontend.Variable  // (1088 bits)/(64 bits/uint64) = 17 uint64s
	Expected [4]frontend.Variable // (256 bits)/(64 bits/uint64) = 4 uint64s
}

func (c *NaiveKeccak256Circuit) Define(api frontend.API) error {
	uapi := newUint64API(api)

	var state [25]frontend.Variable // 25*64=1600 bit
	for i := range state {
		state[i] = 0
		api.AssertIsEqual(state[i], 0)
	}

	for i := 0; i < inputSize; i += 17 {
		for j := 0; j < 17; j++ {
			state[j] = uapi.fromUint64(uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(c.In[i+j])))
		}
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

func main() {
	// compiles our circuit into a R1CS
	circuit := NaiveKeccak256Circuit{In: make([]frontend.Variable, inputSize)}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition

	assignment := NaiveKeccak256Circuit{In: make([]frontend.Variable, inputSize)}

	// 1. Arbitrary length but divisible into 136 byte blocks (17*64 units)
	// 2. Arbitrary length but divisible into 64 uints (padding needed)
	// 3. Arbitrary length in bytes

	//for i := range assignment.State {
	//	assignment.State[i] = 0
	//}
	for i := range assignment.In {
		assignment.In[i] = 0
	}
	assignment.Expected[0] = uint64(14102500177593761960)
	assignment.Expected[1] = uint64(1751238265316416354)
	assignment.Expected[2] = uint64(10191991164706561650)
	assignment.Expected[3] = uint64(9074021743222020896)
	//var uint64{58, 89, 18, 167, 197, 250, 160, 110, 228, 254, 144, 98, 83, 227, 57, 70, 122, 156, 232, 125, 83, 60, 101, 190, 60, 21, 203, 35, 28, 219, 37, 249}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
