package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type NaiveKeccak256Circuit struct {
	In       [17]frontend.Variable // (1088 bits)/(64 bits/uint64) = 17 uint64s
	Expected [4]frontend.Variable  // (256 bits)/(64 bits/uint64) = 4 uint64s
}

func (c *NaiveKeccak256Circuit) Define(api frontend.API) error {
	uapi := newUint64API(api)

	// Initialization
	// S[x, y] = 0 for all x, y in 0..4
	var state [25]frontend.Variable // 25*64=1600 bit
	for i := range state {
		state[i] = 0
		api.AssertIsEqual(state[i], 0)
	}

	// Absorbing phase

	// For each block Pi in P
	// Not doing this now because we specifically chose P to be one block long

	// S[x, y] = S[x, y] xor Pi[x+5y] for all x, y such that x+5y < r/w
	// Here the rate r = 1088 and the width w = 64, so r/w = 17
	// Suppose our flattening is S[x, y] = state[x+5*y]
	// Then we want state[j] = state[j] xor Pi[j] (j = x+5y) for j = 0..16
	for j := 0; j < 17; j++ {
		state[j] = uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(c.In[j]))
	}

	// S = Keccak-f[r+c](S)
	state = keccakf.Permute(api, state)

	// Squeezing phase

	// Z = empty string
	// while output is requested
	// Z = Z || S[x, y] for x, y such that x+5y < r/w
	// What order is this done in? Lexicographical, with x first?
	// So Z[j] = state[j] for j in 0..16
	// Only need 4 of these, so Z[j] = state[j] for j in 0..3?
	var Z [4]frontend.Variable
	for j := 0; j < 4; j++ {
		Z[j] = state[j]
	}

	for j := 0; j < 4; j++ {
		api.AssertIsEqual(Z[j], c.Expected[j])
	}
	//for i := 0; i < 25; i++ {
	//	c.State[i] = 0
	//	api.AssertIsEqual(c.State[i], 0)
	//}
	//for i := 0; i < 17; i++ {
	//	c.In[i] = 0
	//	api.AssertIsEqual(c.In[i], 0)
	//}
	// res := keccakf.Per
	//mute(api, c.In)
	return nil
}

func main() {
	// compiles our circuit into a R1CS
	var circuit NaiveKeccak256Circuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition

	assignment := NaiveKeccak256Circuit{}

	//for i := range assignment.State {
	//	assignment.State[i] = 0
	//}
	for i := range assignment.In {
		assignment.In[i] = 0
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
