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
		state[j] = uapi.fromUint64(uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(c.In[j])))
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

	//d.a[0] ^= bw[0]
	//d.a[1] ^= bw[1]
	//d.a[2] ^= bw[2]
	//d.a[3] ^= bw[3]
	//d.a[4] ^= bw[4]
	//d.a[5] ^= bw[5]
	//d.a[6] ^= bw[6]
	//d.a[7] ^= bw[7]
	//d.a[8] ^= bw[8]
	//d.a[9] ^= bw[9]
	//d.a[10] ^= bw[10]
	//d.a[11] ^= bw[11]
	//d.a[12] ^= bw[12]
	//d.a[13] ^= bw[13]
	//d.a[14] ^= bw[14]
	//d.a[15] ^= bw[15]
	//d.a[16] ^= bw[16]

	var Z [4]frontend.Variable
	for j := 0; j < 4; j++ {
		Z[j] = state[j]
		api.Println("Z[j]", Z[j])
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
	assignment.Expected[0] = uint64(7971647067264276794)
	assignment.Expected[1] = uint64(5060325603602923236)
	assignment.Expected[2] = uint64(13719438169146432634)
	assignment.Expected[3] = uint64(17952996403488429372)
	//var uint64{58, 89, 18, 167, 197, 250, 160, 110, 228, 254, 144, 98, 83, 227, 57, 70, 122, 156, 232, 125, 83, 60, 101, 190, 60, 21, 203, 35, 28, 219, 37, 249}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
