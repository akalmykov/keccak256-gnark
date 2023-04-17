package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type NaiveKeccak256Circuit struct {
	In [17]frontend.Variable // 17*64=1088 bit
}

func (c *NaiveKeccak256Circuit) Define(api frontend.API) error {
	var state [25]frontend.Variable // 25*64=1600 bit
	// State should be moved here
	for i := range state {
		state[i] = 0
		api.AssertIsEqual(state[i], 0)
	}
	for i := range c.In {
		api.AssertIsEqual(c.In[i], 0)
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
