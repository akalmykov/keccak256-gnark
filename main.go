package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type Keccak256Circuit struct {
	In       [25]frontend.Variable
	Expected [25]frontend.Variable `gnark:",public"`
}

func (c *Keccak256Circuit) Define(api frontend.API) error {
	res := keccakf.Permute(api, c.In)
	for i := range res {
		api.AssertIsEqual(res[i], c.Expected[i])
	}
	return nil
}

func main() {
	// compiles our circuit into a R1CS
	var circuit Keccak256Circuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition
	var nativeIn [25]uint64
	for i := range nativeIn {
		nativeIn[i] = 0
	}
	nativeOut := keccakF1600(nativeIn)

	assignment := Keccak256Circuit{}

	for i := range nativeIn {
		assignment.In[i] = nativeIn[i]
		assignment.Expected[i] = nativeOut[i]
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
