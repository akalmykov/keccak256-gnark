# keccak256-gnark

keccak256-gnark is a circuit for the Keccak256 hash function, written in GNARK.

## GNARK 

GNARK is a library for building circuits/constraint systems for use in succinct noninteractive arguments of knowledge (SNARKs), written in golang.  (TODO: link to GNARK).  We chose to write our Keccak256 circuit in GNARK since there is already an implementation in circom (link), and GNARK has a fast backend.

## Keccak256

Keccak256 is a hash function that takes as input a bitstring of any length, and outputs a string of 256 bits.  More generally, the Keccak algorithm can output a bitstring of any length, which is why "256" is added as a suffix to this version of Keccak, which truncates the output at 256 bits.  A full specification of the Keccak algorithm, written in pseudocode by the Keccak Team, can be found [here](https://keccak.team/keccak_specs_summary).

Essentially, Keccak is made of two components: a permutation and a sponge construction.  The permutations used in the various versions of Keccak are called the Keccak-f family of permutations.  These, as well as the sponge construction, depend on parameters called the bitrate *r* and capacity *c*.  In order to make our circuit compatible with Ethereum, we modeled our circuit on the Go Ethereum Keccak256 program (TODO: insert link).  This uses the Keccak-f[1600] permutation, with a rate of 1088 and capacity of 512.

Fortunately, (TODO: attribute) had written a GNARK circuit to perform the Keccak-f[1600] permutation.  This takes in an array of 25 frontend.Variables, considered as uint64s, and returns an array of 25 frontend.Variables.  While the Keccak-f[1600] permutation can be defined at the level of bits, in fact the bits are grouped into a 5x5 grid of lanes, which are 64 bits long each (5x5x64 = 1600): thus the use of 64-bit integers.  What remained for us was to build a circuit for the sponge construction, using the Keccak-f[1600] permutation circuit.

The sponge construction consists of three phases:
1. Padding
2. Absorbing
3. Squeezing

### Padding

In the original Keccak specification, any number of bits can be used as input.  In Ethereum, the input is actually an array of bytes.  
