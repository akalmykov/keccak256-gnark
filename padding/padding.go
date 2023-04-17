package main

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"unsafe"
)

// PaddingCircuit
// https://crypto.stackexchange.com/questions/62633/simplifying-the-description-of-the-keccak-padding-rules
type PaddingCircuit struct {
	In  []frontend.Variable
	Out [17]frontend.Variable `gnark:",public"` // 17*64 = 1088 = block size
}

/*
 * Find the Most-Significant Non-Zero Bit (MSNZB) of `in`, where `in` is assumed to be non-zero value of `b` bits.
 * Outputs the MSNZB as a one-hot vector `one_hot` of `b` bits, where `one_hot`[i] = 1 if MSNZB(`in`) = i and 0 otherwise.
 * The MSNZB is output as a one-hot vector to reduce the number of constraints in the subsequent `Normalize` template.
 * Enforces that `in` is non-zero as MSNZB(0) is undefined.
 * If `skip_checks` = 1, then we don't care about the output and the non-zero constraint is not enforced.
 */
//template MSNZB(b) {
//signal input in;
//signal input skip_checks;
//signal output one_hot[b];
//
//component z = IsZero();
//z.in <== skip_checks+in;
//z.out === 0;
//
//component num2Bits = Num2Bits(b);
//num2Bits.in <== in;
//
//signal temp[b];
//temp[b-1] <== 1;
//
//for (var i = b - 1; i >= 0; i --) {
//one_hot[i] <== temp[i] * num2Bits.bits[i];
//if (i > 0) {
//temp[i - 1] <== (1 - one_hot[i]) * temp[i];
//}
//}
//}

//func Pad(api frontend.API, inputBytes []frontend.Variable) [17]frontend.Variable {
//	blockSize := 1088
//
//	return nil
//}

//output = 256 bits
//bus: 1600 bit
//24 rounds
//[block size] r=1088 ⇒ we pad this
//[capacity] c=522

//memset(self->buf + self->valid_bytes, 0, self->rate - self->valid_bytes);
//self->buf[self->valid_bytes] = padding;
//self->buf[self->rate-1] |= 0x80;

//template Pad(nBits) {
//signal input in[nBits];
//
//var blockSize=136*8;
//signal output out[blockSize];
//signal out2[blockSize];
//
//var i;
//
//for (i=0; i<nBits; i++) {
//out2[i] <== in[i];
//}
//var domain = 0x01;
//for (i=0; i<8; i++) {
//out2[nBits+i] <== (domain >> i) & 1;
//}
//for (i=nBits+8; i<blockSize; i++) {
//out2[i] <== 0;
//}
//component aux = OrArray(8);
//for (i=0; i<8; i++) {
//aux.a[i] <== out2[blockSize-8+i];
//aux.b[i] <== (0x80 >> i) & 1;
//}
//for (i=0; i<8; i++) {
//out[blockSize-8+i] <== aux.out[i];
//}
//for (i=0; i<blockSize-8; i++) {
//out[i]<==out2[i];
//}
//}

func packBytesInUint64s(input []byte) []uint64 {
	n := len(input)
	return (*[1088 / 8]uint64)(unsafe.Pointer(&input[0]))[: n/8 : n/8]
}

func main() {
	input := []byte{1, 2, 3, 4, 5}
	fmt.Println(packBytesInUint64s(input))
}
