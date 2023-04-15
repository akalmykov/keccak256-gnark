from Crypto.Hash import keccak


if __name__ == "__main__":
    k = keccak.new(digest_bits=256)
    k.update(b'hello world')
    print(k.hexdigest())
