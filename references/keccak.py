from Crypto.Hash import keccak


if __name__ == "__main__":
    k = keccak.new(digest_bits=256)
    # k.update(b'hello world')
    k.update(bytearray([88 for i in range(20)]))
    hexdigest = k.hexdigest()
    print(hexdigest)
    print("--- hex (8 bytes groups):")
    group_by_bytes = 8
    hex_chars = group_by_bytes*2
    for i in range(len(hexdigest)//hex_chars):
        start_i = hex_chars*i
        print(f"uint64 {i}: {hexdigest[start_i:start_i+(hex_chars)]}")
    print("--- decimals (big endian):")  # 00000000000000013   0x00000000000000013
    digest = k.digest()
    for i in range(len(digest)//group_by_bytes):
        start_i = group_by_bytes*i
        print(f"uint64 {i}: {int.from_bytes(digest[start_i:start_i+(group_by_bytes)], byteorder='big')}")
    print("--- decimals (little endian):")  # 3100000000000000000   0x13000000000000000
    for i in range(len(digest)//group_by_bytes):
        start_i = group_by_bytes*i
        print(f"uint64  {i}: {int.from_bytes(digest[start_i:start_i+(group_by_bytes)], byteorder='little')}")

    print(f"0x80 big: {int.from_bytes([0,0,0,0,0,0,0,0x80], byteorder='big')}")
    print(f"0x80 little: {int.from_bytes([0,0,0,0,0,0,0,0x80], byteorder='little')}") # 9223372036854775808
    print(f"8 1s big: {int.from_bytes([1,1,1,1,1,1,1,1], byteorder='big')}")
    print(f"8 1s little: {int.from_bytes([1,1,1,1,1,1,1,1], byteorder='little')}") # 9223372036854775808
    print(f"4 1s little: {int.from_bytes([1,1,1,1], byteorder='little')}") # 9223372036854775808
    print(f"1: {int.from_bytes([128,0,0,0,0,0,0,0], byteorder='little')}") # 9223372036854775808
    print(f"2: {int.from_bytes([0,128,0,0,0,0,0,0], byteorder='little')}") # 9223372036854775808
    print(f"3: {int.from_bytes([0,0,128,0,0,0,0,0], byteorder='little')}") # 9223372036854775808
    print(f"4: {int.from_bytes([0,0,0,128,0,0,0,0], byteorder='little')}") # 9223372036854775808
    print(f"5: {int.from_bytes([0,0,0,0,128,0,0,0], byteorder='little')}") # 9223372036854775808
    print(f"6: {int.from_bytes([0,0,0,0,0,128,0,0], byteorder='little')}") # 9223372036854775808
    print(f"7: {int.from_bytes([0,0,0,0,0,0,128,0], byteorder='little')}") # 9223372036854775808
    print(f"8: {int.from_bytes([0,0,0,0,0,0,0,128], byteorder='little')}") # 9223372036854775808
    # 0x8000000000000000 = 9223372036854775808
    # [17376452488221285863 9571781953733019530 15391093639620504046 13624874521033984333 10027350355371872343 18417369716475457492 10448040663659726788 10113917136857017974 12479658147685402012 3500241080921619556 16959053435453822517 12224711289652453635 9342009439668884831 4879704952849025062 140226327413610143 424854978622500449 7259519967065370866 7004910057750291985 13293599522548616907 10105770293752443592 10668034807192757780 1747952066141424100 1654286879329379778 8500057116360352059 16929593379567477321]


# 08:47:41 DBG no_padding.go:54 > Z[j] 17376452488221285863
# 08:47:41 DBG no_padding.go:54 > Z[j] 9571781953733019530
# 08:47:41 DBG no_padding.go:54 > Z[j] 15391093639620504046
# 08:47:41 DBG no_padding.go:54 > Z[j] 13624874521033984333


# 17:00:55 DBG no_padding.go:87 > Z[j] 7971647067264276794
# 17:00:55 DBG no_padding.go:87 > Z[j] 5060325603602923236
# 17:00:55 DBG no_padding.go:87 > Z[j] 13719438169146432634
# 17:00:55 DBG no_padding.go:87 > Z[j] 17952996403488429372
# 0 = {uint64} 7971647067264276794
# 1 = {uint64} 5060325603602923236
# 2 = {uint64} 13719438169146432634
# 3 = {uint64} 17952996403488429372

# 136*2 of zeros
# uint64  0: 14102500177593761960
# uint64  1: 1751238265316416354
# uint64  2: 10191991164706561650
# uint64  3: 9074021743222020896
