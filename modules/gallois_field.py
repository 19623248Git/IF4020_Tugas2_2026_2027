# the class for GF(2^8)
class gallois_field_8:
    def __init__(self, poly):
        self.poly = poly
        pass

    def mult(self, a: int, b: int) -> int :
        """
        the formula is like long binary multiplication, but we get the remainder from XOR with poly
        aᵢ = (a << i) if bit i of b is 1, otherwise ai = 0 where i = 0..7
        result = (a0 ^ a1 ^ a2 ^ ... ^ a7) "mod" poly
        the "mod" is modulus without carry from substraction, in this case just XOR to get rid of bits that surpass a byte
        somehow has the same property as a normal modulus...
        result = (a0 "mod" poly) ^ (a1 "mod" poly) ^ ... (a7 "mod" poly)
        """

        # get only the 8 bits of a and b, just in case
        a_masked = a & 0xFF
        b_masked = b & 0xFF
        res = 0

        while b_masked:
            if b_masked & 1:
                res ^= a_masked
            b_masked >>= 1
            a_masked <<= 1
            if a_masked & 0x100:
                a_masked ^= self.poly
        return res

    def add(self, a: int, b: int) -> int:
        # we can just mask after the XOR operation
        return (a ^ b) & 0xFF

    def mult_table_gen(self) -> list[list[int]]:
        # since its only limited to 2^8, a lookup table should be faster at the cost of memory efficiency
        BITS_IN_BYTE = 256
        table = [[0] * BITS_IN_BYTE for _ in range (BITS_IN_BYTE)]
        for a in range(BITS_IN_BYTE):
            for b in range(BITS_IN_BYTE):
                table[a][b] = self.mult(a,b)
        return table