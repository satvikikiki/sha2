class SHA2:
    def __init__(self, algorithm="sha256"):
        self.algorithm = algorithm
        self.init_vars()

    def init_vars(self):
        
        if self.algorithm == "sha256":
            self.H = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ]
            self.K = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
            ]

    def right_rotate(self, value, shift):
        return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF

    def preprocess(self, message):
        message = bytearray(message, "utf-8")
        bit_len = len(message) * 8
        message.append(0x80)
        while len(message) % 64 != 56:
            message.append(0)
        bit_len_bytes = [(bit_len >> (8 * i)) & 0xFF for i in range(7, -1, -1)]
        message.extend(bit_len_bytes)
        return message

    def chunk_message(self, message):
        for i in range(0, len(message), 64):
            yield message[i:i + 64]

    def schedule_words(self, chunk):
        w = [int.from_bytes(chunk[i:i + 4], "big") for i in range(0, 64, 4)] + [0] * 48
        for i in range(16, 64):
            s0 = self.right_rotate(w[i - 15], 7) ^ self.right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self.right_rotate(w[i - 2], 17) ^ self.right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
        return w

    def compress(self, chunk):
        w = self.schedule_words(chunk)
        a, b, c, d, e, f, g, h = self.H

        for i in range(64):
            s1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + self.K[i] + w[i]) & 0xFFFFFFFF
            s0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        self.H = [(x + y) & 0xFFFFFFFF for x, y in zip(self.H, [a, b, c, d, e, f, g, h])]

    def hash(self, message):
        message = self.preprocess(message)
        for chunk in self.chunk_message(message):
            self.compress(chunk)
        return "".join(f"{x:08x}" for x in self.H)


# Example Usage
sha2 = SHA2()
result = sha2.hash("kikiki" )
print(f"SHA-256: {result}")
