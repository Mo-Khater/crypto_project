class LCG:
    def __init__(self, seed, a=16807, c=0, m=2**31 - 1):
        self.a = a
        self.c = c
        self.m = m
        self.state = seed % self.m  # ensure state is within modulus

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def get_keystream(self, length):
        return [self.next() % 256 for _ in range(length)]  # 1-byte output

if __name__ == "__main__":
    seed = 123456789
    lcg = LCG(seed)
    keystream = lcg.get_keystream(10)
    print("Generated keystream:", keystream)
