class LCG:
    def __init__(self, seed, a=1664525, c=1013904223, m=2**32):
        self.a = a
        self.c = c
        self.m = m
        self.state = seed

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def get_keystream(self, length):
        return [self.next() % 256 for _ in range(length)]  # mod 256 for 1-byte stream

if __name__ == "__main__":
    seed = 123456789
    lcg = LCG(seed)
    keystream = lcg.get_keystream(10)
    print("Generated keystream:", keystream)
