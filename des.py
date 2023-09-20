#!/usr/bin/python3

from os import urandom

class KEYSTREAM:
	# Used Functions
	_sf = [
			lambda k, n: ((k<<1)%pow(2, n)) ^ (k>>(n-1)),
			lambda k, n: (k>>1) ^ ((k%2)<<(n-1))
	]
	_pr = lambda k, m: [k[m[i]] for i in range(len(m))]

	# Relevant Data
	_RDS = 16
	_SFT = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0]
	_PC1 = [
			56, 48, 40, 32, 24, 16,  8,
			0, 57, 49, 41, 33, 25, 17,
			9,  1, 58, 50, 42, 34, 26,
			18, 10,  2, 59, 51, 43, 35,
			62, 54, 46, 38, 30, 22, 14,
			6, 61, 53, 45, 37, 29, 21,
			13,  5, 60, 52, 44, 36, 28,
			20, 12,  4, 27, 19, 11,  3
	]
	_PC2 = [
			40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25
	]

	def __init__(self, key: bytes) -> None:
		assert isinstance(key, bytes)
		self.key: list[int] = self._kp(key)
	
	# Prepare Key for 16 rot shifts.
	def _kp(self, key: bytes) -> list[int]:
		key = ''.join(f'{i:08b}' for i in key)
		key = list(map(int, key))
		return KEYSTREAM._pr(key, KEYSTREAM._PC1)
	
	# Generate Keys
	def gen(self, rev: int) -> list[int]:
		t = len(self.key)//2
		x = (rev*2)-1
		op = lambda : KEYSTREAM._sf[rev](self.key[:t], t) + KEYSTREAM._sf[rev](self.key[t:], t)
		for i in range(KEYSTREAM._RDS):
			if KEYSTREAM._SFT[i*x]:
				self.key = op()
			self.key = op()
			yield KEYSTREAM._pr(self.key, KEYSTREAM._PC2)

def main():
	out = KEYSTREAM(urandom(8)).gen(0)
	print(next(out))

if __name__ == '__main__':
	main()