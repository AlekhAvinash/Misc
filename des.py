#!/usr/bin/python3

from os import urandom
from Crypto.Cipher import DES
from Crypto.Util.number import long_to_bytes as lb, bytes_to_long as bl

class KEYSTREAM:
	# Used Functions
	_sf = [
			lambda a: [a[-1]]+a[:-1],
			lambda a: a[1:]+[a[0]]
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
			13, 16, 10, 23,  0,  4,
			 2, 27, 14,  5, 20,  9,
			22, 18, 11,  3, 25,  7,
			15,  6, 26, 19, 12,  1,
			40, 51, 30, 36, 46, 54,
			29, 39, 50, 44, 32, 47,
			43, 48, 38, 55, 33, 52,
			45, 41, 49, 35, 28, 31
	]

	def __init__(self, key: bytes) -> None:
		assert isinstance(key, bytes)
		self.key: list[int] = self._kp(key)
	
	# Prepare Key for 16 rot shifts.
	def _kp(self, key: bytes) -> list[int]:
		key = f"{bl(key):064b}"
		key = list(map(int, key))
		return KEYSTREAM._pr(key, KEYSTREAM._PC1)
	
	# Generate Keys
	def gen(self, rev: int) -> list[int]:
		op = KEYSTREAM._sf[rev]
		t = len(self.key)//2
		x = (rev*2)-1
		ca = self.key
		
		for i in range(KEYSTREAM._RDS):
			lt = self.key[:t]
			rt = self.key[t:]
			if KEYSTREAM._SFT[i*x]:
				lt, rt = op(lt), op(rt)
			lt, rt = op(lt), op(rt)
			self.key = lt + rt
			yield KEYSTREAM._pr(self.key, KEYSTREAM._PC2)
		
		# Assertion For Standardised Key Usage
		assert ca == self.key
		yield -1

class CIPHER:
	# Functions Used
	_pr = lambda k, m: [k[m[i]] for i in range(len(m))]
	_xr = lambda k, m: [i^j for i, j in zip(k, m)]
	_ct = lambda k: sum([i*pow(2, c) for c, i in enumerate(k[::-1])])

	# Relevant Data
	_RDS = 16
	_IP0 = [
			57, 49, 41, 33, 25, 17, 9,  1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7,
			56, 48, 40, 32, 24, 16, 8,  0,
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6
	]
	_FP0 = [
			39,  7, 47, 15, 55, 23, 63, 31,
			38,  6, 46, 14, 54, 22, 62, 30,
			37,  5, 45, 13, 53, 21, 61, 29,
			36,  4, 44, 12, 52, 20, 60, 28,
			35,  3, 43, 11, 51, 19, 59, 27,
			34,  2, 42, 10, 50, 18, 58, 26,
			33,  1, 41,  9, 49, 17, 57, 25,
			32,  0, 40,  8, 48, 16, 56, 24
	]
	_ET0 = [
			31,  0,  1,  2,  3,  4,
			 3,  4,  5,  6,  7,  8,
			 7,  8,  9, 10, 11, 12,
			11, 12, 13, 14, 15, 16,
			15, 16, 17, 18, 19, 20,
			19, 20, 21, 22, 23, 24,
			23, 24, 25, 26, 27, 28,
			27, 28, 29, 30, 31,  0
	]
	_SBL = 8
	_SBT = [
			# S1
			[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
			 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

			# S2
			[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
			 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
			 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
			 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

			# S3
			[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
			 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
			 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
			 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

			# S4
			[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
			 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
			 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
			 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

			# S5
			[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
			 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
			 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
			 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

			# S6
			[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
			 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
			 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
			 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

			# S7
			[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
			 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
			 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
			 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

			# S8
			[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
			 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
			 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
			 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]
	_PT0 = [
			15,  6, 19, 20, 28, 11, 27, 16,
			 0, 14, 22, 25,  4, 17, 30,  9,
			 1,  7, 23, 13, 31, 26,  2,  8,
			18, 12, 29,  5, 21, 10,  3, 24
	]

	def __init__(self, cip: bytes, key: bytes) -> None:
		self.cip = self._kp(cip)
		self.key = KEYSTREAM(key)
	
	# Prepare Cipher For 16 Round Feistel Structure
	def _kp(self, cip: bytes) -> list[int]:
		cip = f"{bl(cip):064b}"
		cip = list(map(int, cip))
		return CIPHER._pr(cip, CIPHER._IP0)
	
	def f(self, vl, ky):
		ct = lambda k: sum([i*pow(2, c) for c, i in enumerate(k[::-1])])
		vl = CIPHER._pr(vl, CIPHER._ET0)
		vl = CIPHER._xr(vl, ky)
		ht = CIPHER._SBL-2

		ot = []
		for i in range(CIPHER._SBL):
			bk = vl[i*ht:(i+1)*ht]
			tv = (CIPHER._ct([bk[0], bk[-1]])*16) + ct(bk[1:-1])
			ot += list(map(int, f"{CIPHER._SBT[i][tv]:04b}"))
		
		return CIPHER._pr(ot, CIPHER._PT0)
	
	def encode(self, dv = 1):
		t = len(self.cip)//2
		ky = self.key.gen(dv)

		for _ in range(16):
			lt = self.cip[:t]
			rt = self.cip[t:]
			kt = self.f(rt, next(ky))
			self.cip = rt + CIPHER._xr(lt, kt)
		
		self.cip = CIPHER._pr(self.cip[t:]+self.cip[:t], CIPHER._FP0)
		return lb(CIPHER._ct(self.cip))
	
	def decode(self):
		return self.encode(dv = 0)

def main():
	ky = urandom(16)
	pt = b'alekhavi'

	out = CIPHER(pt, ky).encode()
	cipher = DES.new(ky, DES.MODE_ECB)
	cip = cipher.encrypt(pt)
	
	print("True,", cip)
	print("Your,", out)

	assert cip == out

if __name__ == '__main__':
	main()