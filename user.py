from seal import * 
import numpy as np


pow2 = []
for i in range(16):
	pow2.append(2**i)

def nearest_pow_two(x):
	l = 0; r = len(pow2)
	while l <= r:
		mid = (l+r)//2
		if pow2[mid] == x:
			return pow2[mid]
		elif pow2[mid] > x:
			r = mid-1
		else:
			l = mid+1
	return pow2[l]

class USER:
	def __init__(self, keys, context):
		self.scale = 2**40
		#Keygen		
		# context = SEALContext.Create(params)
		# keygen = KeyGenerator(context)
		self.public_key = keys.public_key
		self.private_key = keys.private_key
		self.relin_keys = keys.relin_keys
		self.gal_keys = keys.gal_keys

		#Functionalities
		self.encoder = CKKSEncoder(context)
		self.slot_count = self.encoder.slot_count()
		self.logn = int(np.log2(self.slot_count))

		self.encryptor = Encryptor(context, self.public_key)
		self.decryptor = Decryptor(context, self.private_key)
		self.evaluator = Evaluator(context)

	def encrypt_data(self, X):

		encrypt_X = []
		self.vec_len = nearest_pow_two(X.shape[1])
		self.incr = self.slot_count//self.vec_len

		print("N =", len(X),"k =",self.vec_len, "j =", self.incr)
		print("Encrypting")
		i = 0
		while i < len(X):
			x_plain = Plaintext()
			x_cipher = Ciphertext()
			# if i%800 == 0:
				# print(i)
			x = [0]*self.slot_count
			# print(i, incr, len(x))
			j = i
			while j < min(i+self.incr, len(X)):
				l = (j-i)*self.vec_len
				x[l:l+X.shape[1]] = X[j]
				j += 1
			data = DoubleVector(x)
			self.encoder.encode(data, self.scale, x_plain)
			self.encryptor.encrypt(x_plain, x_cipher)
			encrypt_X.append(x_cipher)
			i += self.incr

		return np.array(encrypt_X)

	def extract_eigen_vectors(self, eig_vec, size):
		vec = []
		for i in range(len(eig_vec)):
			vec.append(self.decrypt_data(eig_vec[i])[:size])
		vec = np.array(vec)
		return vec.T


	def decrypt_data(self, X):
		X_plain = Plaintext(); X_vec = DoubleVector()
		self.decryptor.decrypt(X, X_plain)
		self.encoder.decode(X_plain, X_vec)
		return np.array(X_vec)
		# decrypt_X = []

		# for i in range(len(X)):
		# 	x_plain = Plaintext()
		# 	x_vec = DoubleVector()
		# 	self.decryptor.decrypt(X[i], x_plain)
		# 	self.encoder.decode(x_plain, x_vec)
		# 	temp = np.array(x_vec)
		# 	for j in range(self.incr):
		# 		decrypt_X.append(temp[j*self.vec_len : (j+1)*self.vec_len])

		# return np.array(decrypt_X)
