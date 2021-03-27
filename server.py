from seal import * 
import numpy as np
import time

class SERVER:
	def __init__(self, keys, incr, dims, context):
		self.scale = 2**40
		self.count = 0
		self.dims = dims
		self.context = context
		#Keygen		
		# context = SEALContext.Create(params)
		# keygen = KeyGenerator(context)
		self.public_key = keys.public_key
		self.private_key = keys.private_key
		self.relin_keys = keys.relin_keys
		self.gal_keys = keys.gal_keys

		#Functionalities
		self.encoder = CKKSEncoder(self.context)
		self.slot_count = self.encoder.slot_count()
		self.logn = int(np.log2(self.slot_count))
		self.incr = incr
		self.vec_len = self.slot_count//incr

		self.encryptor = Encryptor(self.context, self.public_key)
		self.decryptor = Decryptor(self.context, self.private_key)
		self.evaluator = Evaluator(self.context)

	def linear_approx(self, x):

		A = Plaintext()
		B = Plaintext()
		ans = Ciphertext()
		a = -0.00019703; b = 0.14777278
		self.encoder.encode(a, self.scale, A)
		self.encoder.encode(b, self.scale, B)

		#Evaluating a*x
		self.evaluator.mod_switch_to_inplace(A, x.parms_id())
		self.evaluator.multiply_plain(x, A, ans)
		self.evaluator.rescale_to_next_inplace(ans)
				
		#Evaluating a*x + b
		ans.scale(self.scale);
		self.evaluator.mod_switch_to_inplace(B, ans.parms_id())
		self.evaluator.add_plain_inplace(ans, B)

		return ans

	def re_encrypt(self, x):
		self.count += 1
		x_plain = Plaintext(); x_vec = DoubleVector()

		self.decryptor.decrypt(x, x_plain)
		self.encoder.decode(x_plain, x_vec)
		self.encoder.encode(x_vec, self.scale, x_plain)
		self.encryptor.encrypt(x_plain, x)

		return x

	def add_row_elements(self, x, offset=1):
		if offset == 1:
			for i in range(self.logn):
				temp = Ciphertext()
				self.evaluator.rotate_vector(x, 2**i, self.gal_keys, temp)
				self.evaluator.add_inplace(x, temp)
		else:
			for i in range(int(np.log2(self.incr))):
				temp = Ciphertext()
				self.evaluator.rotate_vector(x, (2**i)*offset, self.gal_keys, temp)
				# print("i =",i, end=" ");self.print_value(temp)
				self.evaluator.add_inplace(x, temp)
		return x

	def expand_vector(self, x):

		temp = Ciphertext()
		for i in range(int(np.log2(self.vec_len))):
			self.evaluator.rotate_vector(x, (self.slot_count - 2**i), self.gal_keys, temp)
			self.evaluator.add_inplace(x, temp)


	def partial_add(self, x):

		ones = np.append(np.ones(self.vec_len//2), np.zeros(self.vec_len//2))
		for i in range(int(np.log2(self.incr))):
			ones = np.append(ones, ones)
		id_vec = DoubleVector(ones)

		id_plain = Plaintext(); id = Ciphertext()
		self.encoder.encode(id_vec, self.scale, id_plain)
		self.encryptor.encrypt(id_plain, id)

		ans_plain = Plaintext(); ans = Ciphertext()
		self.encoder.encode(0.0, self.scale, ans_plain)
		self.encryptor.encrypt(ans_plain, ans)

			# self.evaluator.mod_switch_to_inplace()
		# x = Ciphertext(X)
		start = time.time()
		for i in range(int(np.log2(self.vec_len))-1, -1, -1):

			# if self.context.get_context_data(x.parms_id()).chain_index() <= 1:
				# x = self.re_encrypt(x)

			self.evaluator.mod_switch_to_inplace(id, x.parms_id())
			temp = Ciphertext(); s1 = Ciphertext(); s2 = Ciphertext()
			# print(self.slot_count, 2**i)
			# print(np.sum(ones))
			self.evaluator.rotate_vector(id, self.slot_count - 2**i, self.gal_keys, temp)

			self.evaluator.multiply(temp, x, s1)
			self.evaluator.relinearize_inplace(s1, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(s1)
			self.evaluator.rotate_vector_inplace(s1, 2**i, self.gal_keys)
			# print("s1 =", end=" "); self.print_value(s1)
			self.evaluator.multiply(id, x, s2)
			self.evaluator.relinearize_inplace(s2, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(s2)
			# print("s2 =", end=" "); self.print_value(s2)
			self.evaluator.add(s1, s2, x)
			# self.print_value(x)

			if i != 0:
				self.evaluator.rotate_vector_inplace(temp, 2**i + 2**(i-1), self.gal_keys)
				self.evaluator.multiply_inplace(id, temp)
				self.evaluator.relinearize_inplace(id, self.relin_keys)
				self.evaluator.rescale_to_next_inplace(id)

				# id = self.re_encrypt(id)

			# print("ans =", end=" "); self.print_value(ans)
			# print(s.scale(), ans.scale())
			# print()
		self.expand_vector(x)
		# print("Time taken for each addition =", time.time() - start)
		# self.print_value(x)

		return x

	def sum_of_squares(self, x):
		norm = Ciphertext()
		self.evaluator.square(x, norm)
		self.evaluator.relinearize_inplace(norm, self.relin_keys)
		self.evaluator.rescale_to_next_inplace(norm)
		norm = self.partial_add(norm)
		norm = self.re_encrypt(norm)
		# temp = np.ones(self.slot_count)*(1/self.incr)
		# incr_inv = DoubleVector(temp); div_by_incr = Plaintext()
		# self.encoder.encode(incr_inv, self.scale, div_by_incr)

		# self.evaluator.mod_switch_to_inplace(div_by_incr, norm.parms_id())
		# self.evaluator.multiply_plain_inplace(norm, div_by_incr)
		# # self.evaluator.relinearize_inplace(norm, self.relin_keys)
		# self.evaluator.rescale_to_next_inplace(norm)

		return norm

	def inv_norm_approx(self, norm):

		guess = self.linear_approx(norm)
		# print("guess =", end=" "); self.print_value(guess)

		# return guess
		#Newton's Method
		div1 = Plaintext()
		div2 = Plaintext()

		self.encoder.encode(-0.5, self.scale, div1)
		self.encoder.encode(1.5, self.scale, div2)

		sum_x = Ciphertext()
		r = 1
		for i in range(r):
			# print("Iteration i =", i+1)
			## x_i+1 = (-b*x_i**3)/2 + 3x_i/2

			#x_i**2
			# print(context.get_context_data(square_x.parms_id()).chain_index())
			# print(context.get_context_data(guess.parms_id()).chain_index())
			# print(guess.scale(), square_x.scale())
			square_x = Ciphertext()
			self.evaluator.square(guess, square_x)
			self.evaluator.relinearize_inplace(square_x, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(square_x)
			# print("guess**2 =", end=" "); self.print_value(square_x)
			#b*x_i
			# square_x.scale(self.scale)
			out_x = Ciphertext()
			self.evaluator.mod_switch_to_inplace(norm, guess.parms_id())
			self.evaluator.multiply(guess, norm, out_x)
			self.evaluator.relinearize_inplace(out_x, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(out_x)
			# print("guess*square =", end=" "); self.print_value(out_x)
		
			#-(x_i**2)/2
			# print(square_x.parms_id(), div1.parms_id())
			self.evaluator.mod_switch_to_inplace(div1, square_x.parms_id())
			# print(square_x.scale(), div1.scale())
			self.evaluator.multiply_plain_inplace(square_x, div1)
			# self.evaluator.relinearize_inplace(out_x, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(square_x)
			# print("-guess**2/2 =", end=" "); self.print_value(square_x)


			#(-b*x_i**3)/2
			self.evaluator.mod_switch_to_inplace(out_x, square_x.parms_id())
			# out_x.scale(self.scale/10); square_x.scale(self.scale/10)
			# print(out_x.scale(), square_x.scale())
			self.evaluator.multiply_inplace(square_x, out_x)
			self.evaluator.relinearize_inplace(square_x, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(square_x)
			# print("guess*square*(-guess**2/2) = ", end=""); self.print_value(square_x)

			#3*x_i/2 
			self.evaluator.mod_switch_to_inplace(div2, guess.parms_id())
			self.evaluator.multiply_plain(guess, div2, sum_x)
			# self.evaluator.relinearize_inplace(sum_x, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(sum_x)
			# print("1.5*guess**2 =", end=" "); self.print_value(sum_x)

			#(-b*x_i**3)/2 + 3x_i/2
			self.evaluator.mod_switch_to_inplace(sum_x, square_x.parms_id())
			square_x.scale(self.scale)
			sum_x.scale(self.scale)
			self.evaluator.add(sum_x, square_x, guess)

		return guess

	def print_value(self, x):
		x_plain = Plaintext(); x_vec = DoubleVector()
		self.decryptor.decrypt(x, x_plain)
		self.encoder.decode(x_plain, x_vec)
		print(x_vec[0])

	def goldschmidt(self, X):
		# temp = self.count
		temp = 0
		# print("X level=", context.get_context_data(X.parms_id()).chain_index())
		norm = self.sum_of_squares(X)
		# print("square =", end=" "); self.print_value(norm)

		# self.evaluator.square(X, norm)
		# self.evaluator.relinearize_inplace(norm, self.relin_keys)
		# self.evaluator.rescale_to_next_inplace(norm)
		# norm = self.add_row_elements(norm)
		# print("square =", end=" "); self.print_value(norm)
		y = Ciphertext(); x = Ciphertext(); r = Ciphertext(); h = Ciphertext()
		y_result = Plaintext(); half = Plaintext(); neg_one = Plaintext()		
		y = self.inv_norm_approx(norm)
		# print("inv =", end=" "); self.print_value(y)
		y = self.re_encrypt(y)


		#x = norm*y
		self.evaluator.mod_switch_to_inplace(y, norm.parms_id())
		self.evaluator.multiply(norm, y, x)
		self.evaluator.relinearize_inplace(x, self.relin_keys)
		self.evaluator.rescale_to_next_inplace(x)
		#h = y/2
		self.encoder.encode(0.5, self.scale, half)
		self.evaluator.mod_switch_to_inplace(half, y.parms_id())
		self.evaluator.multiply_plain(y, half, h)
		# self.evaluator.relinearize_inplace(h, self.relin_keys)
		self.evaluator.rescale_to_next_inplace(h)

		k = 5
		r_res = Plaintext(); x_res = Plaintext(); h_res = Plaintext()

		for i in range(k):
			# print("Iteration :", i)
			self.encoder.encode(-1.0, self.scale, neg_one)
			self.encoder.encode(0.5, self.scale, half)

			# self.decryptor.decrypt(x, x_res)
			# self.encryptor.encrypt(x_res, x)

			# self.decryptor.decrypt(h, h_res)
			# self.encryptor.encrypt(h_res, h)
			##r = 0.5 - x*h
			temp_r = Ciphertext()
			#temp_r = x*h
			# x.scale(10); h.scale(10)
			# print(context.get_context_data(x.parms_id()).chain_index())
			# print(context.get_context_data(h.parms_id()).chain_index())
			self.evaluator.multiply(x, h, temp_r)
			self.evaluator.relinearize_inplace(temp_r, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(temp_r)
			# self.print_value(h)
			#temp_r = -x*h
			# print(neg_one.scale(), temp_r.scale())
			self.evaluator.mod_switch_to_inplace(neg_one, temp_r.parms_id())
			self.evaluator.multiply_plain_inplace(temp_r, neg_one)
			# self.evaluator.relinearize_inplace(temp_r, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(temp_r)
			# print(context.get_context_data(temp_r.parms_id()).chain_index())

			#r = 0.5 + temp_r
			self.evaluator.mod_switch_to_inplace(half, temp_r.parms_id())
			temp_r.scale(self.scale)
			self.evaluator.add_plain(temp_r, half, r)
			# temp = self.context.get_context_data(r.parms_id()).chain_index()

			##x = x + x*r
			temp_x = Ciphertext()
			#temp_x = x*r
			# print(context.get_context_data(x.parms_id()).chain_index())
			self.evaluator.mod_switch_to_inplace(x, r.parms_id())
			# x.scale(r.scale())
			# r.scale(x.scale())
			self.evaluator.multiply(x, r, temp_x)
			self.evaluator.relinearize_inplace(temp_x, self.relin_keys)
			# self.print_value(temp_x);
			self.evaluator.rescale_to_next_inplace(temp_x)
			#x = x + temp_x
			self.evaluator.mod_switch_to_inplace(x, temp_x.parms_id())
			# print(temp_x.scale(), x.scale())
			# temp_x.scale(self.scale); x.scale(self.scale)
			temp_x.scale(self.scale); x.scale(self.scale)
			# self.print_value(x)
			# self.print_value(temp_x)
			self.evaluator.add_inplace(x, temp_x)
			# print("x*r + x", end=" "); self.print_value(x)

			##h = h + h*r
			temp_h = Ciphertext()
			#temp_h = h*r
			self.evaluator.mod_switch_to_inplace(h, r.parms_id())
			self.evaluator.multiply(h, r,temp_h)
			self.evaluator.relinearize_inplace(temp_h, self.relin_keys)
			self.evaluator.rescale_to_next_inplace(temp_h)
			#h = h + temp_h
			self.evaluator.mod_switch_to_inplace(h, temp_h.parms_id())
			temp_h.scale(self.scale); h.scale(self.scale)
			self.evaluator.add_inplace(h, temp_h)

			# self.print_value(x)
			# if i%2:
			# print(self.context.get_context_data(r.parms_id()).chain_index() - temp)
			if self.context.get_context_data(x.parms_id()).chain_index() <= 2:
				temp += 1
				# r = self.re_encrypt(r) 
				x = self.re_encrypt(x)
				h = self.re_encrypt(h)
			# self.decryptor.decrypt(r, r_res)
			# self.encryptor.encrypt(r_res, r)
			# print("r = 0.5-x*h"); self.print_value(r)
		two = Plaintext()
		self.encoder.encode(2.0, self.scale, two)

		self.evaluator.mod_switch_to_inplace(two, h.parms_id())
		self.evaluator.multiply_plain_inplace(h, two)
		# self.evaluator.relinearize_inplace(h, self.relin_keys)
		self.evaluator.rescale_to_next_inplace(h)

		# self.print_value(x)
		# self.print_value(h)
		# print(self.count - temp)
		# print(temp)
		return x, h

	def init_vector(self):
		temp = np.random.random(self.vec_len)
		init_vec = np.array([])
		for i in range(self.incr):
			init_vec = np.append(init_vec, temp)
		print(self.vec_len, init_vec.shape)
		# temp = temp/np.linalg.norm(temp)
		# print(init_vec.shape)
		temp_vec = DoubleVector(init_vec)
		return temp_vec

	def vect_mat_product(self, X_j, r):
		x = Ciphertext()
		self.evaluator.multiply(X_j, r, x)
		self.evaluator.relinearize_inplace(x, self.relin_keys)
		self.evaluator.rescale_to_next_inplace(x)
		# return x

		# print("level =",context.get_context_data(x.parms_id()).chain_index())
		# start = time.time()
		x = self.partial_add(x)
		# print("Time taken for partial add", time.time()-start)
		# print("level =",context.get_context_data(x.parms_id()).chain_index())
		#x = X.x
		# print(x.scale(), X[j].scale())
		self.evaluator.mod_switch_to_inplace(X_j, x.parms_id())
		self.evaluator.multiply_inplace(x, X_j)
		self.evaluator.relinearize_inplace(x, self.relin_keys)
		self.evaluator.rescale_to_next_inplace(x)
		# print("x =", end=" "); self.print_value(x)

		return x
		
	def power_iteration(self, X):

		eig = []; eig_vec = []
		iterations = 4
		temp_vec = self.init_vector()
		# print("levels =", context.get_context_data(X[0].parms_id()).chain_index())

		for d in range(self.dims):
			print("Eigen vector :", d+1)
			r_plain = Plaintext(); r = Ciphertext()
			self.encoder.encode(temp_vec, self.scale, r_plain)
			self.encryptor.encrypt(r_plain, r)
			eig_val = 0
			for k in range(iterations):
				# print("Iteration :", k+1)

				S_plain = Plaintext(); S1 = Ciphertext(); S2 = Ciphertext() 
				self.encoder.encode(0.0, self.scale, S_plain)
				self.encryptor.encrypt(S_plain, S2)
				self.encryptor.encrypt(S_plain, S1)
				# print("r =", end=""); self.print_value(r)
				for j in range(len(X)):
					# start = time.time()
					# self.print_value(X[j])
					##x = X.(X^T.r)
					X_j = Ciphertext(X[j])
					#x = X^T.r
					# if j%5 == 0:
					# print(j)
					# print(context.get_context_data(r.parms_id()).chain_index())
					# self.evaluator.mod_switch_to_inplace(r, X_j.parms_id())
					#S = S + x
					# print("X =", end=" "); self.print_value(X_j)
					x = self.vect_mat_product(X_j, r)
					# print("Time taken for vector multiplication", time.time() - start)

					# self.print_value(self.sum_of_squares(x))
					self.evaluator.mod_switch_to_inplace(S1, x.parms_id())
					# print(S1.scale(), x.scale())
					S1.scale(self.scale); x.scale(self.scale)
					self.evaluator.add_inplace(S1, x)
				# if context.get_context_data(r.parms_id()).chain_index() < 5:
				# print("Time taken for multiplication", time.time() - start)
				S1 = self.add_row_elements(S1, self.vec_len)
				# print("S1 =", end=" "); self.print_value(S1)
				# print("S1 =", end=" "); self.print_value(self.sum_of_squares(S1))

				S1 = self.re_encrypt(S1)

				# S2_plain = Plaintext(); 
				# S2 = Ciphertext()
				# self.encoder.encode(1e-10, self.scale, S2_plain)
				# self.encryptor.encrypt(S_plain, S2)
				# self.evaluator.multiply_plain_inplace(S2, S_plain)
				# self.evaluator.relinearize_inplace(S2, self.relin_keys)
				# self.evaluator.rescale_to_next_inplace(S2)

				# print("S2 init =", end=" "); self.print_value(S2)

				for j in range(len(eig_vec)):
					
					X_j = Ciphertext(eig_vec[j])
					# print(self.context.get_context_data(X_j.parms_id()).chain_index())
					x = self.vect_mat_product(X_j, r)
					# x = Ciphertext()
					# self.evaluator.multiply(X_j, r, x)
					# self.evaluator.relinearize_inplace(x, self.relin_keys)
					# self.evaluator.rescale_to_next_inplace(x)
					# # print("x_mult =", end=" "); self.print_value(x)
					# # return x
					# x = self.partial_add(x)
					# # print("x_add =", end=" "); self.print_value(x)
					# # print("X.t.dot(r)", end=" "); self.print_value(x)
					# #x = X.x
					# # print(x.scale(), X[j].scale())
					# self.evaluator.mod_switch_to_inplace(X_j, x.parms_id())
					# # print("X_j =", end=" "); self.print_value(X_j)
					# # print("level =",context.get_context_data(X[j].parms_id()).chain_index())
					# self.evaluator.multiply_inplace(x, X_j)
					# self.evaluator.relinearize_inplace(x, self.relin_keys)
					# self.evaluator.rescale_to_next_inplace(x)
					# print("x =", end=" "); self.print_value(self.sum_of_squares(x))

					eig_j = Ciphertext(eig[j])
					# print("eig =", end=" "); self.print_value(eig_j)
					# print(self.context.get_context_data(x.parms_id()).chain_index())
					self.evaluator.mod_switch_to_inplace(eig_j, x.parms_id())
					eig_j.scale(self.scale); x.scale(self.scale)

					self.evaluator.multiply_inplace(x, eig_j)
					self.evaluator.relinearize_inplace(x, self.relin_keys)
					self.evaluator.rescale_to_next_inplace(x)
					# print("x =", end=" "); self.print_value(self.sum_of_squares(x))

					self.evaluator.mod_switch_to_inplace(S2, x.parms_id())
					# print("S2 =", end=" "); self.print_value(S2)
					S2.scale(self.scale); x.scale(self.scale)
					# self.print_value(x)
					self.evaluator.add_inplace(S2, x)

				S2 = self.re_encrypt(S2)
				# print("S2 =", end=" "); self.print_value(self.sum_of_squares(S2))
				one = Plaintext()
				self.encoder.encode(-1.0, self.scale, one)
				# self.evaluator.mod_switch_to_inplace(one)
				self.evaluator.multiply_plain_inplace(S2, one)
				# self.evaluator.relinearize_inplace(S2, self.relin_keys)
				self.evaluator.rescale_to_next_inplace(S2)
				# print("S2 =", end=" "); self.print_value(S2)
				# level1 = context.get_context_data(S1.parms_id()).chain_index()
				# if level2 > level1:
				self.evaluator.mod_switch_to_inplace(S1, S2.parms_id())
				S1.scale(self.scale); S2.scale(self.scale)
				# else:
					# self.evaluator.mod_switch_to_inplace(S1, S2.parms_id())
					# S1.scale(S2.scale())

				self.evaluator.add_inplace(S1, S2)
				# print("S1 =", end=" "); self.print_value(self.sum_of_squares(S1))
				# print(context.get_context_data(S1.parms_id()).chain_index())
				# print("S1 =", end=" "); self.print_value(S1)
				# S1 = self.re_encrypt(S1)
				# print("Computing eigen value")
				# start = time.time()
				eig_val, eig_inv = self.goldschmidt(S1)

				# print("Time by goldschmidt =", time.time() - start)
				# return S, r
				#r = r*eig_inv
				# print(context.get_context_data(S.parms_id()).chain_index())
				# print(context.get_context_data(eig_inv.parms_id()).chain_index())
				# if context.get_context_data(r.parms_id()).chain_index() < 7:
					# self.evaluator.mod_switch_to_inplace(eig_inv, S.parms_id())
				# else:
				self.evaluator.mod_switch_to_inplace(S1, eig_inv.parms_id())
				# print("eig_val", end=" "); self.print_value(eig_val)
				# print("eig_inv", end=" "); self.print_value(eig_inv)

				self.evaluator.multiply_inplace(S1, eig_inv)
				r = self.re_encrypt(S1)

				# print("r =", end=" "); self.print_value(r)
			print("final eig_val", end=" "); self.print_value(eig_val)
			eig_val = self.re_encrypt(eig_val)
			# print(self.count)
			eig.append(eig_val); eig_vec.append(r)

		return eig, eig_vec
