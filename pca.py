from seal import * 
import numpy as np
import time 
from sklearn.metrics import r2_score
from read_data import *
from server import *
from user import *
	
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

class Key:
	def __init__(self, context):
		keygen = KeyGenerator(context)
		self.public_key = keygen.public_key()
		self.private_key = keygen.secret_key()
		self.relin_keys = keygen.relin_keys()
		self.gal_keys = keygen.galois_keys()

#CKKS Parameters
params = EncryptionParameters(scheme_type.CKKS)
poly_modulus_degree = 8192*2
params.set_poly_modulus_degree(poly_modulus_degree)
# params.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50]))
params.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [59, 40, 40, 40, 40, 40, 40, 40, 40, 59]))

# scale = 2**40
context = SEALContext.Create(params)
keys = Key(context)
user = USER(keys, context)


dim = 8
imgs = 100

# X_ori = wine_data()
X_ori = load_mnist("training", no_of_imgs=imgs)
# size = X_ori.shape
# # X_ori = X_ori.reshape((size[0], size[1]*size[2]))
# X_ori = load_yale()
mu = np.mean(X_ori, axis=0)
X = X_ori - mu
print(X.shape)

cov_mat = X.T.dot(X)
eig_val, eig_vec = np.linalg.eig(cov_mat)
print(eig_val[:10]) 
X_cipher = user.encrypt_data(X)
print(X_cipher.shape, user.incr, user.vec_len)

server = SERVER(keys, user.incr, dim, context)
# temp_x = X[]
start = time.time()
eig_val, eig_vec = server.power_iteration(X_cipher)
end = time.time()
vec = user.extract_eigen_vectors(eig_vec, X.shape[1])
with open("eigen_vector.npy", "wb") as file:
	np.save(file, vec)

X_red = X.dot(vec)
print(X_red.shape)
X_new = X_red.dot(vec.T) + mu 
print("Time taken =",(end-start)/60,"mins")
print("R2 score =", r2_score(X_ori, X_new))
