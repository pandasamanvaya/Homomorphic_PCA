import numpy as np 
from scipy import optimize
from matplotlib import pyplot as plt
k = 750
n = 2**13

x = np.linspace(0.001, k, n)
# x2 = np.linspace(500, 700, n)
# x = np.append(x, x2)
y = x**(-0.5)

def f(w):
	cost = 0
	for i in range(n):
		cost += (w[0]*x[i] + w[1] - y[i])**2
	return cost/n

np.random.seed(1)
const = []
for i in range(n):
	# const.append({'type':'ineq', 'fun': lambda w: 1.5*(w[0]*x[i] + w[1] - y[i])-1.5*(w[0]*x[i] + w[1] - y[i])*y[i]**2-1.5*(w[0]*x[i] + w[1]-y[i])**2*y[i]-(w[0]*x[i] + w[1]-y[i])**3})
	const.append({'type':'ineq', 'fun': lambda w: w[0]*x[i]+w[1]})

result = optimize.minimize(f, x0=[0.0, 0.0], method="SLSQP", constraints=const)
# result = optimize.minimize(f, x0=[0.0, 0.0], method="SLSQP")
print(result)
# a = result['x'][0]; b = result['x'][1]
# y_pred = a*x + b
# for i in range(2):
# 	y_pred = 1.5*y_pred - 0.5*x*y_pred**3
# print("Error =", np.mean((y_pred-y)**2))

# z = np.array([0.2, 1000]); z_pred = a*z+b
# for i in range(4):
# 	z_pred = 1.5*z_pred - 0.5*z*z_pred**3

# print(z, z_pred, z**(-0.5))
# plt.plot(x, y_pred)
# plt.plot(x, y)
# plt.show()