import os, struct
from array import array as pyarray
from PIL import Image
import numpy as np 

def resize_image(original_image):
    width , height = 16,16
    resize_image = np.zeros(shape=(width,height))

    for W in range(width):
        for H in range(height):
            new_width = int( W * original_image.shape[0] / width )
            new_height = int( H * original_image.shape[1] / height )
            resize_image[W][H] = original_image[new_width][new_height]

    return resize_image

def load_mnist(dataset="training", digits=np.arange(10), path=".", no_of_imgs=60000):
    if dataset == "training":
        fname_img = os.path.join(path, 'train-images-idx3-ubyte')
        fname_lbl = os.path.join(path, 'train-labels-idx1-ubyte')
    elif dataset == "testing":
        fname_img = os.path.join(path, 't10k-images.idx3-ubyte')
        fname_lbl = os.path.join(path, 't10k-labels.idx1-ubyte')
    
    else:
        raise ValueError("dataset must be 'testing' or 'training'")

    print("Reading images")
    flbl = open(fname_lbl, 'rb')
    magic_nr, size = struct.unpack(">II", flbl.read(8))
    lbl = pyarray("b", flbl.read())
    flbl.close()

    fimg = open(fname_img, 'rb')
    magic_nr, size, rows, cols = struct.unpack(">IIII", fimg.read(16))
    img = pyarray("B", fimg.read())
    fimg.close()

    ind = [ k for k in range(size) if lbl[k] in digits ]
    N = size #int(len(ind) * size/100.)
    images = np.zeros((no_of_imgs, 16, 16), dtype=np.uint8)
    labels = np.zeros((no_of_imgs, 1), dtype=np.int8)
    for i in range(no_of_imgs): #int(len(ind) * size/100.)):
    	temp = np.array(img[ ind[i]*rows*cols : (ind[i]+1)*rows*cols]).reshape((rows, cols))
    	images[i] = resize_image(temp)
    	labels[i] = lbl[ind[i]]
    labels = [label[0] for label in labels]
    size = images.shape
    images = images.reshape((size[0], size[1]*size[2]))

    return images/2000

def load_image(path):
    im = Image.open(path).convert('L')
    im = im.resize((32, 32))
    im = np.array(im)
    return im

def load_yale():
	print("Reading Images")
	dir_path = "./Yale"
	# label_dict = {}
	# for i in range(15):
	# 	label_dict[str(i+1)] = i
	image_list = []
	for filename in sorted(os.listdir(dir_path)):
		im = load_image(os.path.join(dir_path,filename))
		image_list.append(im)
	image_list = np.array(image_list)
	size = image_list.shape
	image_list = image_list.reshape((size[0], size[1]*size[2]))

	return image_list[:50]/5000

def wine_data():
	file = open("winequality-red.csv", "r")
	X = []
	line = file.readline()
	line = file.readline()
	while line:
		line = [float(i) for i in line.split(";")]
		X.append(line[:-1])
		line = file.readline()
	X = np.array(X)
	return X/450
