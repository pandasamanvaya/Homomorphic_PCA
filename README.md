# HPCA
This repository focuses on performing PCA on encrypted data.
To use this repository, clone the repo and type :- 
```
cd Homomorphic_PCA
python3 pca.py
```
Dependencies required :-
* [Seal-Python](https://github.com/Huelse/SEAL-Python)
* PIL
* sklearn

The ```read_data.py``` file supports reading of 7 datasets that were used for experimentation. The [Yale face](http://vision.ucsd.edu/content/yale-face-database) dataset has been provided in the repository. Other datasets that are supported are:-
* [Parkinsons Telemonitoring](https://archive.ics.uci.edu/ml/datasets/parkinsons)
* [Air Quality](https://archive.ics.uci.edu/ml/datasets/Air+Quality)
* [Wine Quality(both red and white)](https://archive.ics.uci.edu/ml/datasets/wine+quality)
* [MNIST](http://yann.lecun.com/exdb/mnist/)
* [Fashion-MNIST](https://github.com/zalandoresearch/fashion-mnist)
