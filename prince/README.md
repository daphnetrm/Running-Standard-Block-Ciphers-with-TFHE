# Homomorphic Evaluation of PRINCE

## Install TFHElib

To run the code, you first have to install the TFHElibrary (you can find it [here](https://tfhe.github.io/tfhe/)) and apply the patch provided in the file patch_fft.patch, as explained in the global README file of this repository.


## Run the code

Once TFHElib version 1.1 and the provided patch are installed, you should:

1/ Go to the clefia directory.    
2/ Update the path to the TFHElib directory in the provided sources/CMakeList.txt.     
3/ In the clefia directory, run the "cmake -S . -B ./build" command.      
4/ Run "cd build ; make" to finalize compilation.     
5/ Command "../bin/prince" will then run our PRINCE homomorphic evaluation.   



