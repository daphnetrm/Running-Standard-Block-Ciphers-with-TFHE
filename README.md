# Implementation of the paper "Running Standard Block Ciphers Beyond AES with TFHE: Experiments and Lessons Learnt"

## Install TFHElib

To run the code, you first have to install the TFHElibrary (you can find it [here](https://tfhe.github.io/tfhe/)) and apply the patch provided in the file patch_fft.patch. The git clone command should automatically install version 1.1 of TFHElib, wich we used to implement our work.

1/ git clone https://github.com/tfhe/tfhe.git   
2/ cd tfhe   
3/ cp path/to/patch_fft.patch ./    
4/ git apply patch_fft.patch    
5/ make   


## Run the code

Once TFHElib version 1.1 and the provided patch are installed, you should:

1/ go in the directory of the block cipher you want to evaluate



