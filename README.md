# UnLinkable-PCS (ul-PCS)

This system enables to enforce a pre-determined policy on signatures while ensuring the unlinkability of signatures (transactions).

The structure of this repository is as follows:

* `Generic ul-PCS`: Python code to emulate the proposed Generic UL-PCS scheme. Please execute test.py for testing.
	- Acc.py: Python code to emulate the accumulator scheme.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- matmath.py: Python code to emulate some basic math operation on matrices.
	- OT12.py: Python code to emulate OT12 PO-PE scheme.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
  	- PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  	- Sigma.py: Python code to emulate the described Sigma protocols.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- SPSEQ.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature on equivalence classes.
	- test.py: To test the code.

* `RBAC ul-PCS`: Python code to emulate the proposed Role-based UL-PCS scheme. Please execute test.py for testing.
	- Acc.py: Python code to emulate the accumulator scheme.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
	- policy.py: Python code to emulate a role-based policy maker algorithm.
  	- PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  	- Sigma.py: Python code to emulate the described Sigma protocols.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- SPSEQ.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature on equivalence classes.
	- test.py: To test the code.
  
* `SeparablePolicies`: Python code to emulate the proposed UL-PCS scheme with Separable policies. Please execute test.py for testing.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- ElGamal.py: Python code to emulate the ElGamal encryption.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
	- policy.py: Python code to emulate a role-based policy maker algorithm.
  	- PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  	- Sigma.py: Python code to emulate the described Sigma protocols.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- test.py: To test the code.

* `Generic Standard PCS`: Python code to emulate the Generic Standard PCS scheme proposed by Badertscher, Matt and Waldner (TCC’21). Please execute test.py for testing.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- matmath.py: Python code to emulate some basic math operation on matrices.
	- OT12.py: Python code to emulate OT12 PO-PE scheme.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- test.py: To test the code.

## Instruction for Ubuntu 22.04

### Prerequisite Packages:
```
pip3 install -r /path/to/requirements.txt
```

### Install the PBC Stanford library:
Pairbing-Based Cryptography [PBC](https://crypto.stanford.edu/pbc/) library.

```
wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xf pbc-0.5.14.tar.gz
cd pbc-0.5.14
sudo ./configure.sh
sudo make
sudo make install
sudo make test
```

This [Youtube clip](https://www.youtube.com/watch?v=T0SHn8lMKJA) also gives a detailed instruction on how to set up the PBC library.

### Charm-crypto needs to be installed manually.

- The charm-crypto library should be installed manually from [this repository](https://github.com/JHUISI/charm.git).
Do not use the releases, they do not work. Install from the repo by running the following commands.

```
git clone https://github.com/JHUISI/charm.git
cd charm
sudo ./configure.sh
sudo make
sudo make install
sudo make test
```

Make sure to set the extra `LDFLAGS` so that charm-crypto finds pbc as shown above.

- In case if you are using VS code as the compiler and have installed multiple versions of Python, you might need to change your python interpreter to the compatible version.

```
view --> command palette --> search for Python: Select Interpreter --> choose your compatiable version.
```

- Note that python 3.8 and above seems to be broken for charm-crypto, see [this issue](https://github.com/JHUISI/charm/issues/239).
