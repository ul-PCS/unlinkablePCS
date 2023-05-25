from charm.toolbox.pairinggroup import PairingGroup,pair
from main import UPCS
from BLS import BLS01 as DS
from BG import BG

from PRF import DY as PRF
from OT12 import OT as FE
from SPS import SPS
from GS import GS as NIZK
from Pedersen import PedCom as Com
from SPSEQ import SPSEQ as SEQ
from Sigma import Sigma
import numpy as np
from Bulletproof import RangeProof
from Acc import ACC
from Pedersen import GPed

groupObj = PairingGroup('BN254')
ACC = ACC(groupObj)
SEQ = SEQ(groupObj)
DS = DS(groupObj)
BG = BG(groupObj)
PRF = PRF(groupObj)
NIZK = NIZK(groupObj)
Sigma= Sigma(groupObj)
SPS = SPS(groupObj)
RangeProof = RangeProof()
Com = GPed(groupObj)
UPCS = UPCS(groupObj)

def main(N,x,v):
    '''
    To Setup the master secret key and master public key
    '''
    (msk, mpk) = UPCS.Setup(N)
    

    '''
    KeyGen algorithm for the sender
    '''
    sk_S={};pk_S={}
    (sk_S[0],pk_S[0]) = UPCS.KeyGen(mpk,msk,x)
    
    '''
    KeyGen algorithm to create the receiver's key
    '''
    sk_R={};pk_R={}
    (sk_R[0],pk_R[0]) = UPCS.KeyGen(mpk,msk,v)

    '''
    senders' key re-randomization
    '''
    (sk_S[1],pk_S[1]) = UPCS.RandKey(mpk,sk_S[0])

    '''
    Receiver's key re-randomization
    '''
    (sk_R[1],pk_R[1]) = UPCS.RandKey(mpk,sk_R[0])
    

    '''
    To sign a random integer m under the secret key sk and public key pk_R
    '''
    m = groupObj.random()
    (sigma) = UPCS.Sign(mpk,sk_S[1],pk_R[0],m)

    '''
    To verify the signature on message m under the public key pk and pk_R
    '''
    out = UPCS.Batched_verify(mpk,pk_S[1],pk_R[0],m,sigma)
    if out==True:
        print('The signature is valid.\n')
    else:
        print('The signature is not valid.\n')



'''
You can adjust the number of attributes by changing n
'''

n=2 #number of attributes
v=[groupObj.random() for _ in range(n-1)]
x=[groupObj.random() for _ in range(n-1)]
p=groupObj.order()
v.append(p-(np.sum([x * y for x, y in zip(v, x)])))
x.append(1)
prod = np.sum([x * y for x, y in zip(v, x)]) 
print('IP(x,v)={}'.format(prod))



main(4*n+2,x,v)