from charm.toolbox.pairinggroup import PairingGroup,pair
from main import PCS
from BLS import BLS01 as DS
import numpy as np
from BG import BG
from SPS import SPS
from GS import GS as NIZK
from OT12 import OT as FE

groupObj = PairingGroup('BN254')
DS = DS(groupObj)
BG = BG(groupObj)
NIZK = NIZK(groupObj)
SPS = SPS(groupObj)
PCS = PCS(groupObj)

def main(N,x,v):
    '''
    To Setup the master secret key and master public key
    '''
    (msk, mpk) = PCS.Setup(N)
    

    '''
    KeyGen algorithm for the sender
    '''

    (sk_S,pk_S) = PCS.KeyGen(mpk,msk,x)
    
    '''
    KeyGen algorithm to create the receiver's key
    '''

    (sk_R,pk_R) = PCS.KeyGen(mpk,msk,v)
 

    '''
    To sign a random integer m under the secret key sk and public key pk_R
    '''
    m = groupObj.random()
    (sigma) = PCS.Sign(mpk,sk_S,pk_R,m)

    '''
    To verify the signature on message m under the public key pk and pk_R
    '''
    out = PCS.Batched_verify(mpk,pk_S,pk_R,m,sigma)
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