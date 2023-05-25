
from charm.toolbox.pairinggroup import PairingGroup
from main import UPCS
from policy import Policy


groupObj = PairingGroup('BN254')
F_lambda = Policy()
UPCS = UPCS(groupObj)

def main(n_R,x,y):
    '''
    Policy maker
    '''
    F=F_lambda.maker(n_R)

    '''
    This command ensures the policy for role x and role y fulfills.
    '''
    F['R'][y]=1; F['R'][x]=1; F['S'][y]=1; F['S'][x]=1
    
    '''
    To Setup the master secret key and master public key
    '''
    (msk, mpk) = UPCS.Setup()
    

    '''
    KeyGen algorithm for the sender
    '''
    sk={};pk={}
    (sk[0],pk[0]) = UPCS.KeyGen(mpk,msk,x,F)
    
    '''
    KeyGen algorithm to create the receiver's key
    '''
    sk_R={};pk_R={}
    (sk_R[0],pk_R[0]) = UPCS.KeyGen(mpk,msk,y,F)

    '''
    senders' key re-randomization
    '''
    (sk[1],pk[1]) = UPCS.RandKey(mpk,sk[0])

    '''
    Receiver's key re-randomization
    '''
    (sk_R[1],pk_R[1]) = UPCS.RandKey(mpk,sk_R[0])
    
    '''
    To sign a random integer m under the secret key sk and public key pk_R
    '''
    m = groupObj.random()
    sigma = UPCS.Sign(mpk,sk[1],pk_R[1],m)

    '''
    To verify the signature on message m under the public key pk and pk_R
    '''
    out = UPCS.Batched_verify(mpk,pk[1],pk_R[1],m,sigma)
    if out==True:
        print('The signature is valid.\n')
    else:
        print('The signature is not valid.\n')



'''
You can adjust the size of policy matrix by changing n_R
'''
n_R=10
main(n_R,3,2)
