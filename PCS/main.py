from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.secretutil import SecretUtil
from BLS import BLS01 as DS
from BG import BG
from SPS import SPS
from GS import GS as NIZK
from OT12 import OT as FE
groupObj = PairingGroup('BN254')



class PCS():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)        
        group = groupObj
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.NIZK = NIZK(groupObj)
        self.SPS = SPS(groupObj)
        self.FE = FE(groupObj)
                        
    def Setup(self,N):
        pp = BG.Gen(self.BG)
        CRS, tpd = NIZK.Transpatent_Setup(self.NIZK,pp)
        param, gT, g2 = FE.G_IPE(self.FE,pp,N) #OT12 pre setup
        mpk_fe, msk_fe = FE.Setup(self.FE,param,N) #OT12 main setup
        (sk_pub,vk_pub) = DS.keygen(self.DS,pp)
        (sk_priv,vk_priv) = SPS.keygen(self.SPS,pp,N+1)
        msk={'msk_fe': msk_fe, 'sk_pub':sk_pub,'sk_priv':sk_priv}
        mpk={'pp':pp, 'CRS':CRS, 'vk_pub':vk_pub,'vk_priv':vk_priv, 'mpk_fe':mpk_fe,\
             'g2':g2, 'gT':gT, 'N':N}
        return (msk, mpk)



 

    def KeyGen(self,mpk,msk,x):
        pp = mpk['pp']
        (sk_P,vk_P) = DS.keygen(self.DS,pp)
        ct_fe = FE.Enc(self.FE,mpk['mpk_fe'],x)
        sk_fe = FE.KeyGen(self.FE,mpk['mpk_fe'],msk['msk_fe'],x)
        mes_pub = [vk_P,ct_fe]
        sigma_pub = DS.sign(self.DS, pp,msk['sk_pub'],mes_pub)
        mes_priv = [vk_P]
        for key, value in sk_fe.items():
            mes_priv.append(value)
        sigma_priv = SPS.sign(self.SPS,pp,msk['sk_priv'],mes_priv)
        sk = {'vk_P':vk_P, 'sk_P':sk_P, 'sk_fe':sk_fe, 'sigma_priv':sigma_priv}
        pk = {'vk_P':vk_P, 'ct':ct_fe, 'sigma_pub':sigma_pub}
        return sk,pk


    def Sign(self,mpk,sk,pk_R,M):
        pp = mpk['pp']; GS_proof = {}; GS_comX = {}; GS_comY = {}; N = mpk['N']
        if  DS.verify(self.DS,pp,mpk['vk_pub'],pk_R['sigma_pub'],[pk_R['vk_P'],pk_R['ct']]) == 1 and \
            FE.Dec(self.FE,mpk['mpk_fe'],sk['sk_fe'],pk_R['ct']) == mpk['gT']:
            # The SPS of FE.Dec(sk_x,ct_R)=g_T
            x = []; y = []
            for i in range(len(sk['sk_fe'])):
                x.append(sk['sk_fe'][i])
                y.append(pk_R['ct'][i])
            c_a = [None]*N
            x.append(pp['G1']); y.append(mpk['g2']**(-1))
            c_a.append(mpk['g2']**(-1))
            c_b = y

            GS_comX[1], GS_comY[1], r, s = NIZK.commit(self.NIZK,mpk['CRS'],x,y,c_a,c_b)
            GS_proof[1] = NIZK.prove(self.NIZK,mpk['CRS'],x,r,s,GS_comY[1])

            # The SPS of seed and sk_fe
            c_b = []
            x = [sk['vk_P']]; y = [mpk['vk_priv'][0]]
            for i in range(len(sk['sk_fe'])):
                x.append(sk['sk_fe'][i])
                y.append(mpk['vk_priv'][i+1])
            x.extend([sk['sigma_priv']['R'], sk['sigma_priv']['S'], pp['G1']])
            c_b.extend(y)
            c_a = [None]*(N+3); c_a.append(pp['G1'])
            y.extend([sk['sigma_priv']['T']**(-1), pp['G2'], sk['sigma_priv']['T']**(-1)])
            c_b.extend([None, pp['G2'], None])

            GS_comX[2], GS_comY[2], r, s = NIZK.commit(self.NIZK,mpk['CRS'],x,y,c_a,c_b)
            GS_proof[2] = NIZK.prove(self.NIZK,mpk['CRS'],x,r,s,GS_comY[2])

            sigma = DS.sign(self.DS, pp,sk['sk_P'],[M,pk_R['vk_P']])
            pi={'pi':GS_proof, 'comX':GS_comX, 'comY':GS_comY}
        else:
            print("There is no link")
            sigma="perp"; pi="perp"
        return {'sigma':sigma,'pi':pi}

    def verify(self,mpk,pk_S,pk_R,M,sigma):
        pp = mpk['pp']
        pi_s = sigma['pi']
        return DS.verify(self.DS, pp,pk_S['vk_P'],sigma['sigma'],[M,pk_R['vk_P']]) and \
        DS.verify(self.DS,pp,mpk['vk_pub'],pk_S['sigma_pub'],[pk_S['vk_P'],pk_S['ct']]) and \
        DS.verify(self.DS,pp,mpk['vk_pub'],pk_R['sigma_pub'],[pk_R['vk_P'],pk_R['ct']]) and \
            NIZK.verify(self.NIZK,pp,mpk['CRS'],pi_s['pi'],pi_s['comX'],pi_s['comY'])
                
    def Batched_verify(self,mpk,pk_S,pk_R,M,sigma):
        pp = mpk['pp']
        pi_s = sigma['pi']
        return DS.verify(self.DS, pp,pk_S['vk_P'],sigma['sigma'],[M,pk_R['vk_P']]) and \
        DS.verify(self.DS,pp,mpk['vk_pub'],pk_S['sigma_pub'],[pk_S['vk_P'],pk_S['ct']]) and \
        DS.verify(self.DS,pp,mpk['vk_pub'],pk_R['sigma_pub'],[pk_R['vk_P'],pk_R['ct']]) and \
            NIZK.Batched_verify(self.NIZK,pp,mpk['CRS'],pi_s['pi'],pi_s['comX'],pi_s['comY'])

