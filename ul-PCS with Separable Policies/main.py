from charm.toolbox.pairinggroup import PairingGroup,ZR,G2
from charm.core.engine.util import objectToBytes
from BLS import BLS01 as DS
from BG import BG
from policy import Policy
from PRF import DY as PRF
from GS import GS as NIZK
from SPS import SPS
from Bulletproof import RangeProof
from Sigma import Sigma
from Pedersen import PedCom as Com
from ElGamal import ElGamal as ENC

groupObj = PairingGroup('BN254')
class UPCS():
    def __init__(self, groupObj):
        global util, group       
        group = groupObj
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.Policy = Policy()
        self.PRF = PRF(groupObj)
        self.NIZK = NIZK(groupObj)
        self.Sigma= Sigma(groupObj)
        self.SPS = SPS(groupObj)
        self.RangeProof = RangeProof()
        self.Com = Com(groupObj)
        self.Enc = ENC(groupObj)
                         
    def Setup(self):
        Gamma1={}; Gamma2={}
        pp = BG.Gen(self)
        CRS1, tpd1 = NIZK.Transpatent_Setup(self,pp)
        CRS2, tpd2 = NIZK.Transpatent_Setup(self,pp)
        pp_com = Com.Setup(self)
        (sk_sigAS,vk_sigAS) = SPS.keygen(self,pp,3)
        (sk_sigAR,vk_sigAR) = SPS.keygen(self,pp,3)
        (dk_encA,ek_encA) = ENC.keygen(self,pp)
        #Gamma1[1]=[[1 if i==j else 0 for j in range(5)] for i in range(5)]; Gamma1[1][4][4]=-1
        #Gamma1[2]=[[1,0],[0,-1]]
        #Gamma2[1]=[[1 if i==j else 0 for j in range(6)] for i in range(6)]; Gamma2[1][5][5]=-1
        #Gamma2[2]=[[1 if i==j else 0 for j in range(4)] for i in range(4)]; Gamma2[2][3][3]=-1
        msk={'sk_sigAS':sk_sigAS, 'sk_sigAR':sk_sigAR, 'dk_encA': dk_encA}
        mpk={'pp':pp, 'CRS1':CRS1, 'CRS2':CRS2, 'vk_sigAS':vk_sigAS,\
              'vk_sigAR':vk_sigAR, 'ek_encA':ek_encA, 'pp_com':pp_com}
        return (msk, mpk)

    def KeyGen(self,mpk,msk,x,F):
        seed=group.random()
        if F['R'][x]==1:
            m = group.init(ZR, 1); m_x = mpk['pp']['G1']**m
            sigma_sigR = SPS.sign(self,mpk['pp'],msk['sk_sigAR'],[mpk['pp']['G1']**seed, msk['dk_encA']])
        else:
            m = group.init(ZR, 0); m_x = mpk['pp']['G1']**m
            sigma_sigR = SPS.sign(self,mpk['pp'],msk['sk_sigAR'],[mpk['pp']['G1']**seed, msk['ek_encA']])
        (sk_sig,vk_sig) = DS.keygen(self,mpk['pp'])
        if F['S'][x]==1:
            sigma_sigS = SPS.sign(self,mpk['pp'],msk['sk_sigAS'],[mpk['pp']['G1']**seed, vk_sig, m_x])
            usk = {'seed':seed,'sk_sig':sk_sig,'vk_sig':vk_sig,'sigma_sigS':sigma_sigS,\
                   'sigma_sigR':sigma_sigR,'m':m_x,'dk_encA': msk['dk_encA']}
        else:
            usk = {'seed':seed,'sk_sig':sk_sig,'vk_sig':vk_sig,\
                   'sigma_sigR':sigma_sigR,'m':m_x}
        sk = [usk,-1,"perp","perp","perp"]
        return UPCS.RandKey(self,mpk,sk)
    

    def RandKey(self,mpk,sk):
        pp=mpk['pp']; pp_com=mpk['pp_com']; GS_proof={}; GS_comX={}; GS_comY={}
        #PRF and its proof
        pp=mpk['pp']; X=sk[1]+1
        ID = PRF.Gen(self,pp_com,sk[0]['seed'],X)
        e1, e2, e3 =group.random(), group.random(), group.random()
        cm1 = Com.com(self,pp_com,X,e1)
        cm2 = Com.com(self,pp_com,sk[0]['seed'],e2)
        cm3 = Com.com(self,pp_com,X+sk[0]['seed'],e3)
        w = (X,sk[0]['seed'],e1,e2,e3)
        x = (ID,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
        x_prf, pi_prf = Sigma.PRFprove.Prove(x,w)
        #range_proof
        (v, n, g, h, gs, hs, gamma, u, CURVE, seeds, V)=RangeProof.Setup(self.RangeProof, 2 ** 16 - 1, 16)
        proof = RangeProof.RanProve(self.RangeProof, v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        rp=(V, g, h, gs, hs, u, proof,seeds)

        (sk_sig,vk_sig) = DS.keygen(self,pp)
        sigma_sig = DS.sign(self,pp,sk[0]['sk_sig'],[vk_sig,ID])
        sk[3] = sigma_sig
        ct,r = ENC.Enc(self,pp,mpk['ek_encA'],sk[0]['m']); sk[4]=r
        # Proof of knowledge of encryption
        tau = group.random()
        cm = Com.com(self,pp_com,group.init(ZR, 1),tau)
        x_elgamal = (ct['c1'], ct['c2'],mpk['ek_encA'],cm,pp_com['G'],pp_com['H'])
        w_elgamal = (r,group.init(ZR, 1),tau)
        pi_elgamal = Sigma.ElGamal.Prove(pp,x_elgamal,w_elgamal)
        
        #SPS proof
        x = [pp['G1']**sk[0]['seed'], sk[0]['dk_encA'],sk[0]['sigma_sigR']['R'], sk[0]['sigma_sigR']['S'], pp['G1']]
        y = [mpk['vk_sigAR'][0],mpk['vk_sigAR'][1], sk[0]['sigma_sigR']['T']**(-1), pp['G2'], sk[0]['sigma_sigR']['T']**(-1)]
        c_a = [None, None, None, None, pp['G1']]
        c_b = [mpk['vk_sigAR'][0], mpk['vk_sigAR'][1], None, pp['G2'], None]
        
        GS_comX[1], GS_comY[1], r, s = NIZK.commit(self.NIZK,mpk['CRS1'],x,y,c_a,c_b)
        GS_proof[1] = NIZK.prove(self.NIZK,mpk['CRS1'],x,r,s,GS_comY[1])

        x = [sk[0]['vk_sig'], pp['G1']**(-1)]
        y = [group.hash(objectToBytes([vk_sig,ID], group), G2), sigma_sig]
        c_a = [None, pp['G1']**(-1)]
        c_b = [group.hash(objectToBytes([vk_sig,ID], group), G2), None]

        GS_comX[2], GS_comY[2], r, s = NIZK.commit(self.NIZK,mpk['CRS1'],x,y,c_a,c_b)
        GS_proof[2] = NIZK.prove(self.NIZK,mpk['CRS1'],x,r,s,GS_comY[2])

        sk[1] += 1; sk[2] = sk_sig; sk[3] = sigma_sig
        pk = {'ID':ID,'vk_sig':vk_sig,'ct':ct, 'comX':GS_comX, \
            'comY':GS_comY, 'pi':GS_proof,'rp':rp, 'x_prf':x_prf, 'pi_prf':pi_prf, 'pi_elgamal':pi_elgamal, 'x_elgamal':x_elgamal}
        return sk,pk


    def Sign(self,mpk,sk,pk_R,m):
        pp=mpk['pp']; pp_com=mpk['pp_com']; (V, g, h, gs, hs, u, proof,seeds)=pk_R['rp']; X=sk[1]+1
        GS_proof={}; GS_comX={}; GS_comY={}
        if 'dk_encA' in sk[0].keys() and \
            NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY'])!=True and \
            ENC.Dec(self,sk[0]['dk_encA'],pk_R['ct'])==pp['G1']**group.init(ZR, 1) and \
                RangeProof.RanVerify(self.RangeProof ,V, g, h, gs, hs, u, proof,seeds)==True and \
                    Sigma.PRFprove.Verify(pk_R['x_prf'],pk_R['pi_prf'])==1 and \
                        Sigma.ElGamal.Verify(pp,pk_R['x_elgamal'],pk_R['pi_elgamal'])==1:
                        print('The public key of the reciever is valid\n')
                        # To prove the knowledge of dk^A under the public ek^A
                        ins = (pp['G1'], mpk['ek_encA'])
                        wit = (sk[0]['dk_encA'])
                        x_dk, pi_dk = Sigma.Dlog.Prove(self.Sigma,ins,wit)
                        ID_S = PRF.Gen(self,pp_com,sk[0]['seed'],sk[1])
                        #PRF proof
                        e1, e2, e3 =group.random(), group.random(), group.random()
                        cm1 = Com.com(self,pp_com,X,e1)
                        cm2 = Com.com(self,pp_com,sk[0]['seed'],e2)
                        cm3 = Com.com(self,pp_com,X+sk[0]['seed'],e3)
                        w = (X,sk[0]['seed'],e1,e2,e3)
                        x = (ID_S,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
                        x_prf, pi_prf = Sigma.PRFprove.Prove(x,w)

                        #SPS proof
                        sigma = DS.sign(self,pp,sk[2],[m,pk_R['ID']])
                        x = [pp['G1']**sk[0]['seed'],sk[0]['vk_sig'] ,sk[0]['m'],sk[0]['sigma_sigS']['R'], sk[0]['sigma_sigS']['S'], pp['G1']]
                        y = [mpk['vk_sigAS'][0],mpk['vk_sigAS'][1],mpk['vk_sigAS'][2], sk[0]['sigma_sigS']['T']**(-1), pp['G2'], sk[0]['sigma_sigS']['T']**(-1)]
                        c_a = [None, None, None, None, None, pp['G1']]
                        c_b = [mpk['vk_sigAS'][0], mpk['vk_sigAS'][1], mpk['vk_sigAS'][2], None, pp['G2'], None]
                        
                        GS_comX[1], GS_comY[1], r, s = NIZK.commit(self.NIZK,mpk['CRS2'],x,y,c_a,c_b)
                        GS_proof[1] = NIZK.prove(self.NIZK,mpk['CRS2'],x,r,s,GS_comY[1])
                        
                        # The second SPS
                        x = [pp['G1']**group.init(ZR, 1), pp['G1']**(-1), pp['G1']**group.init(ZR, 1),pp['G1']**group.init(ZR, 1)]
                        y = [pp['G2'],pp['G2']**group.init(ZR, 1),pp['G2']**group.init(ZR, 1),pp['G2']**(-1)]
                        c_a = [None,pp['G1']**(-1),None,None]
                        c_b = [pp['G2'],None,None,pp['G2']**(-1)]
                        
                        GS_comX[2], GS_comY[2], r, s = NIZK.commit(self.NIZK,mpk['CRS2'],x,y,c_a,c_b)
                        GS_proof[2] = NIZK.prove(self.NIZK,mpk['CRS2'],x,r,s,GS_comY[2])

                        pi={'pi':GS_proof, 'comX':GS_comX, 'comY':GS_comY, \
                            'x_prf':x_prf, 'pi_prf':pi_prf, "x_dk":x_dk, "pi_dk":pi_dk}
        else:
            print("There is no link")
            sigma="perp"; pi="perp"
        return {'sigma':sigma,'pi':pi}

    def verify(self,mpk,pk_S,pk_R,m,sigma):
        pi_s=sigma['pi']; pp=mpk['pp']
        if NIZK.verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY']) and \
                NIZK.verify(self.NIZK,pp,mpk['CRS1'],pk_S['pi'],pk_S['comX'],pk_S['comY']) and \
                Sigma.Dlog.Verify(self.Sigma,pi_s['x_dk'],pi_s['pi_dk']):
            print("Valid sender's and receiver's public key\n")
            return DS.verify(self,mpk['pp'],pk_S['vk_sig'],sigma['sigma'],[m,pk_R['ID']]) and \
                NIZK.verify(self.NIZK,pp,mpk['CRS2'],pi_s['pi'],pi_s['comX'],pi_s['comY']) and \
                Sigma.PRFprove.Verify(pk_R['x_prf'],pk_R['pi_prf'])
    def Batched_verify(self,mpk,pk_S,pk_R,m,sigma):
        pi_s = sigma['pi']; pp = mpk['pp']
        if NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY']) and \
                NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_S['pi'],pk_S['comX'],pk_S['comY']) and \
                Sigma.Dlog.Verify(self.Sigma,pi_s['x_dk'],pi_s['pi_dk']):
            print("Valid sender's and receiver's public key\n")
            return DS.verify(self,mpk['pp'],pk_S['vk_sig'],sigma['sigma'],[m,pk_R['ID']]) and \
                NIZK.Batched_verify(self.NIZK,pp,mpk['CRS2'],pi_s['pi'],pi_s['comX'],pi_s['comY']) and \
                Sigma.PRFprove.Verify(pk_R['x_prf'],pk_R['pi_prf'])
