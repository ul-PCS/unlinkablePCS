from random import random
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2
from charm.toolbox.secretutil import SecretUtil
from charm.core.engine.util import objectToBytes
from BLS import BLS01 as DS
from BG import BG
from PRF import DY as PRF
from OT12 import OT as FE
from SPS import SPS
from GS import GS as NIZK
from Pedersen import PedCom as Com
from SPSEQ import SPSEQ as SEQ
from Sigma import Sigma
from Bulletproof import RangeProof
from Acc import ACC
from Pedersen import GPed

#from HVE import HVE08
groupObj = PairingGroup('BN254')
FE = FE(groupObj)
SEQ = SEQ(groupObj)
class UPCS():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)        
        group = groupObj
        self.ACC = ACC(groupObj)
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.PRF = PRF(groupObj)
        self.NIZK = NIZK(groupObj)
        self.Sigma = Sigma(groupObj)
        self.SPS = SPS(groupObj)
        self.RangeProof = RangeProof()
        self.Com = Com(groupObj)
        
        self.GPed = GPed(groupObj)
    
    def Setup(self,N):
        Gamma1={}; Gamma2={};BB_T={}; ck={}
        pp = BG.Gen(self.BG); h=group.random(G2)
        pp_com = Com.Setup(self.Com) # Can we do the setup in the GS file?
        CRS1, tpd1 = NIZK.Transpatent_Setup(self.NIZK,pp)
        CRS2, tpd2 = NIZK.Transpatent_Setup(self.NIZK,pp)
        (sk_sigA,vk_sigA) = SPS.keygen(self.SPS,pp,N+2)
        (sk_seq,vk_seq) = SEQ.keygen(pp,N+2) #For POK of FE ciphertext 
        param, gT, g2 = FE.G_IPE( pp,N) #OT12 pre setup
        mpk_fe, msk_fe = FE.Setup(param,N) #OT12 main setup
        for i in range(N):
            BB_T[i]=[group.init(G2,1)]*N
        
        for i in range(N):
            for j in range(N):
                BB_T[i][j]=mpk_fe['BB'][j][i]
        for i in range(N):
            ck[i]=[h]; ck[i].extend(BB_T[i])

        #Gamma1[1]=[[1,0],[0,-1]]
        #Gamma1[2]=[[1,0],[0,-1]]
        #Gamma2[1]=[[1 if i==j else 0 for j in range(N)] for i in range(N)]; Gamma2[1][N-1][N-1]=-1
        #Gamma2[2]=[[1 if i==j else 0 for j in range(N+4)] for i in range(N+4)]; Gamma2[2][N+3][N+3]=-1
        msk={'sk_sigA':sk_sigA, 'msk_fe': msk_fe, 'sk_seq':sk_seq}
        mpk={'pp':pp, 'pp_com':pp_com, 'CRS1':CRS1, 'CRS2':CRS2, 'vk_sigA':vk_sigA,\
             'vk_seq':vk_seq, 'mpk_fe':mpk_fe, 'gT':gT, 'N':N, 'ck':ck, 'h':h, 'g2': g2}
        return (msk, mpk)


    def KeyGen(self,mpk,msk,x):
        seed = group.random(); pp = mpk['pp']
        (A_sd,alpha_sd) = ACC.Create(self.ACC, pp)
        w_sd = ACC.Add(self.ACC,pp,A_sd,alpha_sd,seed)
        (sk_sig,vk_sig) = DS.keygen(self.DS,pp)
        aux1 = [pp['G1']**seed,vk_sig]
        for i in range(len(x)):
            aux1.append(pp['G1']**x[i])
        sk_fe = FE.KeyGen(mpk['mpk_fe'],msk['msk_fe'],x)
        aux2 = [pp['G1']**seed]
        for i in range(len(sk_fe)):
            aux2.append(sk_fe[i])
        sigma_sig1 = SPS.sign(self.SPS,pp,msk['sk_sigA'],aux1)
        sigma_sig2 = SPS.sign(self.SPS,pp,msk['sk_sigA'],aux2)

        n = len(x); N=4*n+2; C={}; Phi={}; r_C={}; r_Phi={}
        vec = [group.init(ZR,0)]; vec.extend(x); vec.extend([group.init(ZR,0)]*(3*n+1))
        
        phi=[group.init(ZR,0)]*N; phi[0]=1; phi[n+1]=group.random(); phi[N-1]=group.random()
        
        for j in range(N):
            r_C[j] = group.random()
            C[j] = GPed.Com(self.GPed,mpk['ck'][j],vec,r_C[j])
            r_Phi[j] = group.random()
            Phi[j] = GPed.Com(self.GPed,mpk['ck'][j],phi,r_Phi[j])
        C_sign= [A_sd,pp['G2']]
        for i in range(len(C)):
            C_sign.append(C[i])
        sigma_FE = SEQ.sign(pp,msk['sk_seq'],C_sign)

        usk={'seed':seed,'sk_sig':sk_sig,'vk_sig':vk_sig,'sk_fe':sk_fe,
             'sigma_sig1':sigma_sig1,'sigma_sig2':sigma_sig2,'x':x, 'w_sd':w_sd}
        ct_proof={'C':C, 'C_sign':C_sign, 'sigma_FE':sigma_FE, 'r_C':r_C, 'r_phi':r_Phi, 'phi':phi, 'Phi':Phi}
        sk=[usk,-1,"perp",ct_proof]
        return UPCS.RandKey(self,mpk,sk)
    

    def RandKey(self,mpk,sk):
        pp = mpk['pp']; pp_com=mpk['pp_com']; X=sk[1]+1; GS_proof={}; GS_comX={}; GS_comY={}
        Final={};c_x={}; R={}

        #PRF and its proof
        ID = PRF.Gen(self.PRF,pp,sk[0]['seed'],sk[1]+1)
        e1, e2, e3 =group.random(), group.random(), group.random()
        cm1 = Com.com(self.Com,pp_com,X,e1)
        cm2 = Com.com(self.Com,pp_com,sk[0]['seed'],e2)
        cm3 = Com.com(self.Com,pp_com,X+sk[0]['seed'],e3)
        w = (X,sk[0]['seed'],e1,e2,e3)
        x = (ID,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
        x_prf, pi_prf = Sigma.PRFprove.Prove(self.Sigma,x,w)

        #range_proof
        (v, n, g, h, gs, hs, gamma, u, CURVE, seeds, V) = RangeProof.Setup(self.RangeProof , 2 ** 16 - 1, 16)
        proof = RangeProof.RanProve(self.RangeProof, v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        rp = (V, g, h, gs, hs, u, proof, seeds)
 
        omega = group.random(); Final={};c_x={}; R={}
        C_P, sigma_P = SEQ.ChgRep(pp,sk[3]['C_sign'],sk[3]['sigma_FE'],omega)
        
        # Proof of A_sd
        x = [pp['G1']**(-1), sk[0]['w_sd'], sk[0]['w_sd']]
        y = [C_P[1], C_P[0], C_P[1]**sk[0]['seed']]
        c_a = [pp['G1']**(-1), None, None]
        c_b = [C_P[1], C_P[0], None]

        GS_comX[1], GS_comY[1], r, s = NIZK.commit(self.NIZK,mpk['CRS1'],x,y,c_a,c_b)
        GS_proof[1] = NIZK.prove(self.NIZK,mpk['CRS1'],x,r,s,GS_comY[1])


        #Signature proof
        (sk_sig,vk_sig) = DS.keygen(self.DS,pp)
        sigma_ctr = DS.sign(self.DS,pp,sk[0]['sk_sig'],[ID,vk_sig])
        x = [sk[0]['vk_sig'], pp['G1']**(-1)]
        y = [group.hash(objectToBytes([ID,vk_sig], group), G2),sigma_ctr]
        c_a = [None, pp['G1']]
        c_b = [group.hash(objectToBytes([ID,vk_sig], group), G2), None]
        
        
        GS_comX[2], GS_comY[2], r, s = NIZK.commit(self.NIZK,mpk['CRS1'],x,y,c_a,c_b)
        GS_proof[2] = NIZK.prove(self.NIZK,mpk['CRS1'],x,r,s,GS_comY[2])

        
        # Proof of knowledge of encryption
        n=len(sk[0]['x']); N=4*n+2; vec={}
        for j in range(N):
            vec[j]=[0]; vec[j].extend(sk[0]['x']); vec[j].extend([0]*(3*n+1))
        for i in range(N):
            c_x[i] = sk[3]['phi'][i]+(vec[0][i]*omega)
            Final[i] = sk[3]['Phi'][i] * C_P[i+2] 
            R[i] = omega*sk[3]['r_C'][i] + sk[3]['r_phi'][i]
        
        
        
        x_fe={}; pi_fe={}
        for i in range(N):
            x_fe[i] = (sk[3]['Phi'][i], mpk['ck'][i])
            w_fe = (sk[3]['phi'], sk[3]['r_phi'][i])
            pi_fe[i] = Sigma.SingleGPC.Prove(self.Sigma,x_fe[i],w_fe)
        sk[1] += 1; sk[2] = sk_sig; 
        pk = {'ID':ID,'vk_sig':vk_sig,'ct':Final, 'comX':GS_comX, 'comY':GS_comY,\
                  'pi':GS_proof,'rp':rp, 'x_prf':x_prf, 'pi_prf':pi_prf, \
                    'sigma_P':sigma_P, 'Phi':sk[3]['Phi'], 'pi_fe':pi_fe, 'R':R, 'C_P':C_P}
        return sk,pk


    def Sign(self,mpk,sk,pk_R,mes):
        pp=mpk['pp']; (V, g, h, gs, hs, u, proof,seeds)=pk_R['rp']; X=sk[1]+1; pp_com=mpk['pp_com']
        GS_proof={}; GS_comX={}; GS_comY={}; N=mpk['N']; n=int((N-2)/4)
        ct_fe={}; z={}; ck={}; C_phi={}; C_P=[]
        for i in range(N):
            ct_fe[i]=((mpk['h']**(-pk_R['R'][i])) * pk_R['ct'][i])
        # To verify the knowledge of openings of GPC
        x_fe={}
        for j in range(N):
            x_fe[j] = (pk_R['Phi'][j], mpk['ck'][j])
        result_fe=[1 for j in range(N) if \
                   Sigma.SingleGPC.Verify(self.Sigma,x_fe[j],pk_R['pi_fe'][j])==True]
        result_z=True
        # To check the Zero positions in vector phi
        for j in range(N):
            (z[j], s, C_0) = pk_R['pi_fe'][j]
            #(C_phi[j],ck[j]) = pk_R['x_fe'][j]
            C_P.append(pk_R['ct'][j]/pk_R['Phi'][j])
            for i in [x for x in range(N) if x!=0 and x!=n+1 and x!=N-1]:
                if z[j][i]!=group.init(0,ZR):
                    result_z = False
        result_CP= [1 for j in range(N) if C_P[j]==pk_R['C_P'][j+2]]

        if FE.Dec(mpk['mpk_fe'], sk[0]['sk_fe'],ct_fe)==mpk['gT'] and \
        NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY']) == True and \
                RangeProof.RanVerify(self.RangeProof,V, g, h, gs, hs, u, proof,seeds) and \
                    Sigma.PRFprove.Verify(self.Sigma,pk_R['x_prf'],pk_R['pi_prf']) and \
                        result_fe==[1]*N and result_z==True and result_CP==[1]*N and \
                            SEQ.verify(pp,mpk['vk_seq'],pk_R['sigma_P'],pk_R['C_P']):
            #PRF and its proof
            
            ID_S = PRF.Gen(self.PRF,pp,sk[0]['seed'],sk[1]+1)
            e1, e2, e3 = group.random(), group.random(), group.random()
            cm1 = Com.com(self.Com,pp_com,X,e1)
            cm2 = Com.com(self.Com,pp_com,sk[0]['seed'],e2)
            cm3 = Com.com(self.Com,pp_com,X+sk[0]['seed'],e3)
            w = (X,sk[0]['seed'],e1,e2,e3)
            x = (ID_S,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
            x_prf, pi_prf = Sigma.PRFprove.Prove(self.Sigma,x,w)
            
            c_b=[]
            # The SPS of FE.Dec(sk_x,ct_R)=g_T
            x = []; y=[]
            for i in range(len(sk[0]['sk_fe'])):
                x.append(sk[0]['sk_fe'][i])
                y.append(ct_fe[i])
            c_a = [None]*N
            x.append(pp['G1']); y.append(mpk['g2']**(-1))
            c_a.append(mpk['g2']**(-1))
            c_b = y
        
            GS_comX[1], GS_comY[1], r, s = NIZK.commit(self.NIZK,mpk['CRS2'],x,y,c_a,c_b)
            GS_proof[1] = NIZK.prove(self.NIZK,mpk['CRS2'],x,r,s,GS_comY[1])
            

            
            # The SPS of seed and sk_fe
            c_b = []
            x = [pp['G1']**sk[0]['seed']]; y=[mpk['vk_sigA'][0]]
            for i in range(len(sk[0]['sk_fe'])):
                x.append(sk[0]['sk_fe'][i])
                y.append(mpk['vk_sigA'][i+1])
            x.extend([sk[0]['sigma_sig2']['R'], sk[0]['sigma_sig2']['S'], pp['G1']])
            c_b.extend(y)
            c_a = [None]*(N+3); c_a.append(pp['G1'])
            c_b.extend([None, pp['G2'], None])
            y.extend([sk[0]['sigma_sig2']['T']**(-1), pp['G2'], sk[0]['sigma_sig2']['T']**(-1)])
            
            
            GS_comX[2], GS_comY[2], r, s = NIZK.commit(self.NIZK,mpk['CRS2'],x,y,c_a,c_b)
            GS_proof[2] = NIZK.prove(self.NIZK,mpk['CRS2'],x,r,s,GS_comY[2])
            
            sigma = DS.sign(self.DS,pp,sk[2],[mes,pk_R['ID']])
            pi={'pi':GS_proof, 'comX':GS_comX, 'comY':GS_comY, 'x_prf':x_prf, 'pi_prf':pi_prf}
        else:
            print("There is no link")
            sigma="perp"; pi="perp"
        return {'sigma':sigma,'pi':pi}

    def verify(self,mpk,pk_S,pk_R,mes,sigma):
        pp = mpk['pp']; N=mpk['N']; n=int((N-2)/4)
        pi_s = sigma['pi']
        ct_feR={}; zR={}; ckR={}; C_phiR={}; C_PR=[]; x_feR={}; x_feS={}
        for i in range(N):
            ct_feR[i]=((mpk['h']**(-pk_R['R'][i])) * pk_R['ct'][i])
            x_feR[i] = (pk_R['Phi'][i], mpk['ck'][i])
        # To verify the knowledge of openings of GPC
        result_feR=[1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma,x_feR[j],pk_R['pi_fe'][j])==True]
        result_zR=True
        # To check the Zero positions in vector phi
        for j in range(N):
            (zR[j], s, C_0) = pk_R['pi_fe'][j]
            #(C_phiR[j],ckR[j]) = pk_R['x_fe'][j]
            C_PR.append(pk_R['ct'][j]/pk_R['Phi'][j])
            for i in [x for x in range(N) if x!=0 and x!=n+1 and x!=N-1]:
                if zR[j][i]!=group.init(0,ZR):
                    result_zR = False
        result_CPR= [1 for j in range(N) if C_PR[j]==pk_R['C_P'][j+2]]

        ct_feS={}; zS={}; ckS={}; C_phiS={}; C_PS=[]
        for i in range(N):
            ct_feS[i] = ((mpk['h']**(-pk_S['R'][i])) * pk_S['ct'][i])
            x_feS[i] = (pk_S['Phi'][i], mpk['ck'][i])
        # To verify the knowledge of openings of GPC
        result_feS=[1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma,x_feS[j],pk_S['pi_fe'][j])==True]
        result_zS=True
        # To check the Zero positions in vector phi
        for j in range(N):
            (zS[j], s, C_0) = pk_S['pi_fe'][j]
            #(C_phiS[j],ckS[j]) = pk_S['x_fe'][j]
            C_PS.append(pk_S['ct'][j]/pk_S['Phi'][j])
            for i in [x for x in range(N) if x!=0 and x!=n+1 and x!=N-1]:
                if zS[j][i] != group.init(0,ZR):
                    result_zS = False
        result_CPS= [1 for j in range(N) if C_PS[j]==pk_S['C_P'][j+2]]


        (V_S, g_S, h_S, gs_S, hs_S, u_S, proof_S, seeds_S) = pk_S['rp']
        (V_R, g_R, h_R, gs_R, hs_R, u_R, proof_R, seeds_R) = pk_R['rp']

        if NIZK.verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY'])==True and \
            NIZK.verify(self.NIZK,pp,mpk['CRS1'],pk_S['pi'],pk_S['comX'],pk_S['comY'])==True and \
                RangeProof.RanVerify(self.RangeProof,V_S, g_S, h_S, gs_S, hs_S, u_S, proof_S, seeds_S) and \
                    RangeProof.RanVerify(self.RangeProof,V_R, g_R, h_R, gs_R, hs_R, u_R, proof_R, seeds_R) and \
                        Sigma.PRFprove.Verify(self.Sigma,pk_S['x_prf'],pk_S['pi_prf']) and \
                            Sigma.PRFprove.Verify(self.Sigma,pk_R['x_prf'],pk_R['pi_prf']) and \
                                result_feR == [1]*N and result_zR and result_CPR==[1]*N and \
                            SEQ.verify(pp,mpk['vk_seq'],pk_R['sigma_P'],pk_R['C_P']) and \
                                result_feS == [1]*N and result_zS and result_CPS==[1]*N and \
                            SEQ.verify(pp,mpk['vk_seq'],pk_S['sigma_P'],pk_S['C_P']):
                                print("Valid sender's and receiver's public key\n")
                                
        return DS.verify(self.DS,pp,pk_S['vk_sig'],sigma['sigma'],[mes,pk_R['ID']]) and \
            NIZK.verify(self.NIZK,pp,mpk['CRS2'],pi_s['pi'],pi_s['comX'],pi_s['comY']) ==True and \
            Sigma.PRFprove.Verify(self.Sigma,pk_R['x_prf'],pk_R['pi_prf'])

    def Batched_verify(self,mpk,pk_S,pk_R,mes,sigma):
        pp = mpk['pp']; N = mpk['N']; n = int((N-2)/4)
        pi_s = sigma['pi']
        ct_feR = {}; zR = {}; ckR = {}; C_phiR = {}; C_PR=[]; x_feR={}; x_feS={}
        for i in range(N):
            ct_feR[i] = ((mpk['h']**(-pk_R['R'][i])) * pk_R['ct'][i])
            x_feR[i] = (pk_R['Phi'][i], mpk['ck'][i])
        # To verify the knowledge of openings of GPC
        result_feR = [1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma,x_feR[j],pk_R['pi_fe'][j])==True]
        result_zR = True
        # To check the Zero positions in vector phi
        for j in range(N):
            (zR[j], s, C_0) = pk_R['pi_fe'][j]
            #(C_phiR[j],ckR[j]) = pk_R['x_fe'][j]
            C_PR.append(pk_R['ct'][j]/pk_R['Phi'][j])
            for i in [x for x in range(N) if x!=0 and x!=n+1 and x!=N-1]:
                if zR[j][i] != group.init(0,ZR):
                    result_zR = False
        result_CPR = [1 for j in range(N) if C_PR[j] == pk_R['C_P'][j+2]]

        ct_feS = {}; zS = {}; ckS = {}; C_phiS = {}; C_PS = []
        for i in range(N):
            ct_feS[i]=((mpk['h']**(-pk_S['R'][i])) * pk_S['ct'][i])
            x_feS[i] = (pk_S['Phi'][i], mpk['ck'][i])
        # To verify the knowledge of openings of GPC
        result_feS=[1 for j in range(N) if Sigma.SingleGPC.Verify(self.Sigma,x_feS[j],pk_S['pi_fe'][j])==True]
        result_zS=True
        # To check the Zero positions in vector phi
        for j in range(N):
            (zS[j], s, C_0) = pk_S['pi_fe'][j]
            #(C_phiS[j],ckS[j]) = pk_S['x_fe'][j]
            C_PS.append(pk_S['ct'][j]/pk_S['Phi'][j])
            for i in [x for x in range(N) if x!=0 and x!=n+1 and x!=N-1]:
                if zS[j][i]!=group.init(0,ZR):
                    result_zS = False
        result_CPS= [1 for j in range(N) if C_PS[j]==pk_S['C_P'][j+2]]


        (V_S, g_S, h_S, gs_S, hs_S, u_S, proof_S, seeds_S) = pk_S['rp']
        (V_R, g_R, h_R, gs_R, hs_R, u_R, proof_R, seeds_R) = pk_R['rp']

        if NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_R['pi'],pk_R['comX'],pk_R['comY']) == True and \
            NIZK.Batched_verify(self.NIZK,pp,mpk['CRS1'],pk_S['pi'],pk_S['comX'],pk_S['comY']) == True and \
                RangeProof.RanVerify(self.RangeProof,V_S, g_S, h_S, gs_S, hs_S, u_S, proof_S, seeds_S) and \
                    RangeProof.RanVerify(self.RangeProof,V_R, g_R, h_R, gs_R, hs_R, u_R, proof_R, seeds_R) and \
                        Sigma.PRFprove.Verify(self.Sigma,pk_S['x_prf'],pk_S['pi_prf']) and \
                            Sigma.PRFprove.Verify(self.Sigma,pk_R['x_prf'],pk_R['pi_prf']) and \
                                result_feR==[1]*N and result_zR and result_CPR==[1]*N and \
                            SEQ.verify(pp,mpk['vk_seq'],pk_R['sigma_P'],pk_R['C_P']) and \
                                result_feS==[1]*N and result_zS and result_CPS==[1]*N and \
                            SEQ.verify(pp,mpk['vk_seq'],pk_S['sigma_P'],pk_S['C_P']):
                                print("Valid sender's and receiver's public key\n")
                                
        return DS.verify(self.DS,pp,pk_S['vk_sig'],sigma['sigma'],[mes,pk_R['ID']]) and \
            NIZK.Batched_verify(self.NIZK,pp,mpk['CRS2'],pi_s['pi'],pi_s['comX'],pi_s['comY']) == True and \
            Sigma.PRFprove.Verify(self.Sigma,pk_R['x_prf'],pk_R['pi_prf'])

