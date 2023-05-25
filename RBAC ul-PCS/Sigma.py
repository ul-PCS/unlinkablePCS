from charm.toolbox.pairinggroup import ZR
from charm.core.engine.util import objectToBytes
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from openpyxl import Workbook
from charm.core.engine.util import serializeDict,objectToBytes,serializeObject
from BG import BG
from Pedersen import PedCom

class  Sigma():
    def __init__(self, groupObj):
            global util, group 
            group = groupObj
            self.MultComm=Sigma.MultComm()
            self.PRFprove=Sigma.PRFprove()
    class Dlog():
        def Prove(self,x,w):
            (g, A) = x
            (a) = w
            r = group.random(ZR)
            R = g ** r
            c = group.hash(objectToBytes(A, group)+objectToBytes(R, group),ZR)
            z = r - c * a 
            return x, (z, R)
        def Verify(self,x, pi):
            (g, A) = x
            (z, R) = pi
            c = group.hash(objectToBytes(A, group)+objectToBytes(R, group),ZR)
            return R == (g ** z) * (A**c)
    


    class ElGamal():
        def Prove(self,pp,x,w):
            (ct1,ct2,ek,cm,G,H) = x
            (r,m,e) = w
            r1,r2,r3 = group.random(ZR), group.random(ZR), group.random(ZR)
            R1 = pp['G1'] ** r1; R2 = (pp['G1']**r2)* ek**r1; R3 = (G**r2) * H**r3
            c = group.hash(objectToBytes(ct1, group)+objectToBytes(ct2, group)+objectToBytes(cm, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(R3, group),ZR)
            z1 = r1 - c * r; z2 = r2 - c * m; z3 = r3 - c * e
            return (z1,z2,z3,R1,R2,R3)
        
        def Verify(self,pp,x,pi):
            (ct1,ct2,ek,cm,G,H) = x
            (z1,z2,z3,R1,R2,R3) = pi
            c = group.hash(objectToBytes(ct1, group)+objectToBytes(ct2, group)+objectToBytes(cm, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(R3, group),ZR)
            if R1 == (ct1 ** c) * (pp['G1'] ** z1) and R2 == (pp['G1'] ** z2) * (ek ** z1) * (ct2 ** c) and \
                    R3 == (G ** z2) * (H ** z3) * (cm ** c):
                return 1
            else:
                return 0    

   
    class MultComm():
        def Prove(x,w):
            (x1,x2,x3,e1,e2,e3)=w
            (cm1,cm2,cm3,G,H)=x
            r1,r2,r3 = group.random(ZR), group.random(ZR), group.random(ZR)
            s, s1,s2,s3 = group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR)
            R1 = (G**r1)* (H**s1); R2 = (G**r2)* (H**s2); R3 = (G**r3)* (H**s3); R = (cm1**r2)* (H**s)
            e = e3 - e1 * x2
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+objectToBytes(cm3, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(R3, group)+objectToBytes(R, group),ZR)
            z1 = r1 - (c* x1); z2 = r2 - (c* x2); z3 = r3 - (c* x3)
            t1 = s1 - (c* e1); t2 = s2 - (c* e2); t3 = s3 - (c* e3); t = s - c * e
            return (z1,z2,z3,t1,t2,t3,t,R1,R2,R3,R)
        def Verify(x,pi):
            (cm1,cm2,cm3,G,H)=x
            (z1,z2,z3,t1,t2,t3,t,R1,R2,R3,R)=pi
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+objectToBytes(cm3, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(R3, group)+objectToBytes(R, group),ZR)
            return R1 == (G ** z1) * (H ** t1) * (cm1 ** c) and R2 == (G ** z2) * (H ** t2) * (cm2 ** c) and \
                    R3 == (G ** z3) * (H ** t3) * (cm3 ** c) and R == (cm3 ** c) * (cm1 ** z2) * (H ** t)         

    class PRFprove():
        def Prove(self,x,w):
            (X,k,e1,e2,e3) = w
            (ID,cm1,cm2,cm3,G,H) = x
            x1 = (cm1*cm2,ID,G,G,H)
            w1 = (X+k,1/(X+k),1,e1+e2,0,0)
            pi1 = Sigma.MultComm.Prove(x1,w1)
            return x, pi1
        def Verify(self,x,pi):
            (ID,cm1,cm2,cm3,G,H) = x
            x1 = (cm1*cm2,ID,G,G,H)
            return Sigma.MultComm.Verify(x1,pi)   


    class Bridging():
        def Prove(self,x,w):
            (m,e1,e2) = w
            (cm1, cm2, G1, H1, G2, H2) = x
            r1,r2,r3 = group.random(ZR), group.random(ZR), group.random(ZR)
            R1 = (G1**r1)* (H1**r1); R2 = (G2**r1)* (H2**r3)
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(G1, group)+objectToBytes(H1, group)+\
                        objectToBytes(G2, group)+objectToBytes(H2, group),ZR)
            z1 = r1 - (c* m); z2 = r2 - (c* e1); t = r3 - (c* e2)
            pi=(z1,z2,t,R1,R2)
            return x, pi
        def Verify(self,x,pi):
            (z1,z2,t,R1,R2)= ()
            (cm1, cm2, G1, H1, G2, H2) = x
            c = group.hash(objectToBytes(cm1, group)+objectToBytes(cm2, group)+\
                    objectToBytes(R1, group)+objectToBytes(R2, group)+objectToBytes(G1, group)+objectToBytes(H1, group)+\
                        objectToBytes(G2, group)+objectToBytes(H2, group),ZR)
            return R1 == (cm1 ** c) * (G1 ** z1) * (H1 ** z2) and R2 == (cm2 ** c) * (G2 ** z1) * (H2 ** t) 