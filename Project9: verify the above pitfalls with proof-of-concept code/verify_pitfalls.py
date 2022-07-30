import hashlib
import random
import math
import libnum
import time
from gmssl import sm3, func
'''
sm2签名算法的实现
'''

# 椭圆曲线上点的加法
def funcadd(P, Q,a,q):
    #print("funcadd")
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]

    list1 = []  # 存放结果

    if x1 == x2 and y1 == q - y2:
        return False
    if x1 != x2:
        temp = libnum.xgcd(x2-x1,q)[0]
        lamda = ((y2 - y1) * temp) % q
    else:
        temp = libnum.xgcd(2*y1, q)[0]
        lamda = (((3 * x1 * x1 + a) % q) * temp) % q
    x3 = (lamda * lamda - x1 - x2) % q
    y3 = (lamda * (x1 - x3) - y1) % q

    list1.append(x3)
    list1.append(y3)
    return list1


# 椭圆曲线上的点乘
def funcmult(num, P,a,p):
    #print("funcmult")

    num = bin(num)[2:]
    qx, qy = P[0], P[1]
    Q = [qx, qy]
    for i in range(1, len(num)):
        Q = funcadd(Q, Q, a, p)
        if num[i] == '1':
            Q = funcadd(Q, P, a, p)
    return  Q



# 随机选k的签名和验证

#   密钥生成
def keyGen(P,a,p):
    #print("keygen")
    d = random.randrange(1, n - 1)
    while math.gcd(d + 1, n) != 1:  # 后续签名中s的生成需要求逆 故需互素
        d = random.randrange(1, n - 1)
    P_A = funcmult(d, P,a,p)
    return d, P_A


def precompute(ID_A, a,b,G,x_A, y_A):  # ID_A为a的ID x_A y_A为其私钥
    #print("pre")
    ENTL_A = len(ID_A)
    str_a = str(ENTL_A)+ID_A+hex(a)[2:]+hex(b)[2:]+hex(G[0])[2:]+hex(G[1])[2:]+hex(x_A)[2:]+hex(y_A)[2:]
    str_a = bytes(str_a,encoding='utf-8')
    Z_A = sm3.sm3_hash(func.bytes_to_list(str_a))
    return Z_A

def sign(M,ID_A,G,PA,dA,a,b,p):  # M为待签名的消息

    ZA = precompute(ID_A,a,b,G,PA[0],PA[1])
    #print("1")
    M_ = ZA + M
    str_m = bytes(M_,encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(str_m))
    #print("2")
    r = 0
    str_k = M + ID_A + hex(PA[0])[2:] + hex(PA[1])[2:]
    str_k = bytes(str_k,encoding='utf-8')
    str_k = sm3.sm3_hash(func.bytes_to_list(str_k))
    k1 = int(str_k,16)
    s = 0
    while (r==0 or ((r+k1)%n ==0) or s==0):

        k1 = random.randrange(1,n-1)
        kG = funcmult(k1,G,a,p)

        r = (int(e,16)+kG[0]) % n

        s = dn*(k1-r*dA)%n
    #print("3")
    return r,s,k1
def signwithsameK(M,ID_A,G,PA,dA,invd,a,b,p):  # M为待签名的消息

    ZA = precompute(ID_A,a,b,G,PA[0],PA[1])
    M_ = ZA + M
    str_m = bytes(M_,encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(str_m))
    k1 = 65535
    kG = funcmult(k1,G,a,p)
    r = (int(e,16)+kG[0]) % n
    s = invd*(k1-r*dA)%n
    return r,s

def verify(ID_A,M,r,s,PA,a,b,p):

    if r<1 or r>(n-1) or s<1 or s>(n-1):
        print("False!")
        return False

    ZA = precompute(ID_A, a, b, G, PA[0], PA[1])
    M_ = ZA + M
    #print("$")
    str_m = bytes(M_, encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(str_m))
    #print("%")
    t = (r + s)% n
    tem1 = funcmult(s,G,a,p)
    tem2 = funcmult(t,PA,a,p)
    point = funcadd(tem1,tem2,a,p)
    #print("7")
    R = (int(e,16) + point[0])%n

    if R==r:
        print("验证通过!\n")
        return True

# 泄露随机数k
def leakingtocaldA(k,r,s):
    tem = libnum.xgcd(s+r,n)[0]
    d = tem*(k-s) % n
    return d

# 重用随机数k
def reusingtocaldA(r1,s1,r2,s2):
    tem = libnum.xgcd(s1-s2+r1-r2,n)[0]
    return (s2*s1) * tem % n

# 不同用户使用相同k
def tworeusingtocald(r,s,k):
    tem = libnum.xgcd(s+r,n)[0]
    return (k-s) * tem % n

# ECDSA 签名算法
def Sign(d,m,n,P,a,q): # d:私钥 m:待签名消息 n:公钥的阶 P:基点 a:椭圆曲线参数 q:模数

    k1 = 65535
    p=funcmult(k1,P,a,q)
    r=p[0]%n  # 点的横坐标

    e=int(hashlib.sha256(m.encode()).hexdigest(),16) #消息m的哈希值
    t=libnum.xgcd(k1,n)[0]  # t 为k模n的逆

    s=(t*(e+d*r))%n

    return r,s

# sm2 与 ECDSA 使用相同的k和d 由签名求得私钥d
def twoalgoreusingtocald(r1,s1,r2,s2,e1):
    tem = libnum.xgcd(r1-s1*s2-s1*r2,n)[0]
    return (s1*s2-e1) * tem % n

def verifytithoutm(r,s,PA,e,a,b,p):
    if r<1 or r>(n-1) or s<1 or s>(n-1):
        print("False!")
        return False

    t = (r + s)% n
    tem1 = funcmult(s,G,a,p)
    tem2 = funcmult(t,PA,a,p)
    point = funcadd(tem1,tem2,a,p)

    R = (e + point[0])%n

    if R==r:
        print("验证通过!\n")
        return True
    else:
        print("验证失败!\n")

def forge(PA,a,p):
    u = random.randrange(1, n - 1)
    v = random.randrange(1, n - 1)
    r = (v - u) % n
    s = u
    X = funcadd(funcmult(u, G, a, p), funcmult(v, PA, a, p),a,p)
    e = (r - X[0]) % n
    return r, s, e

if __name__ == '__main__':
    # 基础参数
    q = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3  # 素数
    a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498  # 椭圆曲线参数
    b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
    x_G = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D  # 基点横纵坐标
    y_G = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
    n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7  # 阶

    q = int(q)
    a = int(a)
    b = int(b)
    x_G = int(x_G)
    y_G = int(y_G)
    n = int(n)

    G = [x_G, y_G]
    key = keyGen(G, a, q)
    keyB = keyGen(G, a, q)
    dA = key[0]
    PA = key[1]
    xA = key[1][0]
    yA = key[1][1]
    dB = keyB[0]
    PB = keyB[1]
    xB = keyB[1][0]
    yB = keyB[1][1]
    dn = libnum.xgcd(1 + dA, n)[0]
    dnB = libnum.xgcd(1 + dB, n)[0]
    #print("dA: ",dA)
    #print("PA: ",PA,"\n\n")

    #time1 = time.time()
    M = 'sdu_cst'
    M_ = 'pku_cst'
    IDA = '202000141016'
    IDB = '202000141046'
    print("M: ",M)
    print("ID_A: ",IDA)
    print("M_: ",M_)
    print("ID_B: ",IDB)
    sig = sign(M,IDA,G,PA,dA,a,b,q)
    print("signatureA: ",(sig[0],sig[1]),"\n")
    print("-------code to verify the sig -------")
    verify(IDA,M,sig[0],sig[1],PA,a,b,q)

    print("-------leaking k to cal d-------")
    trydA = leakingtocaldA(sig[2],sig[0],sig[1])
    #print(trydA)
    if dA == trydA:
        print(" leaking k to cal d : succeed!\n")

    print("-------reusing k to cal d-------")
    sig1 = signwithsameK(M, IDA, G, PA, dA,dn, a, b, q)
    sig2 = signwithsameK(M_, IDA, G, PA, dA,dn, a, b, q)
    redA = reusingtocaldA(sig1[0], sig1[1], sig2[0], sig2[1])
    if dA == trydA:
        print(" reusing k to cal d : succeed!\n")

    print("-------two users reusing k to cal d of the other-------")
    sig1 = signwithsameK(M, IDA, G, PA, dA, dn,a, b, q)
    sig2 = signwithsameK(M_, IDB, G, PB, dB,dnB, a, b, q)
    adB = tworeusingtocald(sig2[0],sig2[1],65535)
    bdA = tworeusingtocald(sig1[0],sig1[1],65535)
    if adB == dB:
        print(" Alice get the secret key of Bob!")
    else:
        print(" Alice does not get the secret key of Bob!")
    if bdA == dA:
        print(" Bob get the secret key of Alice!")
    else:
        print(" Bob does not get the secret key of Alice!")

    print("\n-------two algorithms reusing k and d to cal d-------")
    sig1 = signwithsameK(M, IDA, G, PA, dA, dn,a, b, q)
    sig2 = Sign(dA,M,n,G,a,q)
    e = int(hashlib.sha256(M.encode()).hexdigest(),16) #消息m的哈希值
    tad = twoalgoreusingtocald(sig2[0],sig2[1],sig1[0],sig1[1],e)
    if tad == dA:
        print("two algorithms reusing k and d to cal d: succeed!\n")
    else:
        print("two algorithms reusing k and d to cal d: false!\n")

    print("-------forge signature with verifying without m-------")
    forgesig = forge(PA,a,q)
    print("伪造签名：(r,s,e)\n ",forgesig)
    verifytithoutm(forgesig[0],forgesig[1],PA,forgesig[2],a,b,q)

    #time2 = time.time()
    #print("time: {:.8f}".format(time2-time1),"s")