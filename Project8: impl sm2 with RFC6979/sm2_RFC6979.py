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
        print("验证通过!")
        return True

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
    dA = key[0]
    PA = key[1]
    xA = key[1][0]
    yA = key[1][1]
    dn = libnum.xgcd(1 + dA, n)[0]
    #print("dA: ",dA)
    #print("PA: ",PA,"\n\n")

    time1 = time.time()
    M = 'sdu_cst'
    IDA = '202000141016'
    print("M: ",M)
    print("ID_A: ",IDA)

    sig = sign(M,IDA,G,PA,dA,a,b,q)
    print("signature: ",sig)
    verify(IDA,M,sig[0],sig[1],PA,a,b,q)

    time2 = time.time()
    print("time: {:.8f}".format(time2-time1),"s")