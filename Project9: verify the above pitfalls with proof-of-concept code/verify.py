import hashlib
import random
import math
import libnum

'''
验证
泄露随机数k
重用随机数K
两个用户使用相同的k能够互推对方的私钥d
不验证消息m可伪造签名


'''

#首先在基于素数域的椭圆曲线上验证ECDSA代码的正确性
#参考网页:https://blog.csdn.net/qq_52428239/article/details/125033933

#a,b为方程系数，t为模数，为私钥，P(X,Y)为基点，即生成元，M为明文
# y^2=x^3+x+1
a = 1
b = 1
t = 23
n = 28 # 椭圆曲线上点的个数
G = [3,10]

    
#椭圆曲线上点的加法
def func_add(P,Q):
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    global a
    global b
    global t
    global k
    list1=[]  #存放结果
    if x1 == x2 and y1 == y2: #P=Q
        for i in range(500):
            if (2 * y1 * i - (3 * (x1 ** 2) + a)) % t == 0:  #计算P+Q中需要的参数，为了防止结果为负或小数，采用这种方式来计算
                k = i
                break
    else:  #P!=Q
        for i in range(500):
            if ((x2 - x1) * i - (y2 - y1)) % t == 0:
                k = i
                break
    #计算结果
    x3 = (k ** 2 - x1 - x2) % t
    y3 = (k * (x1 - x3) - y1) % t
    list1.append(x3)
    list1.append(y3)
    return list1

#椭圆曲线上的点乘
def func_mult(num,P):
    list=P #存放结果
    for i in range(num-1):
        list = func_add(list,P)
    return list

#生成密钥阶段
def generatekey(P):
    d = random.randrange(1,n-1) # d为私钥
    while math.gcd(d,n)!=1:
        d = random.randrange(1,n-1) # d为私钥  
    Q = func_mult(d,P) # Q为公钥
    return (Q,d)

#签名
def Sign(d,m,n,P): # d:私钥 m:待签名消息 n:公钥的阶 P:基点
    s = n
    while math.gcd(s,n)!=1:  #验证时需求s模n的逆 故s和n需互素
        k1=random.randrange(1,n-1)
        while math.gcd(k1,n)!=1:  #后续要求逆 故需互素
            k1=random.randrange(1,n-1)
        #print("k1",k1)
        p=func_mult(k1,P)
        #print(p)
        r=p[0]%n  # 点的横坐标

        e=int(hashlib.sha256(m.encode()).hexdigest(),16) #消息m的哈希值
        #print(e)
        t=libnum.xgcd(k1,n)[0]  # t 为k模n的逆
        #print(t)
        s=(t*(e+d*r))%n
        #if s==0:  # 如果s=0 则重新签名
         #   Sign(d,m,n,G)
    return (r,s)

#验证
def Verify(r,s,m,Q,P): # r,s为接收的签名值 m为接收的消息 Q为公钥 P为基点
    if not ((r>=1 and r<=(n-1)) and (s>=1 and s<=(n-1))):
        print("False!")
        return False
    e=int(hashlib.sha256(m.encode()).hexdigest(),16) #消息m的哈希值
    
    w=libnum.xgcd(s,n)[0]
    
    u1=(e*w)%n
    u2=(r*w)%n
    tem1=func_mult(u1,P)
    tem2=func_mult(u2,Q)
    X=func_add(tem1,tem2)
    print("Verify： ",X)
    if X[0]==0 and X[1]==0:
        print("False!")
        return False
    if ( X[0]%n ) == r:
        print("The signature is verified!")
        return True
    else :
        print("False!")
        return False

# 测试程序
def test():
    global key
    key = generatekey(G)
    print('key： ',key)
    m='Wanglei_202000141016'
    sig = Sign(key[1],m,n,G)
    print('sig： ',sig)
    Verify(sig[0],sig[1],m,key[0],G)

# 不带入消息m的签名验证算法
def Verify_without_m(r,s,e,Q,P):
    if not ((r>=1 and r<=(n-1)) and (s>=1 and s<=(n-1))):
        print("False!")
        return False
    w=libnum.xgcd(s,n)[0]
    u1=e*w%n
    u2=r*w%n
    tem1=func_mult(u1,P)
    tem2=func_mult(u2,Q)
    X=func_add(tem1,tem2)
    print(X)
    if X[0]==0 and X[1]==0:
        print("False!")
        return False
    if ( X[0]%n ) == r:
        print("The signature is verified!")
        return True
    else :
        print("False!")
        return False

# 伪造签名
def forge(n,Q,P): #n:椭圆曲线的点的个数  Q:公钥  P:基点
    ss = n
    while math.gcd(ss,n)!=1:
        u = random.randrange(1,n-1)
        v = random.randrange(1,n-1)
        while math.gcd(v,n)!=1:
            v = random.randrange(1,n-1)
        R = func_mult(u,P)
        R =func_add(R,func_mult(v,Q))
        rr = R[0]%n
        ee = (rr * u * (libnum.xgcd(v,n)[0])) % n
        ss = (rr * (libnum.xgcd(v,n)[0])) % n

    print("\n伪造签名:")
    print([(rr,ss),ee])
    Verify_without_m(rr,ss,ee,Q,G)

test()
forge(n,key[0],G)

#经过简单的基于素数域的椭圆曲线的ECDSA签名的成功伪造
#我们只需按照同样的伪造方法在得到中本聪签名的椭圆曲线基础上进行伪造即可
#如下为sagemath中生成得到中本聪签名的椭圆曲线的相关参数

#F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
#Finite Field of size 115792089237316195423570985008687907853269984665640564039457584007908834671663

#椭圆曲线
#C = EllipticCurve ([F (0), F (7)])   Elliptic Curve defined by y^2 = x^3 + 7 over Finite Field of size 115792089237316195423570985008687907853269984665640564039457584007908834671663

#基点
#G = C.lift_x(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
#(55066263022277343669578718895168534326250603453777594175500187360389116729240 : 83121579216557378445487899878180864668798711284981320763518679672151497189239 : 1)

#基点的阶
#N = FiniteField (C.order())
#Finite Field of size 115792089237316195423570985008687907852837564279074904382605163141518161494337

#密钥
#P = P=-C.lift_x(0x11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c)
#(8077278579061990400249759952135267692351268034085864289451880299432711854684 : 34883007453703041530665294287464619720895014397849163628292634352974843079052 : 1)

'''
由以上参数运行forge函数得到的签名值均可通过验证

'''
P1=(8077278579061990400249759952135267692351268034085864289451880299432711854684,34883007453703041530665294287464619720895014397849163628292634352974843079052)
G1=(55066263022277343669578718895168534326250603453777594175500187360389116729240,83121579216557378445487899878180864668798711284981320763518679672151497189239)
N=115792089237316195423570985008687907852837564279074904382605163141518161494337
a=1
b=7
t=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
#forge(N,P1,G1)
