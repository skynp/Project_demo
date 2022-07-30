import socket
import threading
import sys
import hmac,os
import random
from argon2 import PasswordHasher
import math
import libnum
from gmssl import sm3, func

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

G = [x_G,y_G]

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

# 椭圆曲线上的点P -> -P
def calord(P):
    x = P[0]
    y = P[1]
    Q = [x,-y]
    return Q


secret_key = b'python password' #客户端与服务器端通信所需
def conn_auth(s):
    '''
    验证客户端到服务器的链接
    :param conn:
    :return:
    '''
    msg = s.recv(32)
    h = hmac.new(secret_key, msg, digestmod='MD5')
    digest = h.digest()
    s.sendall(digest)



host='127.0.0.1'  #服务端IP
port=50007   #服务端端口
address=(host,port)   #服务端IP包
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((host,port))
except Exception as e:
    print('Error')
    sys.exit()  # 退出程序
conn_auth(s)

d1 = random.randrange(1,n-1)  # A 的私钥
while math.gcd(d1,n)!=1:
    d1 = random.randrange(1, n - 1)
dn1 = libnum.xgcd(d1,n)[0]
P1 = funcmult(dn1,G,a,q)
PA = funcmult(d1,G,a,q)
x_A = PA[0]
y_A = PA[1]
# 发送数据
s.sendall(str(P1[0]).encode('utf-8'))
s.sendall(str(P1[1]).encode('utf-8'))
# 接收P
Px = s.recv(1024).decode('utf-8')  # x
Py = s.recv(1024).decode('utf-8')  # y
#print(Px,Py)
P = [int(Px,10),int(Py,10)]

M = 'sdu_tql'
IDA = 'zhangsan'
ENTL_A = len(IDA)
str_a = str(ENTL_A) + IDA + hex(a)[2:] + hex(b)[2:] + hex(G[0])[2:] + hex(G[1])[2:] + hex(x_A)[2:] + hex(y_A)[2:]
str_a = bytes(str_a, encoding='utf-8')
Z_A = sm3.sm3_hash(func.bytes_to_list(str_a))
M = Z_A + M
str_a = bytes(M, encoding='utf-8')
e = sm3.sm3_hash(func.bytes_to_list(str_a))
# 发送e
s.sendall(e.encode('utf-8'))

k1 = random.randrange(1,n-1)
Q1 = funcmult(k1,G,a,q)
s.sendall(str(Q1[0]).encode('utf-8'))
s.sendall(str(Q1[1]).encode('utf-8'))

r = int(s.recv(1024).decode('utf-8'),10)
s2 = int(s.recv(1024).decode('utf-8'),10)
s3 = int(s.recv(1024).decode('utf-8'),10)

sig = ((d1+k1)*s2 + d1*s3 -r) % n
print("M : ",M)
print("\nsignature : ",(r,sig))
s.close()  # 关闭服务端
