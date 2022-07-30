import random
from argon2 import PasswordHasher
import socket
from os.path import commonprefix
import threading
import hmac, os
import libnum
import math
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


#认证客户端链接
def conn_auth(conn):
    secret_key = b'python password'
    print('开始验证新链接的合法性')
    msg = os.urandom(32)  # 发送32bite长的字符串
    conn.sendall(msg)
    h = hmac.new(secret_key, msg, digestmod='MD5')
    # 返回一个新的 hmac 对象。
    # key 是一个指定密钥的 bytes 或 bytearray 对象。
    # 如果提供了 msg，将会调用 update(msg) 方法。
    # digestmod 为 HMAC 对象所用的摘要名称、摘要构造器或模块。
    # 虽然该参数位置靠后，但它却是必须的。
    # 参考文献：https://blog.csdn.net/weixin_45895096/article/details/119876903
    digest = h.digest()
    respone = conn.recv(len(digest))
    return hmac.compare_digest(respone, digest)

#处理从客户端收到的消息
def data_handler(s, conn):

    if not conn_auth(conn):
        print('该链接不合法,关闭')
        conn.close()
        return
    else:
        print("链接合法，开始通信")
    while True:
        # 收到了那边发来的P1
        content1 = conn.recv(1024).decode('utf-8')  # x
        content2 = conn.recv(1024).decode('utf-8')  # y
        P1 = [int(content1,10),int(content2,10)]

        d2 = random.randrange(1,n-1)
        while math.gcd(d2,n)!=1:
            d2 = random.randrange(1, n - 1)
        dn2 = libnum.xgcd(d2,n)[0]
        temP = funcmult(dn2,P1,a,q)
        Gn = calord(G)
        P = funcadd(temP,Gn,a,q) # public key

        conn.sendall(str(P[0]).encode('utf-8'))
        conn.sendall(str(P[1]).encode('utf-8'))

        #接收e
        e = conn.recv(1024).decode('utf-8')
        #print(int(e,16))
        Q1_x = conn.recv(1024).decode('utf-8')
        Q1_y = conn.recv(1024).decode('utf-8')
        Q1 = [int(Q1_x,10),int(Q1_y,10)]
        k2 = random.randrange(1,n-1)
        k3 = random.randrange(1, n - 1)
        Q2 = funcmult(k2,G,a,q)
        temQ = funcmult(k3,G,a,q)
        Q3 = funcadd(temQ,Q2,a,q)

        r = (Q3[0] +int(e,16)) % n
        s2 = d2 * k3 %n
        s3 = d2 * (k2+r)%n

        conn.sendall(str(r).encode('utf-8'))
        conn.sendall(str(s2).encode('utf-8'))
        conn.sendall(str(s3).encode('utf-8'))

        conn.close()
        s.close()
        break








HOST = ''
PORT = 50007
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 新建socket
s.bind((HOST, PORT))  # 绑定IP和端口
s.listen(5)  # 监听链接
print('启动监听，等待接入......')



thread_list = []

while True:
    try:
        conn, addr = s.accept()  # 接受链接
        print('成功连接：{}'.format(addr))
    except Exception:
        #print('Error')
        break
    t = threading.Thread(target=data_handler(s,conn), args=(s, conn))
    # Thread类表示在单独的控制线程中运行的活动
    thread_list.append(t)
    t.start()

for t in thread_list:
    t.join()  # 主线程等待子线程的终止

print('Stop the server....')






