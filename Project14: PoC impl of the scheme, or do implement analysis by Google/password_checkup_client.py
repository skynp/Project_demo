import socket
import threading
import sys
import hmac,os
import random
from argon2 import PasswordHasher
import math
import libnum
from gmssl import sm3, func


## 客户端的私钥
global sk_a
sk_a = 3


a = libnum.xgcd(sk_a,22)[0] %22 # a的逆
#print(a)

def calkv(username,password):

    #ph = PasswordHasher()
    #h = ph.hash(username + password)
    #k = h[33:35]  # key
    str_a = bytes(username + password, encoding='utf-8')
    h = sm3.sm3_hash(func.bytes_to_list(str_a))
    k = h[0:16]
    int_h = str(h).encode().hex()
    h = int(int_h, 16)
    # print(h,sk_b)
    v = str((h ** sk_a)%23)
    return (k, v)

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


# exampes:
# username: zhangsan password:12345
# username: zhangsan password:zhangsan

username_password=[('zhangsan','12345'),('zhangsan','zhangsan')]

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
for i in username_password:
    content = calkv(i[0],i[1])
    #print(content)
    #先发送k 再发送v
    try:
        # 发送数据
        s.sendall(content[0].encode('utf-8'))
        # 从服务端接收数据
        data = s.recv(1024)
        #print(data)
    except:
        break
    data = data.decode('utf-8')
    #print('Received:', data)
    if data.lower() == 'yes':
        s.sendall(content[1].encode('utf-8'))  #把ha发给服务器
        data1 = s.recv(1024)  # 收到hab
        #print(data1)
        hb = (int(data1) ** a) % 23 # 计算hb
        #print(hb)
        data1 = s.recv(1024)  # 收到hb
        if int(data1)==hb:
            print(i,"账号有风险！")
    else:
        if data.lower() == 'no' :
            print(i,"账号无风险!")

s.sendall('bye'.encode('utf-8'))
s.close()  # 关闭服务端
