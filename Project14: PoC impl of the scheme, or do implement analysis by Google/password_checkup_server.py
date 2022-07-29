'''
*Project: PoC impl of the scheme, or do implement analysis by Google
利用python的socket模块模拟网络通信以实现密码的检查
整体过程类似零知识证明
通过客户端和服务器的交互以查看客户端的密码是否泄露

'''

import random
from argon2 import PasswordHasher
import socket
from os.path import commonprefix
import threading
import hmac, os
from gmssl import sm3, func

#假设已经从黑市买到的用户名密码如下：
username_passcode=[('zhangsan','12345'),('lisi','123456'),('wangwu','23415'),
                    ('zhaoliu','234567'),('zhengqi','345678'),('wuba','257890')]

# 服务器端的私钥
global sk_b

#sk_b = int(random.random()*100)
sk_b = 7

#Data records
'''
def cal_m2node(m):
    # x坐标的十六进制
    hex_x = m.encode().hex()
    # x坐标十进制
    x = int(hex_x,16)%23
    if x in xlabel:
        y = nodes[xlabel.index(x)][1]
    else:
        y = x
    return (x,y)
'''

# Create key-value teble
def createkv(username,password):
    #ph = PasswordHasher()
    #h = ph.hash(username+password) #每次不一样 选用sm3哈希
    #k = h[33:35]  #key
    str_a = bytes(username+password, encoding='utf-8')
    h = sm3.sm3_hash(func.bytes_to_list(str_a))
    k = h[0:16]
    int_h = str(h).encode().hex()
    h = int(int_h,16)
    #print(h,sk_b)
    v = str((h**sk_b)%23)
    return (k,v)


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
def data_handler(s, conn, ktable):

    if not conn_auth(conn):
        print('该链接不合法,关闭')
        conn.close()
        return
    else:
        print("链接合法，开始通信")
    while True:
        content = conn.recv(1024).decode('utf-8')
        #print(content)
        # 接收的数据是1024比特的倍数
        # 接收到了k v
        # 需要在ktable中找到k并发送给客户端
        # 同时计算h^{a*b}
        if not content:
            conn.close()
            break  # 如果接收的数据不对，则结束循环 客户端退出
        elif content.lower() == 'bye':
            conn.close()
            s.close()
            break

        else:
            #k_tem = content[0]
            #v_tem = content[1]
            #hab = (v_tem**sk_b)%65535
            num = 0
            for user in ktable:
                if content == user[0]:
                    num+=1
                    conn.sendall('yes'.encode('utf-8'))  # 先告诉客户端你的账号在这里 把ha发过来

                    content = conn.recv(1024).decode('utf-8')
                    #print(content)
                    hab = (int(content) ** sk_b) % 23  #计算hab
                    #print(hab)
                    conn.sendall(str(hab).encode('utf-8'))  #发给客户端hab让他验证
                    conn.sendall(user[1].encode('utf-8'))   # 把hb发给他让他验证
                    break
                   # print('接收成功，已转发')
            if num ==0:
                conn.sendall('no'.encode('utf-8'))
                    #print("改用户名暂无风险")






HOST = ''
PORT = 50007
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 新建socket
s.bind((HOST, PORT))  # 绑定IP和端口
s.listen(5)  # 监听链接
print('启动监听，等待接入......')
# ktable
ktable=[]
for i in username_passcode:
    ktable.append(createkv(i[0],i[1]))
#print(ktable)
thread_list = []

while True:
    try:
        conn, addr = s.accept()  # 接受链接
        print('成功连接：{}'.format(addr))
    except Exception:
        #print('Error')
        break
    t = threading.Thread(target=data_handler(s,conn,ktable), args=(s, conn))
    # Thread类表示在单独的控制线程中运行的活动
    thread_list.append(t)
    t.start()

for t in thread_list:
    t.join()  # 主线程等待子线程的终止

print('Stop the server....')






