import random
import math
from gmssl import sm3, func


#椭圆曲线上点的加法
def func_add(x1,y1,x2,y2,a,t): # a为基点横坐标 t为模数
    k = 0
    #list1=[]  #存放结果
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
    #list1.append(x3)
    #list1.append(y3)
    return x3,y3

#椭圆曲线上的点乘
def func_mult(num,x,y,a,t):

    num = bin(num)[2:] # 将乘数转为二进制

    res_x,res_y=x,y
    for i in range(1,len(num)):
        res_x,res_x = func_add(res_x,res_y,res_x,res_y,a,t)
        if num[i]=='1':
            res_x,res_y=func_add(res_x,res_y,x,y,a,t)

    return res_x,res_y


def kdf(z,klen):
    ct=1
    k=''
    for _ in range(math.ceil(klen/256)):
        str_=bytes(hex(int(z+'{:032b}'.format(ct),2))[2:],encoding='utf-8')
        #print(str_)
        result = sm3.sm3_hash(func.bytes_to_list(str_))
        k=k+result
        ct=ct+1
    k='0'*((256-(len(bin(int(k,16))[2:])%256))%256)+bin(int(k,16))[2:]
    return k[:klen]

#parameters
p=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
gx=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
gy=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
n=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
#待加密的消息M：encryption standard
#消息M的16进制表示：656E63 72797074 696F6E20 7374616E 64617264
'''
dB=0x1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
xB=0x435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A
yB=0x75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42
'''
dB=random.randint(1,n-1)
xB,yB=func_mult(dB,gx,gy,a,p)


def encrypt(m:str):
    plen=len(hex(p)[2:])
    m='0'*((4-(len(bin(int(m.encode().hex(),16))[2:])%4))%4)+bin(int(m.encode().hex(),16))[2:]
    klen=len(m)
    while True:
        k=random.randint(1, n)
        while k==dB:
            k=random.randint(1, n)
        x2,y2=func_mult(k, xB, yB, a, p)
        x2,y2='{:0256b}'.format(x2),'{:0256b}'.format(y2)
        t=kdf(x2+y2, klen)
        if int(t,2)!=0:
            break
    x1,y1=func_mult(k, gx, gy, a, p)
    x1,y1=(plen-len(hex(x1)[2:]))*'0'+hex(x1)[2:],(plen-len(hex(y1)[2:]))*'0'+hex(y1)[2:]
    c1='04'+x1+y1
    c2=((klen//4)-len(hex(int(m,2)^int(t,2))[2:]))*'0'+hex(int(m,2)^int(t,2))[2:]
    str_ = bytes(hex(int(x2+m+y2,2))[2:],encoding='utf-8')
    c3=sm3.sm3_hash(func.bytes_to_list(str_))
    return c1,c2,c3

def decrypt(c1,c2,c3,a,b,p):
    c1=c1[2:]
    x1,y1=int(c1[:len(c1)//2],16),int(c1[len(c1)//2:],16)
    if pow(y1,2,p)!=(pow(x1,3,p)+a*x1+b)%p:
        return False
    x2,y2=func_mult(dB, x1, y1, a, p)
    x2,y2='{:0256b}'.format(x2),'{:0256b}'.format(y2)
    klen=len(c2)*4
    t=kdf(x2+y2, klen)
    if int(t,2)==0:
        return False
    m='0'*(klen-len(bin(int(c2,16)^int(t,2))[2:]))+bin(int(c2,16)^int(t,2))[2:]
    str_=bytes(hex(int(x2+m+y2,2))[2:],encoding='utf-8')
    u=sm3.sm3_hash(func.bytes_to_list(str_))
    if u!=c3:
        return False
    return hex(int(m,2))[2:]

fstr="202000141016"
c1,c2,c3=encrypt(fstr)
c=(c1+c2+c3).upper()
print('\nciphertext:')
for i in range(len(c)):
    print(c[i*8:(i+1)*8],end=' ')
print('\n\nplaintext:')


m1=decrypt(c1, c2, c3, a, b, p)
print(m1)
if m1:
    m1=str(bytes.fromhex(m1))
    m1='\n'.join(m1[2:-1].split('\\n'))
    print(m1)
    print(fstr==m1)
else:
    print(False)
