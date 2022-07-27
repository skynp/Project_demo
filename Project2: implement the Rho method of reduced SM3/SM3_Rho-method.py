'''
SM3 Rho method: low-memory collision search
对一个值重复做哈希 期望得到一个环使得二者哈希值相同


'''

from gmssl import sm3, func
import secrets
import string
import time 

choices1 = string.digits  + string.ascii_letters
critical_value = 2**16


def Rho_method(n): # hashvalue为初始哈希值 n为相同的比特数
    pre_hash = [] #存储之前的hash值
    pre_string = [] #存储之前的字符串
    for i in range(2**n):
        str1 = "".join(secrets.choice(choices1) for _ in range(2**n))
        pre_string.append(str1)
        str_a = bytes(str1, encoding='utf-8')
        hashvalue = sm3.sm3_hash(func.bytes_to_list(str_a))
        pre_hash.append(hashvalue)
        collision = hashvalue
        for i in range(critical_value):
            pre_string.append(collision)
            str0 = bytes(collision, encoding='utf-8')
            collision = sm3.sm3_hash(func.bytes_to_list(str0)) #重复做哈希
            if collision[:n] in pre_hash:
                index = pre_hash.index(collision[:n])
                print("string1: ",pre_string[index])
                print("string2: ",str0)
                print("hash1:   ",pre_string[index+1])
                print("hash2:   ",collision)
                return 

            pre_hash.append(collision[:n])
        
        pre_hash = [] #存储之前的hash值
        pre_string = [] #存储之前的字符串


start = time.time()
Rho_method(12)
end = time.time()
print("所需时间:",end-start,"s")
