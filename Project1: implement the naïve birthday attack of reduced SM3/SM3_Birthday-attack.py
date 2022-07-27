'''
SM3生日攻击
一个空间较大的集合(输入)通过哈希算法映射到一个空间较小的集合(哈希值)，
必然会造成多个输入映射到一个哈希值上，
这就是所谓的哈希碰撞。

'''
from gmssl import sm3, func
import secrets
import string

choices1 = string.digits  + string.ascii_letters
choices2 = string.digits  + string.ascii_letters

def random_string(length: int):
    """生成随机字符串"""
    str1 = "".join(secrets.choice(choices1) for _ in range(length))
    str2 = "".join(secrets.choice(choices2) for _ in range(length))
    return str1, str2


def birthday_attack(length):
    high = 2**length
    for i in range(high):
        strings = random_string(length)
        str_a = bytes(strings[0], encoding='utf-8')
        str_b = bytes(strings[1], encoding='utf-8')
        hash_a = sm3.sm3_hash(func.bytes_to_list(str_a))
        hash_b = sm3.sm3_hash(func.bytes_to_list(str_b))
        if hash_a[:int(length/4)] == hash_b[:int(length/4)]:
            print("str_a: ",str_a,"\nstr_b: ",str_b)
            print("Hash_a:",hash_a,"\nHash_b:",hash_b)
            return 
    print("OK")


birthday_attack(32)

strs = "abc"
str_b = bytes(strs, encoding='utf-8')
result = sm3.sm3_hash(func.bytes_to_list(str_b))
