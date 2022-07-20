from gmssl import sm3, func
strs = "abc"
str_b = bytes(strs, encoding='utf-8')
result = sm3.sm3_hash(func.bytes_to_list(str_b))
print(result)
print("\n")
strs = "202000141016"
str_b = bytes(strs, encoding='utf-8')
result = sm3.sm3_hash(func.bytes_to_list(str_b))
print(result)
