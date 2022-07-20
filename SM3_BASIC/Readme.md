利用c++实现了基本的SM3杂凑算法(操作系统为Windows 未依赖新的库 可直接运行)\
对abc及学号202000141016进行了加密

杂凑值如下：\
Hash of abc:\
66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

Hash of 202000141016:\
b2b5ef81 69fc6e0c bf299ce3 9fd6982f 56913d83 e63e4134 eb96f073 1845e4df

将结果与python中的密码库运行结果进行对比 验证正确\
python中的结果为：\
abc：
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0 \
学号：
b2b5ef8169fc6e0cbf299ce39fd6982f56913d83e63e4134eb96f0731845e4df
