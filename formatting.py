def os2ip(octet:bytes):
    #将字节串转换为整数
    return int.from_bytes(octet,'big')

def i2osp(i:int,k:int):
    #将整数转换为字节串
    return i.to_bytes(k,'big')