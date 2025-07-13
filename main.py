from Oracle.oracle import Oracle
from PKCS.formatting import *

#实现扩展欧几里得除法
def extended_gcd(a:int,b:int)->tuple:
    lastremainder,remainder=abs(a),abs(b)
    x,lastx=0,1
    y,lasty=1,0
    while remainder:
        lastremainder,(quotient,remainder)=remainder,divmod(lastremainder,remainder)
        x,lastx=x-quotient*x,x
        y,lasty=y-quotient*y,y
    return lastremainder,lastx *(-1 if a<0 else 1),lasty *(-1 if b<0 else 1)

#计算逆元
def modinv(a:int,n:int)->int:
    g,c,d=extended_gcd(a,n)
    if g!=1:
        raise Exception('modinv error')

    return c%n


def interval(a,b)->range:
    return range(a,b+1)

#向上取整
def ceildiv(a:int,b:int)->int:
    return -(-a//b)

#向下取整
def floordiv(a:int,b:int)->int:
    return a//b

#bleichenbacher攻击的的主逻辑
def bleichenbacher(oracle:Oracle):
    #先读取公钥信息
    n,e,k=oracle.get_n(),oracle.get_e(),oracle.get_k()
    B=pow(2,8*(k-2))
    B2=2*B
    B3=3*B

    #定义一个调用检查是否为PKCS1填充的函数
    def pkcs_conformant(c,s):
        pkcs_conformant.counter+=1
        return oracle.decrypt(i2osp(c*pow(s,e,n)%n,k))
    pkcs_conformant.counter=0
    #Step1 Blinding
    #先检查初始密文符不符合要求
    c=os2ip(oracle.eavesdrop())
    assert(pkcs_conformant(c,1))

    c_0=c
    s_old=0
    set_m_old={(B2,B3-1)}
    i=1
    while True:
        #Step2.a Starting the search
        if i==1:
            s_new=ceildiv(n,B3)
            while not pkcs_conformant(c_0,s_new):
                s_new+=1

        #Step2.b Searching with more than one interval left
        elif i>1 and len(set_m_old)>1:
            s_new=s_old+1
            while not pkcs_conformant(c_0,s_new):
                s_new+=1

        #Step2.c Searching with one interval left
        elif len(set_m_old)==1:
            a,b=next(iter(set_m_old))
            found=False
            r=ceildiv(2*(b*s_old-B2),n)
            while not found:
                for s in interval(ceildiv(B2+r*n,b),floordiv(B3+r*n-1,a)):
                    if pkcs_conformant(c_0,s):
                        found=True
                        s_new=s
                        break
                r+=1
        #Step3 缩小明文的可能区间
        set_m_new=set()
        for a,b in set_m_old:
            r_min=ceildiv(a*s_new-B3+1,n)
            r_max=floordiv(b*s_new-B2,n)

            for r in interval(r_min,r_max):
                new_a=max(a,ceildiv(B2+r*n,s_new))
                new_b=min(b,floordiv(B3-1+r*n,s_new))
                if new_a<=new_b:
                    set_m_new |={(new_a,new_b)}


        if len(set_m_new)==0:
            raise ValueError("The new set is empty")

        #Step4 计算最终结果
        if len(set_m_new)==1:
            a,b=next(iter(set_m_new))
            if a==b:
                print("计算得到：",i2osp(a,k))
                print("计算得到明文整数为:",a)
                print("Success after {} calls to the oracle.".format(pkcs_conformant.counter))
                return a

        set_m_old=set_m_new
        s_old=s_new
        i+=1

if __name__=="__main__":
    oracle=Oracle()
    bleichenbacher(oracle)
