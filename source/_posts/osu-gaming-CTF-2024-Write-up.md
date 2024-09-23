---
title: osu!gaming CTF 2024 Write-up
date: 2024-03-04 10:22:16
tags: ctf
layout: post
typora-root-url: .
cover: /osu-gaming-ctf-2024-write-up/thailand-beach.webp
photos:
  - /osu-gaming-ctf-2024-write-up/thailand-beach.webp
excerpt: I participated in [osu!gaming CTF](https://ctf.osugaming.lol/)  with [TakeKitsune](https://ctftime.org/team/280959), and here is my write-up of the part I solved.
---

I participated in [osu!gaming CTF](https://ctf.osugaming.lol/) with [TakeKitsune](https://ctftime.org/team/280959), and here is my write-up of the part I solved.

## OSU

### sanity-check-2

> [Gawr Gura - Kyoufuu All Back](https://osu.ppy.sh/beatmapsets/2143550)
>
> Your task is to play [A](https://osu.ppy.sh/beatmapsets/2143550#osu/4512653) difficulty and get at least 70% accuracy in std mode. Submit your replay osr file to server in base64 format.

#### Solution

As a beginner in `osu!`, I use the [No Fail (mod)](https://osu.ppy.sh/wiki/en/Gameplay/Game_modifier/No_Fail) to play first and obtain the osr file. Then, I edit the replay using [OsuReplayEditor](https://github.com/thebetioplane/OsuReplayEditor) to remove any misses or mods.

<img src="/osu-gaming-ctf-2024-write-up/replay-editor.webp" style="width: min(22em, 100%);">

### sanity-check-3

> [Gawr Gura - Kyoufuu All Back](https://osu.ppy.sh/beatmapsets/2143550)
>
> Alright, it's gaming time. SS the top diff and submit your replay to the server in base64 format. (Play nomod, please don't use mods like DT or HR)
>
> `nc chal.osugaming.lol 7278`

#### Solution

First, use [Auto (mod)](https://osu.ppy.sh/wiki/en/Gameplay/Game_modifier/Auto) to play it to obtain a perfect `osr` file (`osu!(lazer)` does not support exporting auto played osr files, so we need to use `osu!` Instead). However, even autoplay cannot achieve SS (check the video below).

<video muted controls style="width: 100%;">
  <source src="/osu-gaming-ctf-2024-write-up/almost-ss.mp4" type="video/mp4">
</video>


So I used [osu-replay-parser](https://github.com/kszlim/osu-replay-parser) to add a `20ms` delay to the auto-played `osr`, and it worked.

```python
from osrparse import Replay

# parse from a path
replay = Replay.from_path("at.osr")

# anti AT detection
replay.username = 'ch'

# remove the auto play mods
replay.mod_combination = 0

# add some time
replay.replay_data[1].time_delta += 20

# write to a new file
replay.write_path("at-modified.osr")
```

#### Malware

I stumbled upon [RedLine Stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer) malware while searching for an osu! cheat tool. Interestingly, I had recently reversed it at [GCC 2024](https://gcc.ac/).

![osu-cheat](/osu-gaming-ctf-2024-write-up/osu-cheat.webp)

## Crypto

### secret-map

> Here's an [old, unfinished map](https://osu.ppy.sh/beatmapsets/1680153#osu/3432455) of mine (any collabers?). I tried adding an new diff but it seems to have gotten corrupted - can you help me recover it?
>
> Downloads: [Alfakyun. - KING.osz](https://ctf.osugaming.lol/uploads/2cdc85778a40b176f4541bc782650cf933dd9997083d69e928cd9b4b85e0c189/Alfakyun. - KING.osz)

#### Solution

We first decompress the `osz` file using `7z x file.osz`.

```
.
└── extracted
    ├── Alfakyun. - KING (QuintecX) [ryuk eyeka's easy].osu
    ├── audio.mp3
    ├── bg.webp
    ├── enc.py
    ├── flag.osu.enc
```

In `enc.py`, the osu file is encrypted using XOR with a random 16-byte key. However, since the `osu` file starts with `osu file format v14`, the key can be obtained using it.

```python
# enc.py
import os
xor_key = os.urandom(16)

with open("flag.osu", 'rb') as f:
    plaintext = f.read()

encrypted_data = bytes([plaintext[i] ^ xor_key[i % len(xor_key)] for i in range(len(plaintext))])

with open("flag.osu.enc", 'wb') as f:
    f.write(encrypted_data)
```

```python
# sol.py
with open('flag.osu.enc', 'rb') as f:
    encrypted_data = f.read()

known_pt = b'osu file format v14'[:16]
key = bytes([encrypted_data[i] ^ known_pt[i] for i in range(16)])

def decrypt(data):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

decrypted_data = decrypt(encrypted_data)

with open('sol.osu', 'wb') as f:
    f.write(decrypted_data)
```

After obtaining the `osu` file, I repackaged it into `osz` using `7z a -tzip -mm=Deflate -mx=9 example.osz extracted` and imported it into osu!. Here are the results:

<video muted controls style="width: 100%;">
  <source src="/osu-gaming-ctf-2024-write-up/xor.mp4" type="video/mp4">
</video>

### korean-offline-mafia

> I've been hardstuck for years, simply not able to rank up... so I decided to try and infiltrate the Korean offline mafia for some help. I've gotten so close, getting in contact, but now, to prove I'm part of the group, I need to prove I know every group member's ID (without giving it away over this insecure communication). The only trouble is... I don't! Can you help?
>
> `nc chal.osugaming.lol 7275`
>
> Downloads: [server.py](https://ctf.osugaming.lol/uploads/657a7eedb024c2869f7cd063844cff7337f96dbc516198a86f53b1d995515364/server.py)

```python
from topsecret import n, secret_ids, flag
import math, random

assert all([math.gcd(num, n) == 1 for num in secret_ids])
assert len(secret_ids) == 32

vs = [pow(num, 2, n) for num in secret_ids]
print('n =', n)
print('vs =', vs)

correct = 0

for _ in range(1000):
	x = int(input('Pick a random r, give me x = r^2 (mod n): '))
	assert x > 0
	mask = '{:032b}'.format(random.getrandbits(32))
	print("Here's a random mask: ", mask)
	y = int(input('Now give me r*product of IDs with mask applied: '))
	assert y > 0
	# i.e: if bit i is 1, include id i in the product--otherwise, don't

	val = x
	for i in range(32):
		if mask[i] == '1':
			val = (val * vs[i]) % n
	if pow(y, 2, n) == val:
		correct += 1
		print('Phase', correct, 'of verification complete.')
	else:
		correct = 0
		print('Verification failed. Try again.')

	if correct >= 10:
		print('Verification succeeded. Welcome.')
		print(flag)
		break
```

#### Solution

To solve the challenge, simply send `n` for every verification.

## Web

### pp-ranking

> can you get to the top of the leaderboard? good luck getting past my anticheat...
>
> [https://pp-ranking.web.osugaming.lol](https://pp-ranking.web.osugaming.lol/)
>
> Downloads: [pp-ranking.zip](https://ctf.osugaming.lol/uploads/f1fb87bae1746b60ea2ab113a354108882f65dc61758522cc2f372b0d5074892/pp-ranking.zip)

In order to retrieve the flag, we must reach the top of the leaderboard.

```javascript
app.get("/rankings", (req, res) => {
  let ranking = [...baseRankings];
  if (req.user) ranking.push(req.user);

  ranking = ranking
    .sort((a, b) => b.performance - a.performance)
    .map((u, i) => ({ ...u, rank: `#${i + 1}` }));

  let flag;
  if (req.user) {
    if (ranking[ranking.length - 1].username === req.user.username) {
      ranking[ranking.length - 1].rank = "Last";
    } else if (ranking[0].username === req.user.username) {
      flag = process.env.FLAG || "osu{test_flag}";
    }
  }
  res.render("rankings", { ranking, flag });
});
```

We can submit `osr` files to be ranked.

![submit-rank](/osu-gaming-ctf-2024-write-up/submit-rank.webp)

```javascript
app.post("/api/submit", requiresLogin, async (req, res) => {
  const { osu, osr } = req.body;
  try {
    const [pp, md5] = await calculate(osu, Buffer.from(osr, "base64"));
    if (req.user.playedMaps.includes(md5)) {
      return res.send("You can only submit a map once.");
    }
    if (anticheat(req.user, pp)) {
      // ban!
      users.delete(req.user.username);
      return res.send("You have triggered the anticheat! Nice try...");
    }
    req.user.playCount++;
    req.user.performance += pp;
    req.user.playedMaps.push(md5);
    return res.redirect("/rankings");
  } catch (err) {
    return res.send(err.message);
  }
});
```

Below are the steps involved in the scoring process.

```javascript
import { StandardRuleset } from "osu-standard-stable";
import { BeatmapDecoder, ScoreDecoder } from "osu-parsers";
import crypto from "crypto";

const calculate = async (osu, osr) => {
  const md5 = crypto.createHash("md5").update(osu).digest("hex");
  const scoreDecoder = new ScoreDecoder();
  const score = await scoreDecoder.decodeFromBuffer(osr);

  if (md5 !== score.info.beatmapHashMD5) {
    throw new Error(
      "The beatmap and replay do not match! Did you submit the wrong beatmap?",
    );
  }
  if (score.info._rulesetId !== 0) {
    throw new Error("Sorry, only standard is supported :(");
  }

  const beatmapDecoder = new BeatmapDecoder();
  const beatmap = await beatmapDecoder.decodeFromBuffer(osu);

  const ruleset = new StandardRuleset();
  const mods = ruleset.createModCombination(score.info.rawMods);
  const standardBeatmap = ruleset.applyToBeatmapWithMods(beatmap, mods);
  const difficultyCalculator =
    ruleset.createDifficultyCalculator(standardBeatmap);
  const difficultyAttributes = difficultyCalculator.calculate();

  const performanceCalculator = ruleset.createPerformanceCalculator(
    difficultyAttributes,
    score.info,
  );
  const totalPerformance = performanceCalculator.calculate();

  return [totalPerformance, md5];
};

export default calculate;
```

And it has an anti-cheat mechanism.

```javascript
// anticheat.js
const THREE_MONTHS_IN_MS = 3 * 30 * 24 * 60 * 1000;

const anticheat = (user, newPP) => {
  const pp = parseInt(newPP);
  if (user.playCount < 5000 && pp > 300) {
    return true;
  }

  if (+new Date() - user.registerDate < THREE_MONTHS_IN_MS && pp > 300) {
    return true;
  }

  if (
    +new Date() - user.registerDate < THREE_MONTHS_IN_MS &&
    pp + user.performance > 5_000
  ) {
    return true;
  }

  if (user.performance < 1000 && pp > 300) {
    return true;
  }

  return false;
};

export default anticheat;
```

#### Solution

To bypass the anti-cheat mechanism, we can make our score `Infinity`. This will cause `pp = parseInt(newPP)` in anticheat.js to become `NaN`. [All comparisons involving `NaN` will always return false](https://stackoverflow.com/questions/26982881/why-nan-is-greater-than-any-number-in-javascript#:~:text=All%20comparisons%20involving%20NaN%20will,nor%20greater%20than%20any%20number.), so we can bypass the anti-cheat mechanism.

I randomly selected a song from [here](https://osu.ppy.sh/beatmapsets/2116763#osu/4446816) and downloaded the `osz` and `osr` (from rank). I then unzipped the `osz` file to obtain the `osu` file, modified `OverallDifficulty` of the `osu` file to `1000000000`, and updated the beatmap hash in the `osr` to match the new one of the `osu` file. Finally, I uploaded the modified files to the server and achieved a rank of 1.

![pp-ranking](/osu-gaming-ctf-2024-write-up/pp-ranking.webp)

![pp-ranking-rank](/osu-gaming-ctf-2024-write-up/pp-ranking-rank.webp)

By the way, the variable `pp` can easily become infinity due to the presence of multiple `Math.pow` functions in the formula.

![powers](/osu-gaming-ctf-2024-write-up/powers.webp)

### stream-vs

> how good are you at streaming? i made a site to find out! you can even play with friends, and challenge the goat himself
> https://stream-vs.web.osugaming.lol/

This challenge requires us to beat `cookiezi` in the game, but `cookiezi` will always get the exact `bpm` (see the scoring algorithm below).

```javascript
// stream-vs.js (frontend)
const $ = document.querySelector.bind(document);

const ws = new WebSocket(
  location.origin.replace("https://", "wss://").replace("http://", "ws://"),
);
let username;
$("form").onsubmit = (e) => {
  e.preventDefault();
  username = $("[name='username']").value;
  ws.send(JSON.stringify({ type: "login", data: username }));
  localStorage.key1 = $("#key1").value;
  localStorage.key2 = $("#key2").value;
};

window.onload = () => {
  $("#key1").value = localStorage.key1 || "z";
  $("#key2").value = localStorage.key2 || "x";
};

$("#host-btn").onclick = () => {
  ws.send(JSON.stringify({ type: "host" }));
};

$("#challenge-btn").onclick = () => {
  ws.send(JSON.stringify({ type: "challenge" }));
};

$("#join-btn").onclick = () => {
  ws.send(JSON.stringify({ type: "join", data: prompt("Game ID:") }));
};

$("#start-btn").onclick = () => {
  $("#start-btn").style.display = "none";
  ws.send(JSON.stringify({ type: "start" }));
};

ws.onopen = () => {
  console.log("connected to ws!");
};

let session;
ws.onmessage = (e) => {
  const { type, data } = JSON.parse(e.data);
  if (type === "login") {
    $("form").style.display = "none";
    $("#menu").style.display = "block";

    const params = new URLSearchParams(location.search);
    if (params.has("id")) {
      ws.send(JSON.stringify({ type: "join", data: params.get("id") }));
    }
  } else if (type === "join") {
    session = data;
    $("#menu").style.display = "none";
    $("#lobby").style.display = "block";
    $("#gameId").innerText = `Game ID: ${session.gameId}`;
    $("#gameURL").innerText = location.origin + "/?id=" + session.gameId;
    $("#gameURL").href = "/?id=" + session.gameId;

    if (session.host === username) {
      $("#start-btn").style.display = "block";
    }

    $("#users").innerHTML = "";
    for (const user of session.users) {
      const li = document.createElement("li");
      li.innerText = user;
      $("#users").appendChild(li);
    }
  } else if (type === "game") {
    session = data;
    run(session);
  } else if (type === "results") {
    session = data;
    $("#results").innerHTML = "";
    $("#message").innerHTML =
      session.round < session.songs.length - 1
        ? "The next round will start soon..."
        : "";
    $("#gameURL").parentElement.style.display = "none";
    for (let i = 0; i < session.results.length; i++) {
      const h5 = document.createElement("h5");
      h5.innerText = `Song #${i + 1} / ${session.songs.length}: ${session.songs[i].name} (${session.songs[i].bpm} BPM)`;
      $("#results").appendChild(h5);

      const ol = document.createElement("ol");
      for (let j = 0; j < session.results[i].length; j++) {
        const li = document.createElement("li");
        li.innerText = `${session.results[i][j].username} - ${session.results[i][j].bpm.toFixed(2)} BPM | ${session.results[i][j].ur.toFixed(2)} UR`;
        if (j === 0) li.innerText += " 🏆";
        ol.appendChild(li);
      }
      $("#results").appendChild(ol);
    }
  } else if (type === "message") {
    $("#message").innerText = data;
  } else if (type === "error") {
    alert(data);
  }
};

let clicks = new Set(),
  pressed = [],
  recording = false;
document.onkeydown = (e) => {
  if (
    (e.key === $("#key1").value || e.key == $("#key2").value) &&
    recording &&
    !pressed.includes(e.key)
  ) {
    pressed.push(e.key);
    clicks.add(performance.now());
  }
};
document.onkeyup = (e) => {
  pressed = pressed.filter((p) => p !== e.key);
};

const fadeOut = (audio) => {
  if (audio.volume > 0) {
    audio.volume -= 0.01;
    timer = setTimeout(fadeOut, 100, audio);
  }
};

// algorithm from https://ckrisirkc.github.io/osuStreamSpeed.js/newmain.js
const calculate = (start, end, clicks) => {
  const clickArr = [...clicks];
  const bpm =
    Math.round((((clickArr.length / (end - start)) * 60000) / 4) * 100) / 100;
  const deltas = [];
  for (let i = 0; i < clickArr.length - 1; i++) {
    deltas.push(clickArr[i + 1] - clickArr[i]);
  }
  const deltaAvg = deltas.reduce((a, b) => a + b, 0) / deltas.length;
  const variance = deltas
    .map((v) => (v - deltaAvg) * (v - deltaAvg))
    .reduce((a, b) => a + b, 0);
  const stdev = Math.sqrt(variance / deltas.length);

  return { bpm: bpm || 0, ur: stdev * 10 || 0 };
};

// scoring algorithm
// first judge by whoever has round(bpm) closest to target bpm, if there is a tie, judge by lower UR
/*
session.results[session.round] = session.results[session.round].sort((a, b) => {
    const bpmDeltaA = Math.abs(Math.round(a.bpm) - session.songs[session.round].bpm);
    const bpmDeltaB = Math.abs(Math.round(b.bpm) - session.songs[session.round].bpm);
    if (bpmDeltaA !== bpmDeltaB) return bpmDeltaA - bpmDeltaB;
    return a.ur - b.ur
});
*/

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = async (session) => {
  clicks.clear();
  $("#lobby").style.display = "none";
  $("#game").style.display = "block";
  $("#bpm").innerText = `BPM: 0`;
  $("#ur").innerText = `UR: 0`;

  $("#song").innerText =
    `Song #${session.round + 1} / ${session.songs.length}: ${session.songs[session.round].name} (${session.songs[session.round].bpm} BPM)`;
  const audio = new Audio(`songs/${session.songs[session.round].file}`);
  audio.volume = 0.1;
  audio.currentTime = session.songs[session.round].startOffset;
  await new Promise((r) => (audio.oncanplaythrough = r));

  for (let i = 5; i >= 1; i--) {
    $("#timer").innerText = `Song starting in ${i}...`;
    await sleep(1000);
  }

  const timer = setInterval(() => {
    $("#timer").innerText =
      `Time remaining: ${(session.songs[session.round].duration - (audio.currentTime - session.songs[session.round].startOffset)).toFixed(2)}s`;
  }, 100);

  audio.play();
  // delay to start tapping
  await sleep(1000);
  let start = +new Date();
  recording = true;

  // delay to collect initial samples
  await sleep(500);
  while (
    audio.currentTime - session.songs[session.round].startOffset <
    session.songs[session.round].duration
  ) {
    const { bpm, ur } = calculate(start, +new Date(), clicks);
    $("#bpm").innerText = `BPM: ${bpm.toFixed(2)}`;
    $("#ur").innerText = `UR: ${ur.toFixed(2)}`;
    await sleep(50);
  }

  let end = +new Date();
  recording = false;
  $("#timer").innerText = `Time remaining: 0s`;
  fadeOut(audio);
  clearInterval(timer);

  ws.send(
    JSON.stringify({
      type: "results",
      data: { clicks: [...clicks], start, end },
    }),
  );
  $("#message").innerText = "Waiting for others to finish...";
  $("#game").style.display = "none";
  $("#lobby").style.display = "block";
};
```

#### Solution

I replaced the `stream-vs.js` with my own version using Burp Suite.

![burp-replace](/osu-gaming-ctf-2024-write-up/burp-replace.webp)

In my `stream-vs.js`, I use JavaScript to play the game for me.

```javascript
function click() {
  document.dispatchEvent(new KeyboardEvent("keydown", { key: "x" }));
  document.dispatchEvent(new KeyboardEvent("keyup", { key: "x" }));
}

function getClickInterval(bpm, duration) {
  // bpm = Math.round(((clickArr.length / (end - start) * 60000)/4) * 100) / 100;
  return 60 / bpm / 4 + 0.0003;
}

function startClicking(bpm, duration) {
  let interval = getClickInterval(bpm, duration * 1000);
  let timer = setInterval(click, interval * 1000);
  setTimeout(() => clearInterval(timer), duration * 1000 + 10000);
}
```

The `startClicking` function will be called at the beginning of each round. At the end of each round, `end` will be adjusted so the `bpm` will become exact.

```javascript
const run = async (session) => {
  // [...]
  const timer = setInterval(() => {
    $("#timer").innerText =
      `Time remaining: ${(session.songs[session.round].duration - (audio.currentTime - session.songs[session.round].startOffset)).toFixed(2)}s`;
  }, 100);

  startClicking(round_bmp, round_duration + 3);

  audio.play();
  // [...]
  while (
    audio.currentTime - session.songs[session.round].startOffset <
    session.songs[session.round].duration
  ) {
    // [...]
  }

  // make end so that the bpm becomes the same as the target bpm
  let end = start + ((clicks.size / round_bmp) * 60 * 1000) / 4;
  recording = false;
  $("#timer").innerText = `Time remaining: 0s`;
  // [...]
};
```

<img src="/osu-gaming-ctf-2024-write-up/stream-vs-res.webp" style="width: min(28em, 100%);">
