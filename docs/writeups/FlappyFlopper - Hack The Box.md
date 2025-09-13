![[htb-flappyFlopper1.png]]
**Difficult:** Medium

**Category**: GamePwn

**OS**: Android

**Description**: No one has got 10000 score yet! Are you able to do so?

----

Download and **extract** the **.zip** file with **hackthebox** as password.

Install the `.apk` file using **ADB**
```bash
adb install -r Flappyflopper.arm64-v8a.apk
```

We can see that this is the kind of famous **Flappy Bird game**. Our goal is get **10000 points**!
### Recon
Let's *analyze the source code*. For that, we'll use **JADX**!

Looking in the `AndroidManifest.xml` file we can see the **package name**, which is `com.apuf.flapyfloper`.

Quickly, we can see the **`MainActivity`** in the `.xml` file:
```XML
<activity
    android:theme="@style/UnityThemeSelector"
    android:name="com.unity3d.player.UnityPlayerActivity"
    android:enabled="true"
    android:exported="true"
    android:launchMode="singleTask"
    android:screenOrientation="portrait"
    android:configChanges="fontScale|layoutDirection|density|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|navigation|keyboardHidden|keyboard|touchscreen|locale|mnc|mcc"
    android:hardwareAccelerated="false"
    android:resizeableActivity="false">
    <intent-filter>
        <category android:name="android.intent.category.LAUNCHER"/>
        <category android:name="android.intent.category.LEANBACK_LAUNCHER"/>
        <action android:name="android.intent.action.MAIN"/>
    </intent-filter>
    <meta-data
        android:name="unityplayer.UnityActivity"
        android:value="true"/>
    <meta-data
        android:name="notch_support"
        android:value="true"/>
</activity>
```

Notice that the class name is `UnityPlayerActivity`. So, we are reversing an **Unity** game!

Let's *decompile* the application using **apktool**:
```bash
apktool d Flappyflopper.arm64-v8a.apk
```

Inside we can found the `assets` directory, which have the following content:
```bash
assets
├── available_features.json
├── available.tflite
├── bin
│   └── Data
│       ├── boot.config
│       ├── data.unity3d
│       ├── Managed
│       │   ├── Metadata
│       │   │   └── global-metadata.dat
│       │   └── Resources
│       │       ├── mscorlib.dll-resources.dat
│       │       └── System.Data.dll-resources.dat
│       ├── Resources
│       │   └── unity default resources
│       ├── RuntimeInitializeOnLoads.json
│       ├── ScriptingAssemblies.json
│       └── unity_app_guid
├── oom_features.json
├── oom.tflite
├── realtime_features.json
├── realtime.tflite
└── unity_obb_guid
```

And the libraries:
```bash
lib
└── arm64-v8a
    ├── libil2cpp.so
    ├── libmain.so
    └── libunity.so
```

Looks like we'll have to **work with IL2CPP**!

But, **what's IL2CPP**?

**Definition**:

*IL2CPP (Intermediate Language To C++) is a scripting backend developed by Unity, serving as an alternative to the Mono backend. Its primary function is to enhance the performance, security, and platform compatibility of Unity projects, particularly when deploying to a wide range of platforms.*

So, where the information of our interest is located?

In the `assets/bin/Data/Managed/Metadata` directory, we can see the `global-metadata.dat` file **contains the class, methods and fields**.


Also `ScriptingAssemblies.json` confirms **`Assembly-CSharp`** as the *game container*.


By the way, we can **enumerate** which *custom* class are using in the app using **Frida**!

We *can hook at a high level with the bridge* (methods/fields) or **go all out using the native method's VA**. I chose the latter for maximum robustness.

Fortunately, there are geniuses who have already made our job easier, we can find it in this repository:
- https://github.com/vfsfitvnm/frida-il2cpp-bridge

Install with **npm**
```bash
npm install frida-il2cpp-bridge
```
Let's search the bridge script:
```bash
echo $(npm root -g)/frida-il2cpp-bridge/dist/index.js
```
This will drop a path with the script that we need use for hooking, in my case:
- `/home/lautaro/.nvm/versions/node/v20.18.2/lib/node_modules/frida-il2cpp-bridge/dist/index.js`

So, I develop a *frida script* that **discover the Classes, Methods and Fields**:
```javascript
// check this before https://github.com/vfsfitvnm/frida-il2cpp-bridge
// enumerate class and methods for Unity games
// discover.js — use global Il2Cpp from bridge (no require)
'use strict';
const wait = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  while (!Module.findBaseAddress('libil2cpp.so')) await wait(100);

  Il2Cpp.perform(() => {
    const asm = Il2Cpp.domain.assembly('Assembly-CSharp');
    if (!asm) { console.log('[-] Assembly-CSharp not loaded yet'); return; }
    const img = asm.image;

    const CLASS_RX = /(score|game|bird|pipe|spawner|manager|hud|ui)/i;
    const FIELD_RX = /(score|points|high.?score|best.?score)/i;
    const METH_RX  = /(add|set|increase).*score|onpass|gameover|die|ontriggerenter2d|oncollisionenter2d|update/i;

    for (const k of img.classes) {
      if (!CLASS_RX.test(k.name)) continue;

      const fields = [];
      for (const f of k.fields) {
        try {
          if (FIELD_RX.test(f.name || '')) {
            fields.push(`${f.isStatic ? 'static ' : ''}${f.type?.name || '?'} ${f.name}`);
          }
        } catch (_) {}
      }

      const methods = [];
      for (const m of k.methods) {
        try {
          if (METH_RX.test(m.name)) {
            const sig = `${m.returnType?.name || 'void'} ${k.name}::${m.name}(${m.parameters.map(p => p.type?.name || '?').join(', ')})`;
            methods.push(sig);
          }
        } catch (_) {}
      }

      if (fields.length || methods.length) {
        console.log(`\n[CLASS] ${k.name}`);
        if (fields.length)  console.log('  Fields:\n   - ' + fields.join('\n   - '));
        if (methods.length) console.log('  Methods:\n   - ' + methods.join('\n   - '));
      }
    }
  });
})();
```

I'll set to a *variable* `BRIDGE` the previous path:
```bash
BRIDGE="/home/lautaro/.nvm/versions/node/v20.18.2/lib/node_modules/frida-il2cpp-bridge/dist/index.js"
```

So, put running *frida server* in your phone and then, run the following frida command in your client (PC):
```bash
frida -U "Flappyflopper" --runtime=v8 \
  -l "$BRIDGE" \
  -l discover.js
```
Output:
```bash
[CLASS] BirdControl
  Fields:
   - Score scoreText
  Methods:
   - System.Void BirdControl::Update()
   - System.Void BirdControl::OnTriggerEnter2D(UnityEngine.Collider2D)
   - System.Void BirdControl::GameOver()

[CLASS] GameMain
  Methods:
   - System.Void GameMain::Update()

[CLASS] PipeMove
  Methods:
   - System.Void PipeMove::Update()
   - System.Void PipeMove::GameOver()

[CLASS] PipeSpawner
  Methods:
   - System.Void PipeSpawner::GameOver()

[CLASS] Score
  Fields:
   - UnityEngine.UI.Text scoreText
   - System.Int32 score
  Methods:
   - System.Void Score::UpdateScoreText()
```

This is really interesting!

We can see the *functions and classes that interest us most*.

We will *focus* in:
```bash
[CLASS] Score
  Fields:
   - UnityEngine.UI.Text scoreText
   - System.Int32 score
  Methods:
   - System.Void Score::UpdateScoreText()
```
Why? **Runs every time the HUD updates** → perfect *synchronization point*. On `ARM64`, `x0` is `this` → writing `this + offset(score)` before the body *ensures that the game code itself renders the forced value*.

Avoid *dealing with UI overloads* (`Text/TMP_Text`) and *trigger timing*.


But before, what is **VA**? 

**VA = Virtual Address**: The absolute virtual address (*post-ASLR*) of the *method's native entry point within the process*. In Unity IL2CPP, *every C# method ends as a native function*.

The bridge (`frida-il2cpp-bridge`) **gives you that VA with `method.virtualAddress`** so you can `Interceptor.attach(va, ...)` to it.


**RVA is the offset relative to the base of `libil2cpp.so`**. The *bridge resolves both* from `MethodInfo/FieldInfo` using `global-metadata.dat`.


How does bridge “resolve” it?

It uses *il2cpp's APIs/structures and metadata* (`global-metadata.dat`) to map: *domain* → *assemblies* → *images* → *classes* → *methods/fields*.

From each `MethodInfo`, it *obtains the code pointer* (VA) and from each `FieldInfo`, the *offset within the object*.

This is why we were able to: **read `fScore.offset`, and hook `mUpd.virtualAddress`**.
### Solution
So *I hooked the VA* and, on `ARM64` where `x0` is `this`, I wrote `this+offset = 10000`. When the *method was executed*, the **UI itself took the already patched value** and **displayed the manipulated score**.
```javascript
// native score
'use strict';
const wait = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  while (!Module.findBaseAddress('libil2cpp.so')) await wait(100);

  Il2Cpp.perform(() => {
    const img   = Il2Cpp.domain.assembly('Assembly-CSharp').image;
    const Score = img.class('Score');
    const fScore = Score.field('score');
    const mUpd   = Score.method('UpdateScoreText');

    const addr = mUpd.virtualAddress;
    if (!addr) { console.log('no UpdateScoreText'); return; }

    // x0 = this
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          const self = args[0];
          self.add(fScore.offset).writeS32(10000); // set score
        } catch (_) {}
      }
    });

    console.log('hook');
  });
})();
```

So, run again the Frida command but now with `hook.js`
```bash
frida -U "Flappyflopper" --runtime=v8 \
  -l "$BRIDGE" \
  -l writeScore.js
```
Make 1 point and *the score will set to 10000*, given us the **flag**!

![[htb-flappyFlopper2.png]]

I hope you found it useful (:
