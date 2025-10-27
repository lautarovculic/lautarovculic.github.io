**Description**: SwizzleMeTimbers is a pirate-themed iOS app with a secret buried deep inside its view controller. A simple button reads “Unlock Treasure”, but it’s protected by a method that always returns false, unless you’re crafty enough to change its behavior at runtime.

**Link**: https://academy.8ksec.io/course/ios-application-exploitation-challenges

![[8ksec-swizzleMeTimbers1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Recon
In this application, we can see a simple button that says "**Unlock Treasure**"

If we click it, we see a message that says "**That ain't the pirate's path**"

Inside of `Payload/SwizzleMeTimbers.app/` we can see the **`SwizzleMeTimbers.debug.dylib`**.

Let's **import this file into Ghidra** for examine some code.

But before, let's explore some **classes** with **Frida**!

Here's the code:
```javascript
// list classes and methods
if (!ObjC.available) throw new Error("ObjC not found");

for (const n in ObjC.classes) {
  if (/ViewController|Treasure|Swizzle/i.test(n)) console.log("[C]", n);
}

const CANDIDATE = "NOT YET";
if (ObjC.classes[CANDIDATE]) {
  console.log("[Methods of]", CANDIDATE, ObjC.classes[CANDIDATE].$methods);
}
```
Get your **Identifier** with
```bash
frida-ps -Uai | grep Swizzle
```

Now run the command:
```bash
frida -U -f com.8ksec.SwizzleMeTimbers.YX4C7J2RLK -l recon.js
```
In the output we found a **Interesting class** named **`SwizzleMeTimbers.Q9V0`**

Let's add in the `const CANDIDATE` in the script (replace `NOT YET`). And run again the script.

We can see now in the output a huge list of **methods**:
```bash
[Methods of] SwizzleMeTimbers.Q9V0 +
```
After a huge look, I found **two methods**:

- `_9zB`

- `t4G0`

So, let's go now to **Ghidra** and we will look for this suspicious classes and methods.

First, the **`_9zB`** method **always will return `false`**:
```C
/* SwizzleMeTimbers.Q9V0._9zB() -> Swift.Bool */

bool __thiscall SwizzleMeTimbers::Q9V0::_9zB(Q9V0 *this)

{
  return false;
}
```
This method  `_9zB()` is the **logical guard that controls whether the user can unlock the treasure**.

But **if this is `true`** will trigger the **`t4G0`** method!
```C
void $$SwizzleMeTimbers.Q9V0.(t4G0_in__8DFD43FAB028256CB03EE728FE8EB512)()_->_()(void)

{
  _8DFD43FAB028256CB03EE728FE8EB512 *p_Var1;
  _8DFD43FAB028256CB03EE728FE8EB512 *unaff_x20;
  String SVar2;
  String SVar3;
  
  p_Var1 = unaff_x20;
  _objc_msgSend();
  if (((uint)p_Var1 & 1) == 0) {
    SVar2 = Swift::String::init(s_Nah_0000cc36,10,0);
    SVar3 = Swift::String::init(s_That_ain_t_the_pirate_s_path._0000cc50,0x21,0);
    $$SwizzleMeTimbers.Q9V0.(_P0_in__8DFD43FAB028256CB03EE728FE8EB512)(Swift.String,Swift.String)_-> _()
              (SVar2.str,SVar2.bridgeObject,SVar3.str);
    _swift_bridgeObjectRelease(SVar3.bridgeObject);
    _swift_bridgeObjectRelease(SVar2.bridgeObject);
  }
  else {
    SVar2 = Swift::String::init(s_Ye_got_it_0000cc80,0x17,0);
    SVar3 = SwizzleMeTimbers::Q9V0::_8DFD43FAB028256CB03EE728FE8EB512::get_g0(unaff_x20);
    $$SwizzleMeTimbers.Q9V0.(_P0_in__8DFD43FAB028256CB03EE728FE8EB512)(Swift.String,Swift.String)_-> _()
              (SVar2.str,SVar2.bridgeObject,SVar3.str);
    _swift_bridgeObjectRelease(SVar3.bridgeObject);
    _swift_bridgeObjectRelease(SVar2.bridgeObject);
  }
  return;
}
```

- When you press **Unlock Treasure**, `t4G0` is called.

- This method executes `_9zB()` as **validation**.

- If **`true`**, the flag is obtained via `g0()` and displayed in a **`UIAlertController`**.
### Unlocking the Treasure
Since `_9zB()` was **exposed as an ObjC method**, we **dynamically overrode it with Frida**:
```javascript
if(!ObjC.available) throw "ObjC off";

const VC = ObjC.classes["SwizzleMeTimbers.Q9V0"];
VC["- _9zB"].implementation = ObjC.implement(VC["- _9zB"], () => 1); // force bool

let shown = false;
const AC = ObjC.classes.UIAlertController;
const S = "- setMessage:";
const o = AC[S].implementation;

AC[S].implementation = ObjC.implement(AC[S], function (self, _cmd, msg) {
  try {
    const s = new ObjC.Object(msg).toString();
    if (!shown && /CTF\{.*\}/.test(s)) {
      shown = true;
      console.log("---hook--- " + s);
    }
  } catch (_) {}
  return o(self, _cmd, msg);
});

// trigger IBAction
ObjC.schedule(ObjC.mainQueue, () => {
  ObjC.choose(VC, {
    onMatch(i) { if (i["- t4G0:"]) i["- t4G0:"](ptr(0)); },
    onComplete() {}
  });
});
```

And now run the Frida command:
```bash
frida -U -f com.8ksec.SwizzleMeTimbers.YX4C7J2RLK -l swizzle.js
```
Press the **Unlock Treasure** button and now you will get the flag!!

![[8ksec-swizzleMeTimbers2.png]]

#### Glossary

| API / Function                      | Description                                      |
| ----------------------------------- | ------------------------------------------------ |
| `ObjC.implement()`                  | Defines a new implementation for a class method  |
| `UIAlertController`                 | Native component to display alerts               |
| `- setMessage:`                     | Message setter within the `UIAlertController`    |
| `- t4G0:`                           | IBAction selector when pressing the button       |
| `- _9zB`                            | Swift method that acts as a guard                |
| `ObjC.choose()`                     | Finds live instances of a class in memory        |
| `ObjC.schedule(ObjC.mainQueue, fn)` | Executes code on the main thread (needed for UI) |

**Some considerations**

- The `_9zB()` method **wasn't visible in the U**I, but it was **swizzleable because it was generated as an ObjC selector**.

- The `g0()` method **that returns the flag didn't need to be hooked**, as the *UIAlert exposed it directly*.

- Using *UIAlertController allowed the flag to be sniffed* without the need for further reversing.

**Flag**: **`CTF{{Swizzle_mbers}}`**

I hope you found it useful (:
