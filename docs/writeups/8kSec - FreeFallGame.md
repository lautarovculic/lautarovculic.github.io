---
title: 8kSec - FreeFallGame
description: "Experience the thrill of FreeFall, an addictive iOS ball game that challenges your reflexes and precision! Navigate a fast-moving ball through obstacles using intuitive paddle controls and all under a 60-second time limit."
tags:
  - flutter
  - reflutter
  - frida-trace
  - fridump
  - frida
  - rev-binaries
  - 8ksec
  - ios
keywords:
  - ios hacking
  - ctf writeup
  - 8ksec
  - mobile writeups
  - ios reversing
  - ios exploitation
  - mobile security research
canonical: https://lautarovculic.github.io/writeups/8kSec%20-%20FreeFallGame/
---

**Description**: Experience the thrill of FreeFall, an addictive iOS ball game that challenges your reflexes and precision! Navigate a fast-moving ball through obstacles using intuitive paddle controls and all under a 60-second time limit.

**Link**: https://academy.8ksec.io/course/ios-application-exploitation-challenges

![[8ksec-freeFallGame1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Recon
We are facing an arcade game, which if we look inside `Payload/Runner.app` we can notice that we are dealing with a **flutter app**.

So, in first place, we need use **reFlutter**.

reFlutter is a tool for decompiling and rebuilding Flutter apps:

- The **Flutter app on iOS compiles the entire Dart file into the App.framework/App (Mach-O binary)**.

- What reFlutter does is *extract and disassemble those sections, reconstructing the Dart AOT snapshots into readable Dart pseudo-code*.

- It allows you to **reverse engineer Flutter logic into an API**, just like on Android: internal paths, validations, strings, endpoints, debug flags, etc.

- The difference is that on iOS, *the binary is in Mach-O, not in ELF like Android* (`libapp.so`).

Install reFlutter using `pip`
```bash
pip3 install reflutter
```
Then:
```bash
reflutter 1-FreeFall.ipa
```
Select option 2 and put your host IP. The output will be *another `.ipa`* file: `release.RE.ipa`

Install using *sideloadly* the new file (uninstalling the original version before).

And then, using `ssh` on our iPhone will need find the **`dump.dart`** file.
```bash
iPhoneHack:/var/mobile/Containers/Data/Application root# ls -l /var/mobile/Containers/Data/Application/
```
There are a lot of UUID, for search `FreeFallGame`:
```bash
find /var/mobile/Containers/Data/Application/ -name "*.plist" | grep -i Free
```
In my case, the UUID is `C402751A-E920-41A5-8EEF-2DE3BF9A4007`.

Inside of `Documents` directory, you will find the `dump.dart` file:
```bash
iPhoneHack:/var/mobile/Containers/Data/Application/C402751A-E920-41A5-8EEF-2DE3BF9A4007/Documents root# ls
dump.dart  freefallgame.db  security_tokens.db
```

Let's use **`scp`** for file transfer:
```bash
scp root@192.168.0.248:/var/mobile/Containers/Data/Application/C402751A-E920-41A5-8EEF-2DE3BF9A4007/Documents/dump.dart .
```
Now we can work with the `dump.dart` looking for **methods** and **classes** that we can use for complete the challenge.

I found the **method** **`submitScore`** from **`GameEngine`** **class**.
```json
{"method_name":"submitScore","offset":"0x0000000000171f10","library_url":"package:freefallgame\/game_engine.dart","class_name":"GameEngine"}
```

Also, among the important Flutter functions:

- `Leaderboard.submitScore(score)`

- `GameEngine._score`

- `GameEngine._submitScore()` — *relevant, seems to be the final internal*

- `LeaderboardDatabase.insert()` — *SQL logic with token and score*

- Flutter bindings: `FlutterMethodCall`, `FlutterMethodChannel`

This pattern suggests a Flutter → ObjC → SQLite → Backend encapsulation.

Anyway, I decide work with **`+[FlutterMethodCall methodCallWithMethodName:arguments:]`**.

- The `+` indicates that **it's a class method** (not an instance method). That is, it can be called directly on the `FlutterMethodCall` class and not on a created object.

- The `methodCallWithMethodName:arguments:` signature is a **constructor/factory method that creates an instance of `FlutterMethodCall` from**:

	- `methodName` → the name of the Flutter method being called.

	- `arguments` → the associated arguments.

So, in the practice:

- Flutter uses `FlutterMethodChannel` when **communicating between Dart and iOS (Objective-C/Swift)**.

- Each *invocation on the Dart side is translated into a `FlutterMethodCall` object on iOS*.

- This *class method constructs that object, packaging the name and args in a form that the `MethodChannel` can dispatch to the native handler*.

So, when you **trace it with Frida**, hooking `+[FlutterMethodCall methodCallWithMethodName:arguments:]` lets you see **all the calls Flutter sends to the native iOS side: the method names and their raw arguments**.

It's a *strategic hook point for inspecting or manipulating the communication layer between Dart and the native bridge*.

Let's hook!
```bash
frida-trace -U -f com.eightksec.freefallgame.YX4C7J2RLK -m '+[FlutterMethodCall methodCallWithMethodName:arguments:]'
```
We can see that the method is called when we submit the score!

And, a file is *autogenerated* by Frida:

- `__handlers__/FlutterMethodCall/methodCallWithMethodName_arguments_.js`

Let's modify that for get more context and information:

Just modify the `methodCallWithMethodName_arguments_.js` file and put this JavaScript code:
```javascript
defineHandler({
  onEnter: function (log, args, state) {
    try {
      var methodName = new ObjC.Object(args[2]).toString();   // NSString*
      var dict       = new ObjC.Object(args[3]);              // NSDictionary*
      log("method=" + methodName);
      log("args=" + dict.toString());
      var arr = dict.objectForKey_("arguments");
      if (arr) log("arguments=" + arr.toString());
    } catch (e) { log("ERR " + e); }
  },

  onLeave: function (log, retval, state) { }
});
```

Now if we running again the **`frida-trace`** command, when you *submit the score*:
```json
/* TID 0x6a07 */
 92185 ms  method=openDatabase
 92185 ms  args={
    path = "/var/mobile/Containers/Data/Application/A67DB2A3-E846-40B5-AA10-B6B60B75254B/Documents/security_tokens.db";
    singleInstance = 1;
}
 92188 ms  method=query
 92188 ms  args={
    id = 3;
    sql = "PRAGMA user_version";
}
 92190 ms  method=query
 92190 ms  args={
    arguments =     (
        1758461569262
    );
    id = 3;
    sql = "SELECT * FROM tokens WHERE expiry > ? LIMIT 1";
}
 92190 ms  arguments=(
    1758461569262
)
           /* TID 0x32f3 */
 92192 ms  method=closeDatabase
 92192 ms  args={
    id = 3;
}
 92196 ms  method=openDatabase
 92196 ms  args={
    path = "/var/mobile/Containers/Data/Application/A67DB2A3-E846-40B5-AA10-B6B60B75254B/Documents/security_tokens.db";
    singleInstance = 1;
}
 92197 ms  method=query
 92197 ms  args={
    id = 4;
    sql = "PRAGMA user_version";
}
 92198 ms  method=query
 92198 ms  args={
    arguments =     (
        1758461569270
    );
    id = 4;
    sql = "SELECT * FROM tokens WHERE expiry > ? LIMIT 1";
}
 92198 ms  arguments=(
    1758461569270
)
 92200 ms  method=closeDatabase
 92200 ms  args={
    id = 4;
}
 92201 ms  method=openDatabase
 92201 ms  args={
    path = "/var/mobile/Containers/Data/Application/A67DB2A3-E846-40B5-AA10-B6B60B75254B/Documents/security_tokens.db";
    singleInstance = 1;
}
 92202 ms  method=query
 92202 ms  args={
    id = 5;
    sql = "PRAGMA user_version";
}
 92203 ms  method=query
 92203 ms  args={
    arguments =     (
        5d9670b4e79f841111dec8ba52d1e33f0053c9c277b4692b8f8facd780727208,
        1758461569275
    );
    id = 5;
    sql = "SELECT * FROM tokens WHERE token = ? AND expiry > ?";
}
 92203 ms  arguments=(
    5d9670b4e79f841111dec8ba52d1e33f0053c9c277b4692b8f8facd780727208,
    1758461569275
)
 92205 ms  method=closeDatabase
 92205 ms  args={
    id = 5;
}
 92206 ms  method=insert
 92206 ms  args={
    arguments =     (
        test2,
        720,
        1758461569278,
        5d9670b4e79f841111dec8ba52d1e33f0053c9c277b4692b8f8facd780727208
    );
    id = 2;
    sql = "INSERT INTO leaderboard (name, score, timestamp, token) VALUES (?, ?, ?, ?)";
}
 92206 ms  arguments=(
    test2,
    720,
    1758461569278,
    5d9670b4e79f841111dec8ba52d1e33f0053c9c277b4692b8f8facd780727208
)
           /* TID 0x6a07 */
 92216 ms  method=query
 92216 ms  args={
    id = 2;
    sql = "SELECT * FROM leaderboard";
}
           /* TID 0x103 */
 92218 ms  method=read
 92218 ms  args={
    key = "db_encryption_key";
    options =     {
        accessibility = unlocked;
        accountName = "flutter_secure_storage_service";
        synchronizable = false;
    };
}
 92220 ms  method=write
 92220 ms  args={
    key = "db_signature";
    options =     {
        accessibility = unlocked;
        accountName = "flutter_secure_storage_service";
        synchronizable = false;
    };
    value = 6064ad2b75dfa8144654071ef2149e313d2a93df6ed2c47c89963152d3fe0545;
}
 92228 ms  method=TextInput.clearClient
 92228 ms  args=nil
 92228 ms  ERR TypeError: not a function
 92229 ms  method=TextInput.hide
 92229 ms  args=nil
 92229 ms  ERR TypeError: not a function
 92234 ms  method=TextInputClient.onConnectionClosed
 92234 ms  args=(
    0
)
 92234 ms  ERR TypeError: not a function
           /* TID 0x32f3 */
 92244 ms  method=query
 92244 ms  args={
    id = 2;
    sql = "SELECT * FROM leaderboard ORDER BY score DESC LIMIT 20";
}
```

We can see **that the application performs a series of SQL operations with the files we previously found in the Documents directory** (where we extracted the `dump.dart`).
### Score flow

1. The player taps the screen to keep the ball in the air.

2. Each collision with an obstacle adds X point.

3. The `GameEngine` maintains a `_score` property, which is *incremented locally*.

4. When the* game ends*, the `_submitScore()` function is called.

5. The **score information is serialized and sent as a `FlutterMethodCall` with the insert method**.

6. In Objective-C (iOS), this method calls **`+[FlutterMethodCall methodCallWithMethodName:arguments:]`**.

7. An SQL call is constructed with the following parameters:
```SQL
INSERT INTO leaderboard (name, score, timestamp, token)
```
Where **score is index 1 of the "arguments" array**.

In the `frida-server` output we can check that:
```json
92206 ms  method=insert
 92206 ms  args={
    arguments =     (
        test2,
        720,
        1758461569278,
        5d9670b4e79f841111dec8ba52d1e33f0053c9c277b4692b8f8facd780727208
    );
    id = 2;
    sql = "INSERT INTO leaderboard (name, score, timestamp, token) VALUES (?, ?, ?, ?)";
}
 92206 ms  arguments=(
    test2,
    720,
    1758461569278,
    5d9670b4e79f841111dec8ba52d1e33f0053c9c277b4692b8f8facd780727208
)
```
### PoC
What's the objective? Intercept `+[FlutterMethodCall methodCallWithMethodName:arguments:]` and **overwrite the score value before it is serialized to SQLite**.

```javascript
'use strict';

const NSNumber = ObjC.classes.NSNumber;
const NSMutableArray = ObjC.classes.NSMutableArray;
const FlutterMethodCall = ObjC.classes.FlutterMethodCall;
const method = FlutterMethodCall["+ methodCallWithMethodName:arguments:"];

Interceptor.attach(method.implementation, {
  onEnter(args) {
    try {
      const methodName = ObjC.Object(args[2]).toString();
      if (methodName !== "insert") return;

      const originalDict = ObjC.Object(args[3]);
      const modifiedArgs = NSMutableArray.array();
      const values = originalDict.objectForKey_("arguments");

      for (let i = 0; i < values.count(); i++) {
        const item = values.objectAtIndex_(i);
        modifiedArgs.addObject_(i === 1 ? NSNumber.numberWithInt_(13371337) : item);
      }

      const mutable = originalDict.mutableCopy();
      mutable.setObject_forKey_(modifiedArgs, "arguments");
      args[3] = mutable;
    } catch (_) {}
  }
});
```

So, Its method `+ methodCallWithMethodName:arguments:` is invoked just before the "*insert*" method call.

- We intercept this method to:

	- **Read** the original dictionary (**`NSDictionary`**).
  
	- **Replace** index 1 (*score*) with `NSNumber.numberWithInt_(13371337)`.

	- Inject the modified dictionary into `args[3]`.

*This happens before any serialization*, meaning the DB and backend receive a valid but altered score.

- **`NSDictionary` / `NSMutableDictionary`**: Foundation's *immutable/mutable dictionary*.

- **`NSMutableArray`**: *Objective-C dynamic array*.

- **`NSNumber`**: *Wrapper for primitive types such as int, float, etc*. Necessary to maintain type integrity when injecting the new score.

- **`ObjC.Object(args[n])`**: *Frida API that allows you to convert a native pointer to an Objective-C object* for inspection or modification.

So, launch the app with the PoC script:
```bash
frida -U -f com.eightksec.freefallgame.YX4C7J2RLK -l hookGame.js
```
Tap play and just wait, then, put your name for leaderboard and see the `13371337` score!

You can also set `-1` as score, just because 8kSec mention as goal:

- *submit arbitrary scores that would be impossible to achieve through normal play*

![[8ksec-freeFallGame2.png]]

I hope you found it useful (:
