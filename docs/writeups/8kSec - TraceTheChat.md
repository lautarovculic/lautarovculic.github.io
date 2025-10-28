**Description**: TraceTheChat is a seemingly innocent messaging app. Type a message, hit send, and it gets routed to a mysterious contact. But beneath the surface, the message travels through an obfuscated class that hides the details from plain sight.

**Link**: https://academy.8ksec.io/course/ios-application-exploitation-challenges

![[8ksec-traceTheChat1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Recon
For this challenge I decided to do it 100% with Frida and not decompile the app.
For this, **the best tool for dynamically recognizing the application's behavior is `frida-trace`**.

We can guess that the module is **`TraceTheChat`**.
You can get the *identifier* with this Frida command:
```bash
frida-ps -Uai | grep TraceTheChat
```
Output:
```bash
4564  TraceTheChat     com.8ksec.TraceTheChat.YX4C7J2RLK
```

So, let's enum with `frida-trace`:
```bash
frida-trace -U -f com.8ksec.TraceTheChat.YX4C7J2RLK -i '*TraceTheChat*'
```
We can say *that the most important function*, and where we need to focus, is the **Send button**. This is *where we can use the hook to intercept and process the communication* we need to complete the challenge, basically, the **recipient and the content of the message**.

Output:
```bash
 /* TID 0x103 */
 15239 ms     | $s12TraceTheChat13MessageRouterC6sharedACvau()
 15239 ms     |    | $s12TraceTheChat13MessageRouterCMa()
 15240 ms     |    | $s12TraceTheChat13MessageRouterCACycfC()
 15240 ms     |    |    | $s12TraceTheChat13MessageRouterCACycfC()
 15240 ms     |    |    |    | $s12TraceTheChat13MessageRouterCMa()
 15240 ms     | $s12TraceTheChat13MessageRouterC8dispatch_2toySS_SStF()
 15240 ms     |    | $s12TraceTheChat10ObfMessageCMa()
 15240 ms     |    | $s12TraceTheChat10ObfMessageC3msg7contactACSS_SStcfC()
 15240 ms     |    |    | $s12TraceTheChat10ObfMessageC3msg7contactACSS_SStcfc()
 15240 ms     |    |    |    | $s12TraceTheChat10ObfMessageCMa()
 15240 ms     |    | $s12TraceTheChat18InternalMsgHandlerC6sharedACvau()
 15240 ms     |    |    | $s12TraceTheChat18InternalMsgHandlerCMa()
 15241 ms     |    |    | $s12TraceTheChat18InternalMsgHandlerCACycfC()
 15241 ms     |    |    |    | $s12TraceTheChat18InternalMsgHandlerCACycfc()
 15241 ms     |    |    |    |    | $s12TraceTheChat18InternalMsgHandlerCMa()
 15241 ms     |    | $s12TraceTheChat18InternalMsgHandlerC5route3msgyAA10ObfMessageC_tF()
 15242 ms     | $s12TraceTheChat11ContentViewV4bodyQrvg()
```

From here we can get interesting functions:
- **`$s12TraceTheChat13MessageRouterC8dispatch_2toySS_SStF()`**
- **`$s12TraceTheChat10ObfMessageCMa()`**
- **`$s12TraceTheChat10ObfMessageC3msg7contactACSS_SStcfC()`**
- **`$s12TraceTheChat18InternalMsgHandlerC5route3msgyAA10ObfMessageC_tF()`**
- ...

We will focus on **`$s12TraceTheChat13MessageRouterC8dispatch_2toySS_SStF()`**.
Let me break this function down:
`$s`: *Swift* prefix.
`12TraceTheChat`: length 12 + *TraceTheChat* **module**.
`13MessageRouter`: length 13 + *MessageRouter* **type**.
`C`: is a **class**.
`8dispatch`: length 8 + **dispatch method name**.
`_2to`: Parameter labels. First parameter unlabeled (`_`), second labeled `to`(length 2).
`SS_SS`: Parameter **types**: **`Swift.String`**, **`Swift.String`**.
`t`: End of parameter tuple.
`y`: return `()` (**Void**).
`F`: End of function signature.

So, we can translate into:
- **`TraceTheChat.MessageRouter.dispatch(_:to:) -> Void`**
That is perfect for our hook!

Also, we can *enumerate this* using the following JavaScript code:
```javascript
Process.enumerateModules().forEach(mod => {
    if (mod.name.includes("TraceTheChat")) {
        console.log("module:", mod.name);
        mod.enumerateSymbols().forEach(sym => {
            if (sym.name.includes("dispatch")) {
                console.log("--", sym.name, "@", sym.address);
            }
        });
    }
});
```

Then, using Frida:
```bash
frida -U -f com.8ksec.TraceTheChat.YX4C7J2RLK -l searchFunction.js
```
### Trying to get the messages
A moment ago we identified the function that interests us with `frida-trace`.
`frida-trace` generates **hook files for each of the functions it inspects**. We can view them before it begins tracing the functions.

To further *filter the function*, we can use the following command:
```bash
frida-trace -U -f com.8ksec.TraceTheChat.YX4C7J2RLK -i '$s12TraceTheChat*dispatch*'
```
Output:
```bash
$s12TraceTheChat13MessageRouterC8dispatch_2toySS_SStF: Loaded handler at "/Users/lautaro/Documents/8ksec/traceTheChat/writeup/__handlers__/TraceTheChat.debug.dylib/_s12TraceTheChat13MessageRouterC_baa2796e.js"
```

So, the handler is located in `__handlers__` directory, we can see the `.js` file. Open it and then, modify the code to this:
```javascript
defineHandler({
  onEnter: function (log, args, state) {
    log('dispatch(message:to:)');

    // in swift args[1] = message and args[2] is to
    for (var i = 0; i < 4; i++) {
      try {
        if (args[i]) {
          log('arg[' + i + '] = ' + args[i]);

          // hexdump
          try {
            if (!args[i].isNull()) {
              log('  [HEX] ' + hexdump(args[i], { length: 32, ansi: false }).split('\n').slice(0,2).join(' '));
            }
          } catch (e) {}
        }
      } catch (e) {
        log('Error processing arg[' + i + ']: ' + e.message);
      }
    }

    // stack trace --------
    try {
      var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 5)
        .map(function (d) { return '    ' + d.toString(); })
        .join('\n');
      log('bt:\n' + bt);
    } catch (e) {}

    log('end---------------------');
  }
});
```

With this code we **can see the arguments**, which, if we run `frida-trace` again *but with the updated handler*, we can see the following:
```bash
Started tracing 1 function. Web UI available at http://localhost:60831/
           /* TID 0x103 */
  4000 ms  dispatch(message:to:)
  4000 ms  arg[0] = 0x61
  4000 ms  arg[1] = 0xe100000000000000
  4000 ms  arg[2] = 0x313030395f746f42
  4000 ms  arg[3] = 0xe800000000000000
  4000 ms  bt:
    0x100dbe80c TraceTheChat.debug.dylib!ContentView.sendMessage()
    0x100dbe668 TraceTheChat.debug.dylib!closure #1 in closure #2 in closure #1 in ContentView.body.getter
    0x196a3335c SwiftUI!0x7d735c (0x18ac6f35c)
    0x196a33844 SwiftUI!0x7d7844 (0x18ac6f844)
    0x196a3376c SwiftUI!0x7d776c (0x18ac6f76c)
  4000 ms  end---------------------
```

And here is:
```bash
4000 ms  arg[0] = 0x61
4000 ms  arg[1] = 0xe100000000000000
4000 ms  arg[2] = 0x313030395f746f42
4000 ms  arg[3] = 0xe800000000000000
```
I sent the message with `a` as body. In hex, `a` is `0x61`!
And `0x313030395f746f42` is **`Bot_9001`**!
But, there's a problem, because we can see that if we use hexdump, the *output* is `1009_toB`!
It’s because of little-endian… and **because of Swift Small String Optimization (SSO)**.

![[8ksec-traceTheChat2.png]]
In memory (little-endian) you read it as `1 0 0 9 _ t o B`, but the logical text is `B o t _ 9 0 0 1` → `Bot_9001`. When you *capture the word from the registry and treat it as a number/hex, you are seeing it “right side up” numerically*, which is the **reverse of the string printing order**. That is **why when you dump directly you get `1009_toB`**.
### Understanding Swift SSO
This is an excellent challenge to learn about Swift SSO (**Small String Optimization**).
*You may not have noticed that if you send a message `>12 characters long`, our hook may not be able to catch it, right?*

Let's try:
```bash
/* TID 0x103 */
 11820 ms  dispatch(message:to:)
 11820 ms  arg[0] = 0xf
 11820 ms  arg[1] = 0x5000000283062400
 11820 ms    [HEX]                    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF 5000000283062400  79 81 b0 ed a1 21 00 00 e0 07 00 00 1c 00 00 00  y....!..........
 11820 ms  arg[2] = 0x313030395f746f42
 11820 ms  arg[3] = 0xe800000000000000
 11820 ms  bt:
    0x10027280c TraceTheChat.debug.dylib!ContentView.sendMessage()
    0x100272668 TraceTheChat.debug.dylib!closure #1 in closure #2 in closure #1 in ContentView.body.getter
    0x196a3335c SwiftUI!0x7d735c (0x18ac6f35c)
    0x196a33844 SwiftUI!0x7d7844 (0x18ac6f844)
    0x196a3376c SwiftUI!0x7d776c (0x18ac6f76c)
 11820 ms  end---------------------
```

I sent 15 `a`'s. And the `arg` is `0xf`. What a problem, huh?
In Swift 5+, **Strings are native UTF-8 and occupy 16 bytes of payload for the value**. If the content *fits within those 16 bytes (actually up to 15 usable bytes because 1 byte stores flags/length)*, the string i**s saved inline without heap or pointers**. That's SSO.

**Layout (64-bit, little-endian)**:
- 16 total bytes.
- 15 data bytes + 1 byte with a length of "*small*".

- In little-endian, when you *look at the first u64 as a number/hex*, it appears the opposite of how you would read it as text.
	- *Example*: `0x313030395f746f42` in memory represents the bytes `31 30 30 39 5f 74 6f 42` then "`1 0 0 9 _ t o B`", which is logically "**`Bot_9001`**".

**When SSO is NOT available**: If the **string exceeds 15 bytes, Swift uses heap/native storage or Cocoa storage**. In this case, the String **contains a pointer to the bytes**, and there's no need to invert anything; it's read with **`Memory.readUtf8String(ptr)`** or **bridged to `NSString`**.
### Foundation and the String ↔ NSString bridge
**NSString (Foundation/ObjC)**
- Immutable semantics, logical *UTF-16 encoding* (`CFString` can optimize internally), old but stable API.
- **When you request** `-UTF8String`, CF creates/looks for a *contiguous UTF-8 view*; if it doesn't exist, *it copies and returns a temporary buffer*.
**Bridging runtime**
- Swift *String* is `ObjectiveCBridgeable`.
- If an **ObjC method expects `NSString*`**, the runtime:
	- If the *String already has Cocoa storage* (e.g., it was **born from an `NSString`**), share it *without copying*.
	- If **it's native/SSO,** *create an `NSString` from the UTF-8*.
- On the way back: *`NSStrings` entering Swift can remain as Cocoa-backed Strings without copying*.
**Why we can use this logic**
**For bytes ≤ 15**: you avoided reading the inline SSO.
**For > 15 bytes or Unicode**: you've avoided dealing with pointers and lengths; *`NSString` already gives you the content ready*.
### Intercepting Messages
So, here's the Frida script that we can use for *intercept* the message:
```javascript
(function () {
  'use strict';
  if (!ObjC.available) throw new Error('ObjC no disponible');

  function findSym(re) {
    for (const m of Process.enumerateModules()) {
      try {
        const s = m.enumerateSymbols().find(x => re.test(x.name) && x.address && !x.address.isNull());
        if (s) return s.address;
      } catch(_) {}
    }
    return null;
  }

  const dispatchAddr = findSym(/\$s12TraceTheChat13MessageRouterC8dispatch_2toySS_SStF$/);
  if (!dispatchAddr) throw new Error('MessageRouter.dispatch not found');

  const bridgeAddr = findSym(/\$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF$/)
                  || findSym(/_\$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF$/)
                  || findSym(/\$sSS10FoundationE.*bridgeToObjectiveC.*So8NSStringCyF$/);
  if (!bridgeAddr) throw new Error('bridge String->NSString not found');

  const bridge = new NativeFunction(bridgeAddr, 'pointer', ['pointer','pointer']);

  Interceptor.attach(dispatchAddr, {
    onEnter(args) {
      try {
        const nsMsg = bridge(args[0], args[1]);
        const nsTo  = bridge(args[2], args[3]);
        const sMsg = nsMsg.isNull() ? '<nil>' : new ObjC.Object(nsMsg).toString();
        const sTo  = nsTo.isNull()  ? '<nil>' : new ObjC.Object(nsTo).toString();
        console.log('---hook--- >> message="' + sMsg + '" to="' + sTo + '"');
      } catch (e) {
        console.log('!!!error ' + e + ' | RAW x0=' + args[0] + ' x1=' + args[1] + ' x2=' + args[2] + ' x3=' + args[3]);
      }
    }
  });

  console.log('dispatch @ ' + dispatchAddr);
  console.log('bridge   @ ' + bridgeAddr);
})();
```

Let's try running the Frida command:
```bash
frida -U -f com.8ksec.TraceTheChat.YX4C7J2RLK -l interceptor.js
```
Output:
```bash
     ____
    / _  |   Frida 17.3.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iPhone (id=666eb5ebad136366b2085d7ef60c978ce95eec2d)
Spawning `com.8ksec.TraceTheChat.YX4C7J2RLK`...
dispatch @ 0x101079728
bridge   @ 0x18d169114
Spawned `com.8ksec.TraceTheChat.YX4C7J2RLK`. Resuming main thread!
[iPhone::com.8ksec.TraceTheChat.YX4C7J2RLK ]->
[iPhone::com.8ksec.TraceTheChat.YX4C7J2RLK ]-> ---hook--- >> message="hola bot :)" to="Bot_9001"
[iPhone::com.8ksec.TraceTheChat.YX4C7J2RLK ]->
[iPhone::com.8ksec.TraceTheChat.YX4C7J2RLK ]-> ---hook--- >> message="aaaaaaaaaaaaaaaa" to="Bot_9001"
[iPhone::com.8ksec.TraceTheChat.YX4C7J2RLK ]->
[iPhone::com.8ksec.TraceTheChat.YX4C7J2RLK ]->
```

I hope you found it useful (: