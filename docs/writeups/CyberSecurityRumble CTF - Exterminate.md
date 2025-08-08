**Description**: Daleks have invaded the earth and the Doctor is nowhere to be seen. Now it's up to you to find out how they are built and which code can stop the extermination of all humankind.

**Download**: https://lautarovculic.com/my_files/exterminate.apk

![[cyberRumbleCTF2023_exterminate1.png]]

Install the `.apk` file using **ADB**
```bash
adb install -r exterminate.apk
```

We can see that when the app is launched, there are a *countdown* of 3 seconds and then, **EXTERMINATE** text is printed on screen. Finally, **the app is closed**.

Let's inspect the **source code** using **JADX**.
In the **`AndroidManifest.xml`** we found these activities:
```XML
<activity
    android:name="de.cybersecurityrumble.exterminate.CodeActivity"
    android:exported="false"/>
<activity
    android:name="de.cybersecurityrumble.exterminate.CountdownActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```
Where `CountdownActivity` is the main activity, and obviously is exported. And also, we can see the `CodeActivity`. Which **isn't exported**.

Let's see the **`CountdownActivity`** class, useful code:
```java
new CountDownTimer() { // from class: de.cybersecurityrumble.exterminate.CountdownActivity$onCreate$timer$1
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    {
        super(3000L, 1000L);
    }

    @Override // android.os.CountDownTimer
    public void onTick(long millisUntilFinished) {
        objectRef.element.setText(String.valueOf(intRef.element));
        if (intRef.element == 1) {
            objectRef2.element.setVisibility(0);
        }
        intRef.element--;
    }

    @Override // android.os.CountDownTimer
    public void onFinish() {
        System.exit(0);
        throw new RuntimeException("System.exit returned normally, while it was supposed to halt JVM.");
    }
}.start();
```
Here's the function where *countdown occurs*.
Also:
```java
public final void switchActivity() {
    startActivity(new Intent(this, (Class<?>) CodeActivity.class));
}
```
The `switchActivity()`, that **opens** `CodeActivity` class.

In the **`CodeActivity`** we can see the following objects:
```java
Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.input_code)");
Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(R.id.button_submit)");
Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(R.id.text_response)");
```
But the *most important part* is:
```java
static {
    System.loadLibrary("exterminate");
}
```
Where an *native library is loaded*.

Let's use **ghidra** for binary analysis.
But first we need *decompile* the `.apk` using **apktool**
```bash
apktool d exterminate.apk
```
In `exterminate/lib/arm64-v8a` directory, we can see the `libexterminate.so`.
*Import in ghidra* and let's see some *useful functions*.

Well, we can see a *couple of functions in the library*.
- `Java_de_cybersecurityrumble_exterminate_CodeActivity_getCodeResponse`
- `is_utf8`
- `isCodeCorrect`
- `getFlag`
- `decrypt`

I will avoid placing the code for each function. However, you can **find these functions in the Symbol Tree on the left**.
![[cyberRumbleCTF2023_exterminate2.png]]

### Functions
#### `getCodeResponse`
This is a **JNI** that is "exposed" to the **UI**. I mean, when you *insert a code* in the `CodeActivity` (input), the `getCodeResponse` will be executed first.
The function **flow** is:
1. Convert **jstring** -> `std::string`.
2. `isCodeCorrect(s)` -> bool.
3. If **true** -> `getFlag(s)`; *otherwise load* literal “**No Flag For You**”.
4. Return the result to Java.
#### `is_utf8`
UTF-8 sequence validator (*while loop with masks `0xE0/0xF0/0xF8`*).
Reject *any byte ≥ `0x80` that does not match UTF-8*; if it fails, the app replaces it with “**Wrong Code**”.
#### `isCodeCorrect`
Contains a 8-byte filter:
• `len` == 8
• `code[1]` == `code[2]`
• Contains *substring* “**on**”
• `code[6]` == ‘**-**’
• All alphabetic (`isalpha`)
*This can help us if we wanna bruteforce*
#### `getFlag`
Copy **code to stack**, concatenate literal “**geronimo**” → `AES-128` key. Call `decrypt(ptrKey)` to **decrypt 32 hardcoded bytes and push the result** to a `std::string` that **returns to `getCodeResponse`**.
#### `decrypt`
The **two encrypted blocks**:
**C1** = `c7e98af11a35c8a8...`
**C2** = `d66d203aadabea4f...`
They are **decrypted** with `<code>` + `geronimo`.

The **chain of execution**:
1. `UI -> Java: onClick("<code>")`
2. `Java -> JNI: getCodeResponse("<code>")`
3. `JNI -> Native: isCodeCorrect()`
4. `Native -> JNI: true`
5. `JNI -> Native: getFlag()`
6. `Native -> Native: decript("<code>" + "geronimo")`
7. `Native -> JNI: "CSR{...flag...}"`
8. `JNI -> Java: jstring flag`
9. `Java -> UI: show flag in text view`

I want to *divide in two parts this challenges*.
The *first part* is stopping the **countdown** and call the `CodeActivity` so we can put the code.
For this, I develop a **frida script** that skip the `System.Exit()` function and **start the activity `CodeActivity`**:
```javascript
Java.perform(() => {
	// kill system exit
  Java.use('java.lang.System').exit.implementation = () => {};
  Java.use('de.cybersecurityrumble.exterminate.CountdownActivity$onCreate$timer$1')
       .onFinish.implementation = () => {};

	// log flag
  const CA = Java.use('de.cybersecurityrumble.exterminate.CodeActivity');
  CA.getCodeResponse.implementation = function (code) {
     const res = this.getCodeResponse(code);
     console.log(`[+] ${code}  →  ${res}`);
     return res;
  };

	// launch code activity (and delay)
  function launchWhenReady() {
    const app = Java.use('android.app.ActivityThread').currentApplication();
    if (app) {
      setTimeout(() => {
        const ctx    = app.getApplicationContext();
        const Intent = Java.use('android.content.Intent');
        const CodeAct= Java.use('de.cybersecurityrumble.exterminate.CodeActivity');
        const i = Intent.$new(ctx, CodeAct.class);
        i.addFlags(0x10000000);	// NEW_TASK
        ctx.startActivity(i);
        console.log('[+] Starting CodeActivity');
      }, 5000);
    } else {
      setTimeout(launchWhenReady, 100);
    }
  }
  launchWhenReady();
});
```

We can *launch the app* and run frida with this command:
```bash
frida -U -f de.cybersecurityrumble.exterminate -l scriptExt.js
```
This will *launch the app* and 5 seconds later, the `CodeActivity` will be shown.

Notice that now **we can insert and submit a code**.
After a *little research* and reading the challenge *description* (I don't know anything related to *Doctor Who*). I found the following information from a Google search:

"*"Fantastic," "**Allons-y**," and "Geronimo" are popular phrases associated with the Ninth, Tenth, and Eleventh Doctors, respectively, in Doctor Who*"

**`allons-y`** -> Is the `<code>`.
Because as we previously mentioned...
Contains a 8-byte filter:
• `len` == 8
• `code[1]` == `code[2]`
• Contains *substring* “**on**”
• `code[6]` == ‘**-**’
• All alphabetic (`isalpha`)

The numbers in `[]` are positions, think that *starting from 0*.
- `code[1]` and `code[2]` == `l`

So, the *final key* for AES decryption is `allyons-ygeronimo`.
But, we can just insert `allons-y`, then, the Java code sends to JNI and libraries put together the key for decrypt the flag.
![[cyberRumbleCTF2023_exterminate3.png]]

Flag: **`CSR{_the-def1n1te-article-fl4g_}`**

I hope you found it useful (: