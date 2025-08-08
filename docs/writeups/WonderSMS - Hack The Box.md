![[wondersms1.png]]
**Difficult:** Hard
**Category**: Mobile
**OS**: Android

**Description**: My grandmother just got stolen! Someone drained her bank account! I didn't even know this was possible, with so many security layers and tokens and stuff nowadays! Anyway, I need your help! You're the only hacker I know! I took a look at her phone and the only thing that struck me as odd was this SMS app. Could you have a look at it? See if it could have been used to help log into her account? Ideally find some info about the attackers too. I know it's a long shot, but it's the only thing I can think of...

-----------------
Download the **.zip** file and extract this with the password **hackthebox**.

Install the **APK** with **ADB**
```bash
adb install -r WonderSMS.apk
```

It appears to be an app for sending and receiving SMS messages.
Let's use **JADX-GUI** for *inspect the source code*.

In the **`AndroidManifest.xml`** we can see the **`MainActivity`** class and the **broadcast receiver** `SmsReceiver`.

The *package name* is `com.rloura.wondersms`.
```xml
<activity
    android:name="com.rloura.wondersms.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
<activity android:name="com.rloura.wondersms.ViewMessageActivity"/>
<activity android:name="com.rloura.wondersms.InfoActivity"/>
<activity android:name="com.rloura.wondersms.SendMessageActivity"/>
<receiver
    android:name="com.rloura.wondersms.SmsReceiver"
    android:enabled="true"
    android:exported="true">
    <intent-filter>
        <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
    </intent-filter>
</receiver>
```

**`SmsReceiver.java`**:
```java
public final class SmsReceiver extends BroadcastReceiver {
    private final native ProcessedMessage processMessage(SmsMessage smsMessage);

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        SmsMessage[] messagesFromIntent = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        c.x(messagesFromIntent, "getMessagesFromIntent(...)");
        for (SmsMessage smsMessage : messagesFromIntent) {
            c.u(smsMessage);
            if (processMessage(smsMessage) != null) {
                MediaPlayer mediaPlayer = new MediaPlayer();
                mediaPlayer.setDataSource((MediaDataSource) null);
                mediaPlayer.start();
            } else {
                RingtoneManager.getRingtone(context, RingtoneManager.getDefaultUri(2)).play();
            }
        }
    }
}
```

This receive **capture the messages** that income to our device.
And then, **forwards to the native method `processMessage`**.
In the Java code, handle a *media playback for such features*, and use *native code*.

This can be **suspicious**, due the **sensitivity of SMS content** (2FA tokens).
Let's *decompile* the `.apk` file with **APKTool**
```bash
apktool d WonderSMS.apk
```

We can get the **`libaudio.so`** library in the `/WonderSMS/lib/x86_64/libaudio.so` directory.
*Import* this using **Ghidra**.

Notice the `Java_com_rloura_wondersms_SmsReceiver_processMessage` function.
![[wondersms2.png]]

We can see in the line `44` that the **`MessageSound`** class is *initialized*.
Reading the content of the **function** `JNI_OnLoad` under the `Symbol Tree` → `Functions` → `J`, **it turns out that the app overrides the usual resolution of `processMessage`** by manually calling `RegisterNatives`.

![[wondersms3.png]]

According to the [official documentation](https://developer.android.com/training/articles/perf-jni#native-libraries), `JNI_OnLoad` is a **system callback function that is called when a native library is loaded into an application**, and it is used for **performing library-level initializations**. 
This method allows **overriding the initial `processMessage` function**, making the analysis process *more difficult*.

The **real implementation of `processMessage` is a method of the `processor` class**. We **can navigate to this function by double-clicking on the `PTR_s_processMessage_001ec9f0`, and then on `processor::processMessage` from the Listing view**. Or, we can *simply search for `processMessage` in the `Symbol Tree` and looking at the export functions*.

![[wondersms4.png]]

Double click and we can see the *code* of the *implementation* of `processor::processMessage`
![[wondersms5.png]]

Here, **the contents of the SMS message are first extracted and converted to lowercase by calling the `toLowerCase` method (line `65`)**. The message is then **checked to ensure all characters are alphabetic or whitespaces**.
*This check is specifically performed on the first 28 characters of the message*.

After this, the program **checks the length of the SMS message body, ensuring it contains more than 36 characters**.
If these conditions are met, the SMS message body is then passed to the method `f315732804` (line 108 in the code) for further handling, as shown in the picture below.
![[wondersms6.png]]

Let's move to `f315732804`, here's the code:
![[wondersms7.png]]

Each of these checks **if certain characters of the SMS message meet specific conditions, then directs the control flow to various additional checks based on the outcome of these conditions**.
Despite the complex network of control paths, **all paths eventually converge at a single critical check: the `check_extension` method in the `processor` class**.

Exploring the method `f55246438` and subsequently `f3982753770` leads to the **discovery of the `check_extension` method**, although other combinations of functions also lead to the same endpoint.
![[wondersms8.png]]

Let's entry to `check_extension` function. We can notice that is a *huge code*.
This function performs **some final checks and if they are met**, a message-dependent string is constructed.
Then, **a regex-based search is performed on the message body to identify specific patterns** (`std::ndk1::basic_regex`).
![[wondersms9.png]]

Upon **finding a match, which is managed through the `RegexMatchResults` object**, it constructs an **HTTP POST request** where the matched data is sent to a **specified endpoint**. This operation is handled by the `httpcon::post` method call.

![[wondersms10.png]]

Let's inspect the `__android_log_print` call.
Therefore, the **message-dependent string we defined earlier is the URL**. The data to be sent is stored in the second parameter, that is `param_1`.
The `android_log_print` **simulates a POST request that would be made in an actual malicious application**.

The second argument of the `basic_regex` constructor is `RegexPatternStr`, **which does not appear to be initialized anywhere**. We identified this argument **as the regex pattern string by referring to the `basic_regex` documentation linked above**. In other words, this is the **string against which the message body will be evaluated for a match**. Notably, before the construction of the regex object, there are several calls to the `get_encoding` method.

The body of the function `get_encoding` is shown below:
![[wondersms11.png]]

The value of `RegexPatternStr` is assigned by `get_encoding`:
- `\.mp3`
- `\.mp4`
- `\.ogg`
- `\.wav`
- `\.midi`
- `\d{6}`

The **first five are common file extensions for audio and video files, so there is nothing particularly interesting about them**. However, the *last string seems oddly out of place*. *Exfiltrating 6 digits from an SMS message can be quite dangerous*, as it would catch most **2FA tokens**.

#### Using angr to find the correct call path
In essence, `angr` systematically explores all **feasible execution paths of a binary and analyzes the outcomes**, similar to using **a map to identify the optimal route without traversing every possible path**.
Since **angr does not actually run the application**, the architecture **doesn't matter**. Thus, we **will simply choose the `x86_64` version of `libaudio.so`**

Let's create a **python script**:
```python
import angr
import claripy

proj = angr.Project("./libaudio.so", auto_load_libs=False)
arg = claripy.BVS("msg", 36 * 8)
arg_p = proj.factory.callable.PointerWrapper(arg, buffer=True)
state = proj.factory.call_state(0x473420, 0, arg_p, prototype='void f(void *, char *)')
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

for b in arg.chop(8):
    state.add_constraints(claripy.Or(b == ' ', claripy.And(b >= 'a', b <= 'z')))

sm = proj.factory.simgr(state)
print("Exploring paths...")
sm.explore(find=0x4741f8)
total = len(sm.found)
print(f"Exploration finished with {total} path(s) found")

print("Checking satisfiability")
sols = []
for i in range(total):
    print(f"Progress: {i + 1}/{total}   ", end='\r', flush=True)
    guess = sm.found[i]
    if guess.solver.satisfiable():
        sols.append(guess.solver.eval(arg, cast_to=bytes))

print("\nSolution(s)")
for i in range(len(sols)):
    print(repr(sols[i]))
```

Output:
```bash
Exploring paths...
Exploration finished with 1 path(s) found
Checking satisfiability
Progress: 1/1   
Solution(s)
b'ko r lkgkn vprdfkcpt  n  o e    kpdd'
```

**The message is non-deterministic, so its output varies each time**. Some *even-indexed characters aren't parsed correctly*. Since the app tries to exfiltrate a **6-digit SMS code but our script can’t handle numbers**, we *know the last 6 chars (e.g., `kpdd`) are wrong and must be guessed*.

To simplify, **we replace those uncertain chars with `X`**. Leaving spaces intact improves readability. *The message becomes*:  
`b'Xo r lXgXn vXrXfXcXt n o e XXXX'`

Since the **app extracts 2FA codes via SMS**, we infer the real format is:  
**Your login verification code: ######**

*Sending an SMS in that format* (e.g., `Your login verification code: 123456`) **triggers the exfil logic**.
To test, just run this command for "*auto-send*" a SMS.
```bash
adb emu sms send 1234 "Your login verification code: 123456"
```

Finally, just need read to *log message*, which is a HTTP POST request like.
```bash
Uploading 123456 via POST to http://HTB{I_g3t_angr_3as1lY_aT_unicorn}
```

Flag: **`HTB{I_g3t_angr_3as1lY_aT_unicorn}`**

I hope you found it useful (: