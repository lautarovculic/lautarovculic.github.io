**Description**: Looks like this app is all locked up. Think you can figure out the combination?

Download **APK**: https://lautarovculic.com/my_files/challenge2_h1-702.apk

![[h1-702_challenge2-1.png]]

Install the **apk** with **adb**
```bash
adb install -r challenge2_h1-702.apk
```
And then, **decompile** with **apktool**
```bash
apktool d challenge2_h1-702.apk
```

We can see a **PIN** app, which have **six** numbers combination.
So, we can simply try the `1.000.000` combinations (`C= 10⁶ = 1.000.000`) or **look the source code**.

Open **jadx** (GUI Version) for **analyze** the code.
The package name is `com.hackerone.mobile.challenge2`
And the **unique** activity is the **MainActivity**.
But, we have some **extra classes** like `SecretBox`, `PinLockView`, `IndicatorDots`

Here's the **main code** of our interest
```java
[...]
[...]
public class MainActivity extends AppCompatActivity {  
    private static final char[] hexArray;  
    private byte[] cipherText;  
    IndicatorDots mIndicatorDots;  
    PinLockView mPinLockView;  
    String TAG = "PinLock";  
    private PinLockListener mPinLockListener = new PinLockListener() { // from class: com.hackerone.mobile.challenge2.MainActivity.1  
        @Override // com.andrognito.pinlockview.PinLockListener  
        public void onComplete(String str) {  
            Log.d(MainActivity.this.TAG, "Pin complete: " + str);  
            byte[] key = MainActivity.this.getKey(str);  
            Log.d("TEST", MainActivity.bytesToHex(key));  
            try {  
                Log.d("DECRYPTED", new String(new SecretBox(key).decrypt("aabbccddeeffgghhaabbccdd".getBytes(), MainActivity.this.cipherText), StandardCharsets.UTF_8));  
            } catch (RuntimeException e) {  
                Log.d("PROBLEM", "Unable to decrypt text");  
                e.printStackTrace();  
            }  
        }  
  
        @Override // com.andrognito.pinlockview.PinLockListener  
        public void onEmpty() {  
            Log.d(MainActivity.this.TAG, "Pin empty");  
        }  
  
        @Override // com.andrognito.pinlockview.PinLockListener  
        public void onPinChange(int i, String str) {  
            Log.d(MainActivity.this.TAG, "Pin changed, new length " + i + " with intermediate pin " + str);  
        }  
    };  
  
    public native byte[] getKey(String str);  
  
    public native void resetCoolDown();
[...]
[...]
```

The code use **native code** for decrypt the flag. We can see the `getKey` function that work with the pin code.

We can **hook the `onComplete`** function for inspect **how it work**.
The `PinLockListener` use an **anonymous class**.

Anonymous classes generate a class name like `<aClassName>$<id>`.
The `id` start from 1 until the *last anonymous class*. In this case we can find the anonymous class in `com.hackerone.mobile.challenge2.MainActivity$1`.

We can find this with
```bash
tree smali/com/hackerone/mobile/challenge2
```
And see
```bash
smali/com/hackerone/mobile/challenge2
├── BuildConfig.smali
├── MainActivity$1.smali
[...]
```

Let's hook the `onComplete` with frida.
Here's the script
```javascript
Java.perform(function () {
    const Listener = Java.use('com.hackerone.mobile.challenge2.MainActivity$1');

    Listener.onComplete.implementation = function (key) {
        console.log("[*] Hooked onComplete called with key: " + key);

        function generateAndTest(count, prefix) {
            if (count === 0) {
                this.onComplete(prefix);
                console.log("Trying key: " + prefix);
                return;
            }

            for (let i = 0; i < 10; i++) {
                generateAndTest.call(this, count - 1, prefix + i.toString());
            }
        }

        console.log("[*] Starting brute force...");
        generateAndTest.call(this, 6, "");

        console.log("[*] Brute force completed.");
    };
});
```

we can see that this work, but also **every 50 attempts**, there are an **wait**. This can make more *difficult* to bruteforce the pin.
So, the next challenge is that we need *bypass* the *protection*.
Which is **another native code** in `resetCoolDown();` function.

This functions is like an *ok, start again the process*. So, we need call it every 50 attempts. Like
```javascript
      if (i % 50 == 0) {
        this.this$0.value.resetCoolDown();
      }
```

So now, the **actual code for hook `onComplete`** looks like
```javascript
Java.perform(function () {
    const Listener = Java.use('com.hackerone.mobile.challenge2.MainActivity$1');

    Listener.onComplete.implementation = function (key) {
        console.log("[*] Hooked onComplete called with key: " + key);

        function generateAndTest(count, prefix) {
            if (count === 0) {
                this.onComplete(prefix);
                console.log("Trying key: " + prefix);
                return;
            }


            for (let i = 0; i < 10; i++) {
                generateAndTest.call(this, count - 1, prefix + i.toString());

                if (i % 50 == 0) {
                	this.this$0.value.resetCoolDown();
             	}
            }
        }

        console.log("[*] Starting brute force...");
        generateAndTest.call(this, 6, "");

        console.log("[*] Brute force completed.");
    };
});
```

And we can see that the bruteforce *run without* stoppers.
The **final step** is *know what is the correct PIN*, right? We need **check** of some way the *correct pin*.

Looking in **logcat** if the code work
```bash
adb logcat -c && adb logcat | grep -E "complete|TEST|PROBLEM"
```
We can see the attempts.

Since the `onComplete` functions doesn't make sense (this just return *logcat* content), we need inspect the `SecretBox.decrypt()`

```java
public byte[] decrypt(byte[] bArr, byte[] bArr2) {  
        Util.checkLength(bArr, 24);  
        byte[] prependZeros = Util.prependZeros(16, bArr2);  
        byte[] zeros = Util.zeros(prependZeros.length);  
        NaCl.sodium();  
        Util.isValid(Sodium.crypto_secretbox_xsalsa20poly1305_open(zeros, prependZeros, prependZeros.length, bArr, this.key), "Decryption failed. Ciphertext failed verification");  
        return Util.removeZeros(32, zeros);  
    }
```

This return the **decrypted data** if it *could be decrypted successfully*.
Let's hook the method.
We can implement this code
```javascript
    let success = false;

    SecretBox.decrypt.implementation = function (bArr, bArr2) {
        let ret = "";
        try {
            ret = this.decrypt(bArr, bArr2);
            success = true;
            console.log("[*] Decryption successful! Found flag: " + JavaString.$new(ret));
        } catch (ex) {
            success = false;
            ret = Java.array('byte', []);
        }
        return ret;
    };
    ```
For work with the method.
Also, this code
```javascript
Listener.onComplete.implementation = function (key) {
        console.log("[*] Hooked onComplete called with key: " + key);

        const self = this;

        function generateAndTest(count, prefix) {
            if (success) return;

            if (count === 0) {
                console.log("[*] Trying key: " + prefix);

                const ret = self.onComplete(prefix);
                if (success) {
                    console.log("[*] The correct PIN is: " + prefix);
                    return ret;
                }
                return;
            }

            for (let i = 0; i < 10; i++) {
                if (success) break;

                generateAndTest(count - 1, prefix + i.toString());

                if (i % 50 === 0 && !success) {
                    console.log("[*] Resetting cooldown...");
                    self.this$0.value.resetCoolDown();
                }
            }
        }
```
Will modify the call to `onComplete()` for check if this is correct.
I'll start from the beginning, this will take a long of time, but, I'll get the dinner while the code is running.

The final code look like
```javascript
Java.perform(function () {
    const Listener = Java.use('com.hackerone.mobile.challenge2.MainActivity$1');
    const SecretBox = Java.use('org.libsodium.jni.crypto.SecretBox');
    const JavaString = Java.use('java.lang.String');

    let success = false;

    SecretBox.decrypt.implementation = function (bArr, bArr2) {
        let ret = "";
        try {
            ret = this.decrypt(bArr, bArr2);
            success = true;
            console.log("[*] Decryption successful! Found flag: " + JavaString.$new(ret));
        } catch (ex) {
            success = false;
            ret = Java.array('byte', []);
        }
        return ret;
    };

    Listener.onComplete.implementation = function (key) {
        console.log("[*] Hooked onComplete called with key: " + key);

        const self = this;

        function generateAndTest(count, prefix) {
            if (success) return;

            if (count === 0) {
                console.log("[*] Trying key: " + prefix);

                const ret = self.onComplete(prefix);
                if (success) {
                    console.log("[*] The correct PIN is: " + prefix);
                    return ret;
                }
                return;
            }

            for (let i = 0; i < 10; i++) {
                if (success) break;

                generateAndTest(count - 1, prefix + i.toString());

                if (i % 50 === 0 && !success) {
                    console.log("[*] Resetting cooldown...");
                    self.this$0.value.resetCoolDown();
                }
            }
        }

        console.log("[*] Starting brute force...");
        generateAndTest(6, "");

        if (!success) {
            console.log("[*] Brute force completed without finding the correct PIN.");
        }
    };
});
```

And the code works!!
```bash
[*] Resetting cooldown...
[*] Trying key: 918251
[*] Trying key: 918252
[*] Trying key: 918253
[*] Trying key: 918254
[*] Trying key: 918255
[*] Trying key: 918256
[*] Trying key: 918257
[*] Trying key: 918258
[*] Trying key: 918259
[*] Trying key: 918260
[*] Resetting cooldown...
[*] Trying key: 918261
[*] Trying key: 918262
[*] Trying key: 918263
[*] Trying key: 918264
[*] Decryption successful! Found flag: flag{wow_yall_called_a_lot_of_func$}
[*] The correct PIN is: 918264
[Pixel 2::PID::3422 ]->
[Pixel 2::PID::3422 ]->
```

PIN: `918264`
Flag: **`flag{wow_yall_called_a_lot_of_func$}`**

I hope you found it useful (: