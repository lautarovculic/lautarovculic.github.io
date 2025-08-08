**Description**: A new mobile remote keyless system “**CyberTruck**” has been implemented by one of the most well-known car security companies “**NowSecure Mobile Vehicles**”. The car security company has ensured that the system is entirely **uncrackable** and therefore attackers will not be able to recover secrets within the mobile application.

If you are an experienced Android reverser, then enable the `tamperproof` button to harden the application before unlocking your cars. Your goal will consist on **recovering up to 6 secrets in the application**.

**Challenge 1 to unlock car1. "DES key: Completely Keyless. Completely safe"**
- `50pts`: There is a secret used to create a DES key. Can you tell me which one?

- `100pts`: There is a token generated at runtime to unlock the `carid=1`. Can you get it? (flag must be submitted in hexa all lowercase)

**Challenge 2 to unlock car2: "AES key: Your Cell Mobile Is Your Key"**
- `50pts`: This challenge has been obfuscated with ProGuard, therefore you will not recover the AES key.

- `100pts`: There is a token generated at runtime to unlock the `carid=2`. Can you get it? (flag must be submitted in hexa all lowercase)

**Challenge 3 to unlock car3. "Mr Truck: Unlock me Baby!"**
- `50pts`: There is an interesting string in the native code. Can you catch it?


**Download**: https://lautarovculic.com/my_files/cybertruck.apk

![[cybertruck2019_1.png]]

Install the **apk** with **ADB**
```bash
adb install -r cybertruck.apk
```

We can notice that is an *app with many functions*.
Let's take a look to the **source code** with **jadx** (GUI version).
But before, *decompile it* with **apktool**
```bash
apktool d cybertruck.apk
```

#### General Recon
The **package name** is `org.nowsecure.cybertruck` and the *unique activity* is **MainActivity**.
But, we can see that there are other classes like `c`, `a`, `HookDetector`, `Challenge1`.

#### Challenge 1
*DES key: Completely Keyless. Completely safe*

*There is a secret used to create a DES key. Can you tell me which one?*
We can see the class **`Challenge1`**, where the code show the lines
```java
protected byte[] generateDynamicKey(byte[] bArr) {
    SecretKey generateSecret = SecretKeyFactory.getInstance("DES")
        .generateSecret(new DESKeySpec("s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!".getBytes()));
    Cipher cipher = Cipher.getInstance("DES");
    cipher.init(Cipher.ENCRYPT_MODE, generateSecret);
    return cipher.doFinal(bArr);
}

```
Response: **`s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!`**

*There is a token generated at runtime to unlock the `carid=1`. Can you get it? (flag must be submitted in hexa all lowercase)*
Looking the **`MainActivity`** class, when the *button is pressed*:
```java
public void onClick(View view) {
    if (button != null) {
        Toast.makeText(MainActivity.this.getApplicationContext(), "Unlocking cars...", 0).show();
        MainActivity.this.k();
    }
}
```
The *method `k()`* is launched.
Which is
```java
protected void k() {
    new Challenge1();
    new a(j);
    init();
}
```
Inspecting the **`Challenge1`** class, we can see the `generateDynamicKey` function. We need *hook* with **frida** in order to *get the generated token*.

For this, we can use this `javascript` script:
```javascript
Java.perform(function () {
    // Hook class
    var challenge1 = Java.use("org.nowsecure.cybertruck.keygenerators.Challenge1");
    console.log("[+] Hooking successfull");

    // Hook method
    challenge1.generateDynamicKey.overload('[B').implementation = function (bArr) {
        console.log("[+] Hooking generateDynamicKey");

        var result = this.generateDynamicKey(bArr);

		// Convert input (secret) to string
        console.log("[+] Input (bArr): " + bytesToString(bArr));
        console.log("[+] Flag (hex): " + bytesToHex(result));

        return result;
    };

    // Helper for convert byte[] to string
    function bytesToString(byteArray) {
        var result = "";
        for (var i = 0; i < byteArray.length; ++i) {
            result += String.fromCharCode(byteArray[i]);
        }
        return result;
    }

    // Helper for convert byte[] to hex
    function bytesToHex(byteArray) {
        var hexString = "";
        for (var i = 0; i < byteArray.length; ++i) {
            var hex = (byteArray[i] & 0xFF).toString(16);
            hexString += (hex.length === 1 ? "0" : "") + hex;
        }
        return hexString;
    }
});
```

Where the output (flag) **always will be the same**, because the *hardcoded* secret.
```bash
Attaching...
[+] Hooking successfull
[Redmi Note 8::PID::3878 ]-> [+] Hooking generateDynamicKey
[+] Input (bArr): CyB3r_tRucK_Ch4113ng3
[+] Flag (hex): 046e04ff67535d25dfea022033fcaaf23606b95a5c07a8c6
```

Flag: **`046e04ff67535d25dfea022033fcaaf23606b95a5c07a8c6`**

#### Challenge 2
*AES key: Your Cell Mobile Is Your Key*

*This challenge has been obfuscated with ProGuard, therefore you will not recover the AES key.*
So, we need *recover* the *AES* key.
We can follow *again* the `k()` method called when *press the UNLOCK button*
```java
protected void k() {
    new Challenge1();
    new a(j);
    init();
}
```
There are a *`a`* class.
Which have some *interesting function*:
```java
public class a {  
    public a(Context context) {  
        try {  
            a("uncr4ck4ble_k3yle$$".getBytes(), a(context));  
        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {  
            e.printStackTrace();  
        }  
    }  
  
    protected byte[] a(Context context) {  
        InputStream inputStream;  
        String readLine;  
        Log.d("CyberTruckChallenge", "KEYLESS CRYPTO [2] - Unlocking carID = 2");  
        StringBuilder sb = new StringBuilder();  
        String str = null;  
        try {  
            inputStream = context.getAssets().open("ch2.key");  
        } catch (IOException e) {  
            e.printStackTrace();  
            inputStream = null;  
        }  
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));  
        while (true) {  
            try {  
                readLine = bufferedReader.readLine();  
            } catch (IOException e2) {  
                e2.printStackTrace();  
            }  
            if (readLine == null) {  
                return sb.toString().getBytes();  
            }  
            str = readLine;  
            sb.append(str);  
        }  
    }  
  
    protected byte[] a(byte[] bArr, byte[] bArr2) {  
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr2, "AES");  
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");  
        cipher.init(1, secretKeySpec);  
        return cipher.doFinal(bArr);  
    }  
}
```

The **AES key** is here:
`SecretKeySpec secretKeySpec = new SecretKeySpec(bArr2, "AES");`
Which corresponds to **`ch2.key`** file.
Why `uncr4ck4ble_k3yle$$` isn't the key? because the `secretKeySpec` uses `bArr2` and the *hardcoded string* is `bArr`.

So, you can find the `ch2.key` file in the **assets** directory, the response of this challenge part is `d474_47_r357_mu57_pR073C73D700!!`.

*There is a token generated at runtime to unlock the `carid=2`. Can you get it? (flag must be submitted in hexa all lowercase)*
Again, like the previous challenge, we need *hook* the class and methods.

Here's the script
```javascript
Java.perform(function () {
    var targetClass = "org.nowsecure.cybertruck.keygenerators.a";
    console.log("[+] Hookeando la clase: " + targetClass);

    var clazz = Java.use(targetClass);

    // Hook ch2.key method
    clazz.a.overload("android.content.Context").implementation = function (context) {
        console.log("[+] Hookeando método a(Context)");

        var result = this.a(context);
        console.log("[+] ch2.key (hex): " + bytesToHex(result));

        return result;
    };

    // Hook cypher method
    clazz.a.overload('[B', '[B').implementation = function (bArr, bArr2) {
        console.log("[+] Hooking a(byte[], byte[])");

        console.log("[+] Input (bArr): " + bytesToHex(bArr));
        console.log("[+] Key (bArr2): " + bytesToHex(bArr2));

        var result = this.a(bArr, bArr2);

        console.log("[+] Flag (hex): " + bytesToHex(result));
        return result;
    };

    // Helper for convert byte[] to hex
    function bytesToHex(byteArray) {
        var hexString = "";
        for (var i = 0; i < byteArray.length; ++i) {
            var hex = (byteArray[i] & 0xFF).toString(16);
            hexString += (hex.length === 1 ? "0" : "") + hex;
        }
        return hexString;
    }
});
```

Output
```bash
Attaching...
[+] Hooking class: org.nowsecure.cybertruck.keygenerators.a
[Redmi Note 8::PID::3878 ]-> [+] Hookeando método a(Context)
[+] ch2.key (hex): 643437345f34375f723335375f6d7535375f7052303733433733443730302121
[+] Hooking a(byte[], byte[])
[+] Input (bArr): 756e637234636b34626c655f6b33796c652424
[+] Key (bArr2): 643437345f34375f723335375f6d7535375f7052303733433733443730302121
[+] Flag (hex): 512100f7cc50c76906d23181aff63f0d642b3d947f75d360b6b15447540e4f16
```

Flag: **`512100f7cc50c76906d23181aff63f0d642b3d947f75d360b6b15447540e4f16`**
**NOTE**
The **`HookDetector`** is used in this second challenge, but, just check if there are a `frida-server` file in the *Android device*, if you frida server binary has named like the code say, just *rename it*.

#### Challenge 3
*Mr Truck: Unlock me Baby!*

*There is an interesting string in the native code. Can you catch it?*
Mmmm, let's do it.
In the **`MainActivity`** class, this is the *loaded library*
```java
static {
    System.loadLibrary("native-lib");
}
```

So, go to the *apktool directory* that has dropped, inside of the *lib* directory you will find a file called `libnative-lib.so`. No matters what *arch* you choose.
We are looking for *a string*, then, let's show all strings with
```bash
strings libnative-lib.so
```

In the output, we can *catch the flag*: **`Native_c0d3_1s_h4rd3r_To_r3vers3`**

I hope you found it useful (: