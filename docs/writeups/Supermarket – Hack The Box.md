![[market1.png]]
**Difficult:** Medium
**Category**: Mobile
**OS**: Android

**Description**: My supermarket list is too big and I only have $50. Can you help me get the Discount code?

---

Download the **.zip** and install the APK vía ADB.
![[market2.png]]

```bash
adb install -r supermarket.apk
```

Reading the application code and taking into account the **description of the challenge**, apparently we have to **get the discount coupon** (flag) in a certain way. This particularly caught my attention:
![[market3.png]]

![[market4.png]]

This code appears to be involved in handling text change events in an EditText. Depending on whether or not the entered text matches the decoded text, specific actions are performed, such as clearing a list and filling it with certain items. The logic seems to be related to a discount mechanism in a supermarket application, where certain discount codes trigger different actions in the user interface.

But, we need focus on this:
```java
new String(cipher.doFinal(Base64.decode(stringFromJNI, 0)), "utf-8")
```

Why?

Here, a Cipher object is being used to perform the **decryption operation** (**doFinal**) on a **string that has been previously Base64 encoded**. The result is **converted to a string** using the **new String** constructor with the “utf-8” encoding.

The stringFromJNI value is obtained from the call to MainActivity.this.stringFromJNI(). In the context, **this method probably contains the logic to get the encrypted string**.

So indeed, the **result of this decryption operation is crucial** and probably **contains the “flag”** or discount code (the flag) you are looking for.
So, we need identify this piece in the **smali code**!
After some research, I can take the right smali file, it’s **MainActivity$b.smali**

From the line **98** until **125**
```smali
.line 2
invoke-virtual {p2}, Lcom/example/supermarket/MainActivity;->stringFromJNI3()Ljava/lang/String;

move-result-object p2

invoke-static {p2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

move-result-object p2

const/4 v0, 0x2

invoke-virtual {p2, v0, p4}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

const/4 p4, 0x0

invoke-static {p3, p4}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

move-result-object p3

invoke-virtual {p2, p3}, Ljavax/crypto/Cipher;->doFinal([B)[B

move-result-object p2

new-instance p3, Ljava/lang/String;

const-string v0, "utf-8"

invoke-direct {p3, p2, v0}, Ljava/lang/String;-><init>([BLjava/lang/String;)V
```

So, to recap, we have to **get the discount coupon** somehow. That is, we must **call the function** to **give us the discount**. I have come up with several ways, for example: Intercept it with **FRIDA**. Send it through a **Toast** message. Save it in a **local.txt** file. Or, with my method, in the **logs of the application** that is the less intrusive and simple.

In the **smali file**, we can inject the following 2 lines:
```smali
const-string v4, "MiAppTag"

invoke-static {v4, p3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
```
The value is in **p3**, so we take that value and **show it in the logs**.

The injected 2 lines must be place under of
```smali
invoke-direct {p3, p2, v0}, Ljava/lang/String;-><init>([BLjava/lang/String;)V
```
Save the **smali file** and remove the old **.apk** and uninstall the **.apk** from the device.

Build the **.apk** with **apktool**
```bash
apktool b supermarket
```

Now its time of creating a **key**
```bash
apksigner sign --ks keystore.jks --ks-key-alias key_alias --ks-pass pass:<yourKeyPassword> --key-pass pass:<yourKeyPassword> --out signed_supermarket.apk supermarket/dist/supermarket.apk
```

Then install the **signed_supermarket.apk** into the device
```bash
adb install signed_supermarket.apk
```

Open the app in your Android device and in your terminal type
```bash
adb logcat | grep "MiAppTag"
```
For grep the flag.

And type some random input in the **Discount code** field.
![[market5.png]]
And we get the flag!

_Before I say goodbye, I want to clarify that although the APK can be run on the latest versions of Android, in my case I used Android 9 (SDK 29)._

I hope you found it useful (: