![[saw1.png]]
**Difficult:** Medium
**Category**: Mobile
**OS**: Android (SDK ≥ 29)

**Description**: The malware forensics lab identified a new technique for hiding and executing code dynamically. A sample that seems to use this technique has just arrived in their queue. Can you help them?

----

When you download the .zip file and extract them, we can see that is required an Android 10 (SDK 29) minimum.

So, with **apktool** try decompile the **.apk**
```bash
apktool d SAW.apk
```

And with **adb** try install the **.apk**
```bash
adb install -r SAW.apk
```
I’m trying launch the app, but nothing happen.

So, with **jadx** let’s inspect the source code.
![[saw2.png]]

In the **onCreate** we can see that is necessary use extras “keys” for create the view.
This expected an string extra called “open” with the value “sesame” to start the Main Activity.
I think that with **adb** it’s possible.

This is the intent for launch the MainActivity:
![[saw3.png]]

And we will use the **am** tool (Activity Manager).
Searching the correct command, if we run **adb** like this:
```bash
adb shell am start -a android.intent.action.MAIN --es open "sesame" -n com.stego.saw/.MainActivity
```

![[saw4.png]]

And the app it’s running.
Notice that isn’t an full app view, it’s like a floating menu.
And if we press “CLICK ME”, the app disappear..

We can check the source code again.
![[saw5.png]]

Here, the f() function, show the creation of the new “view”.

This piece of code **create a new center window**, so, with the details that the app isn’t running on “full screen” we can think that **if the display over other apps permission is enabled**, this may work.
![[saw6.png]]

Launch again the app with **adb** and we can see this:
![[saw7.png]]

I input some random text but nothing happen.

Let’s move to the **last of the code**, and analyze this.
![[saw8.png]]

This code is the “XOR ME!” alert, we can see the param “**answer**”.
And this is work of **mainActivity.a()**, that mean, a native method.

I think that is necessary inspect the **native code** that in the start of the class it’s mentioned:
![[saw9.png]]

But we can’t find “**default.so**” file in the app folder, so with this script we can find the native resources and from where are loaded using frida:
`https://raw.githubusercontent.com/lasting-yang/frida_hook_libart/master/hook_RegisterNatives.js`

And here we can see that the file “**libdefault.so**” is loaded.
![[saw10.png]]

Also we can see the functions at the right of the file followed of **!**
![[saw11.png]]

So with **ghidra** i found the **_Z1aP7_JNIEnvP8_1** function:
![[saw12.png]]

Where
**param_1** is the file path.
![[saw13.png]]
**param_2** is the user input (answer) of the alert message.

We will work with this piece of code:
![[saw14.png]]

We have some values for the **l** variable and **m** variable.

If we inspect inside of the **DAT_000*** value we can see that:
![[saw15.png]]

**DAT_00013a18 = 0000000Ah (0000000Ah = 0x0a)**
It seems like, **if 1 XOR input = m, input = 1 XOR m**
Then, first we need order the **l** array:

l = `[0x0a (0000000Ah), 0x0b (0000000Bh), 0x18 (00000018h), 0x0f, 0x5e, 0x31, 0x0c, 0x0f] And for m`:
![[saw16.png]]

m = `[0x6c (0000006Ch), 0x67 (00000067h), 0x28, 0x6e, 0x2a, 0x58, 0x62, 0x68]`

So, with this script we can xorfy these values:
```python
l = [0x0a, 0x0b, 0x18, 0x0f, 0x5e, 0x31, 0x0c, 0x0f]
m = [0x6c, 0x67, 0x28, 0x6e, 0x2a, 0x58, 0x62, 0x68]

text = ""

for xor in range (0, len(l)):
	text += chr(l[xor]^m[xor])
print(text)
```

![[saw17.png]]

The value is **fl0ating**

**Keep reviewing the code**, we an see that when we put the “fl0ating” **value in the alert msg**, something **is store in a file**:
![[saw18.png]]
Here we can see that is manipulating a file.

This file may be stored in the app data.
![[saw19.png]]
And there are the flag.

I hope you found it useful (: