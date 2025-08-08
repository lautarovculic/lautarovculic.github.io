**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/VirusClicker.apk

![[virusClicker1.png]]

Install the **apk** with **adb**
```bash
adb install -r VirusClicker.apk
```

And decompile with **apktool**
```bash
apktool d VirusClicker.apk
```

We can notice that the **app isn't responding**. So I need install this app into an **Android API29**
Let's inspect the **source code** with **jadx** (GUI version)
We have the **SplashActivity**, **MainActivity**, and some other **Activities**.
Launching the **app**, we can see an **button** and a counter until **10.000.000**

So, we need a way for get the flag that we'll receive when we reach this number.
We can see in the **XML** file **MainPreferences.xml** saved into `/data/data/com.tm.ctf.clicker`folder in the device
```XML
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="DATA">Q</string>
    <int name="COUNT" value="1" />
</map>
```

I try override the file, but I don't have success.
So, maybe we can modify the **CongratulationsActivity**
```java
package com.tm.ctf.clicker.activity;  
  
import android.app.Activity;  
import android.graphics.Bitmap;  
import android.graphics.BitmapFactory;  
import android.os.Bundle;  
import android.util.Log;  
import com.tm.ctf.clicker.p004a.C0238a;  
import java.io.IOException;  
import java.io.InputStream;  
import java.nio.ByteBuffer;  
  
/* loaded from: classes.dex */  
public class CongraturationsActivity extends Activity {  
  
    /* renamed from: b */  
    private static final String f563b = CongraturationsActivity.class.getSimpleName();  
  
    /* renamed from: c */  
    private static final byte[] f564c = {-119, 80, 78, 71, 13, 10, 26, 10};  
  
    /* renamed from: a */  
    SurfaceHolderCallbackC0240b f565a = null;  
  
    /* renamed from: a */  
    private Bitmap m921a() {  
        try {  
            InputStream open = getResources().getAssets().open("f.png");  
            byte[] bArr = new byte[open.available()];  
            open.read(bArr);  
            ByteBuffer allocate = ByteBuffer.allocate(bArr.length + 8);  
            allocate.put(f564c);  
            allocate.put(bArr);  
            return BitmapFactory.decodeByteArray(allocate.array(), 0, bArr.length + 8);  
        } catch (IOException e) {  
            e.printStackTrace();  
            return null;  
        }  
    }  
  
    @Override // android.app.Activity  
    protected void onCreate(Bundle bundle) {  
        super.onCreate(bundle);  
        getActionBar().hide();  
        if (10000000 != C0238a.m918c()) {  
            finish();  
        }  
        this.f565a = new SurfaceHolderCallbackC0240b(this, String.valueOf(getIntent().getStringExtra("data")) + "Nf");  
        Bitmap m921a = m921a();  
        setContentView(this.f565a);  
        Log.i("VirusClicker", "width=" + m921a.getWidth() + ", height=" + m921a.getHeight());  
    }  
}
```

In this code we can see that the flag is showed.
The flag is created in the method **m924a**
```java
private void m924a(Canvas canvas, Paint paint) {  
        canvas.drawText("Conguraturations!", (this.f572c - ((int) paint.measureText("Conguraturations!"))) / 2, (this.f573d / 6) * 2, paint);  
        canvas.drawText("The flag is ...", (this.f572c - ((int) paint.measureText("The flag is ..."))) / 2, (this.f573d / 6) * 3, paint);  
        m925a();  
        String obj = C0246b.m933b(this.f575f.getBytes(), "click_machine").toString();  
        canvas.drawText("TMCTF{" + this.f575f + "}", (this.f572c - ((int) paint.measureText(r1))) / 2, (this.f573d / 6) * 4, paint);  
        Log.i("VirusClicker", "length=" + obj.length());  
    }
```
But there aren't nothing that we can do.

So, I found this code in **ScoreBroadcastReceiver**
```java
public class ScoreBroadcastReceiver extends BroadcastReceiver {  
    @Override // android.content.BroadcastReceiver  
    public void onReceive(Context context, Intent intent) {  
        int intExtra = intent.getIntExtra("SCORE", 0);  
        String str = "";  
        if (3769 == intExtra) {  
            str = "2";  
        } else if (10007 == intExtra) {  
            str = "x";  
        } else if (59239 == intExtra) {  
            str = "p";  
        } else if (100003 == intExtra) {  
            str = "Y";  
        } else if (495221 == intExtra) {  
            str = "2";  
        } else if (1000003 == intExtra) {  
            str = "t";  
        } else if (9999999 == intExtra) {  
            str = "z";  
        }  
        C0238a.m916a(str);  
    }  
}
```
This code send the data score for **some checks** to the app.
So, get again the previous code of the **Congratulations** activity
```java
if (10000000 != C0238a.m918c()) {  
            finish();  
} 
```
Where compare with the **Intent** that is sent to the **Broadcast**.
So, we can modify the **smali code**.
The **CongraturationsActivity.smali** file is in `/VirusClicker/smali/com/tm/ctf/clicker/activity` directory.
In the line `150` we can see the line `if-eq v0, v1, :cond_0`.

So, changing the **if-eq** statement to **if-ne**
Must look like this `if-ne v0, v1, :cond_0`
Save the **smali** file.

I notice that here (in the **c.class**) are an method that register **every touch screen**.
And we have the **intent** that is sent to the **broadcast receiver**.
```java
public boolean onTouchEvent(final MotionEvent motionEvent) {
    switch (motionEvent.getAction()) {
        case 0: {
            return this.h = true;
        }
        case 1: {
            this.h = false;
            ++this.g;
            com.tm.ctf.clicker.a.a.b();
            if (3763 == this.g || 10007 == this.g || 59239 == this.g || 100003 == this.g || 495221 == this.g) {
                final Intent intent = new Intent("com.tm.ctf.clicker.SCORE");
                intent.putExtra("SCORE", this.g);
                this.a.sendBroadcast(intent);
            }
            if (10000000 <= this.g) {
                final Message obtain = Message.obtain();
                obtain.obj = String.valueOf(this.g) + "\n";
                this.b.sendMessage(obtain);
                return true;
            }
            break;
        }
    }
    return true;
}
```
And we need reach the last **if condition** `f (10000000 <= this.g)`
For get the "final message".
Then, we need modify again the **smali** file for **c.smali** file in `/VirusClicker/smali/com/tm/ctf/clicker/activity`
We can see in the **line 845** `if-gt v0, v1, :cond_0`
You need change **if-gt** (if greater than) to **if-lt** (if less-than).

The line must look like `if-lt v0, v1, :cond_0`
Save the file and now is time for **rebuild** the **apk**.

Build the **apk**
```bash
apktool b VirusClicker
```

Generate a **key**
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

**Sign** the apk
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore VirusClicker/dist/VirusClicker.apk alias
```

Uninstall the **app** in the device and reinstall the **new** apk
```bash
adb install -r VirusClicker/dist/VirusClicker.apk
```

So now, launch the app. **Do not touch the app**.
We can complete the challenge with adb. Sending the **intents** via **broadcast** the **value of SCORE** like the code do.

Send this chain of broadcast with **adb**
```bash
adb shell am broadcast -a com.tm.ctf.clicker.SCORE -n com.tm.ctf.clicker/.receiver.ScoreBroadcastReceiver --ei SCORE 3769
```
```bash
adb shell am broadcast -a com.tm.ctf.clicker.SCORE -n com.tm.ctf.clicker/.receiver.ScoreBroadcastReceiver --ei SCORE 10007
```
```bash
adb shell am broadcast -a com.tm.ctf.clicker.SCORE -n com.tm.ctf.clicker/.receiver.ScoreBroadcastReceiver --ei SCORE 59239
```
```bash
adb shell am broadcast -a com.tm.ctf.clicker.SCORE -n com.tm.ctf.clicker/.receiver.ScoreBroadcastReceiver --ei SCORE 100003
```
```bash
adb shell am broadcast -a com.tm.ctf.clicker.SCORE -n com.tm.ctf.clicker/.receiver.ScoreBroadcastReceiver --ei SCORE 495221
```
```bash
adb shell am broadcast -a com.tm.ctf.clicker.SCORE -n com.tm.ctf.clicker/.receiver.ScoreBroadcastReceiver --ei SCORE 1000003
```
```bash
adb shell am broadcast -a com.tm.ctf.clicker.SCORE -n com.tm.ctf.clicker/.receiver.ScoreBroadcastReceiver --ei SCORE 9999999
```

Let's explain the params of the **adb command**:
- `adb shell`: Start a **shell session** with the device.
- `am broadcast`: Sent the **Broadcast Intent**.
- `-a com.tm.ctf.clicker.SCORE`: Set the **intent action**.
- `-n com.tm.ctf.clicker/.receiver.ScoreBroadcastReceiver`: Specify the **component**.
- `--ei SCORE <valor>`: Add the **extra integer** with the **SCORE** key and the **value**.

So, just make a click and get the flag. A **black screen** with **white chars** must be printed. The flag is `TMCTF{Congrats_10MClicks}`


I hope you found it useful (: