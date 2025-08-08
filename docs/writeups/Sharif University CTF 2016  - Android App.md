**Description**: Find the Flag!!
**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/Sharif_CTF.apk

![[sharif_ctf_2016_1.png]]

Install the **apk** with **adb**
```bash
adb install -r Sharif_CTF.apk
```

Then, **decompile** with **apktool**
```bash
apktool d Sharif_CTF.apk
```

We can see an **input** that need a **serial number** for login.
Let's inspect the **source code** with **jadx** (GUI Version)
The **package name is** `com.example.ctf2`

Here's the **MainActivity** java code
```java
public class MainActivity extends Activity {  
    Button a;  
    EditText b;  
    TextView c;  
    int d = 123;  
    String e = "Code";  
  
    static {  
        System.loadLibrary("adnjni");  
    }  
  
    public native int IsCorrect(String str);  
  
    @Override // android.app.Activity  
    public void onCreate(Bundle bundle) {  
        super.onCreate(bundle);  
        setContentView(R.layout.activity_main);  
        this.a = (Button) findViewById(R.id.Btn);  
        this.b = (EditText) findViewById(R.id.edit_message);  
        this.c = (TextView) findViewById(R.id.text_id);  
        this.e = Build.SERIAL;  
        this.d = 114366;  
        this.a.setOnClickListener(new a(this));  
    }  
  
    public native int processObjectArrayFromNative(String str);  
}
```

And we can found a **library** called `adnjni`
And `IsCorrect(String str)` is an **function** from this library.

For the **a** class (**onClick** method)
```java
public void onClick(View view) {  
        new String(" ");  
        String editable = this.a.b.getText().toString();  
        Log.v("EditText", this.a.b.getText().toString());  
        new String("");  
        int processObjectArrayFromNative = this.a.processObjectArrayFromNative(editable);  
        int IsCorrect = this.a.IsCorrect(editable);  
        String str = String.valueOf(this.a.d + processObjectArrayFromNative) + " ";  
        try {  
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");  
            messageDigest.update(str.getBytes());  
            byte[] digest = messageDigest.digest();  
            StringBuffer stringBuffer = new StringBuffer();  
            for (byte b : digest) {  
                stringBuffer.append(Integer.toString((b & 255) + 256, 16).substring(1));  
            }  
            if (IsCorrect == 1 && this.a.e != "unknown") {  
                this.a.c.setText("Sharif_CTF(" + stringBuffer.toString() + ")");  
            }  
            if (IsCorrect == 1 && this.a.e == "unknown") {  
                this.a.c.setText("Just keep Trying :-)");  
            }  
            if (IsCorrect == 0) {  
                this.a.c.setText("Just keep Trying :-)");  
            }  
        } catch (NoSuchAlgorithmException e) {  
            e.printStackTrace();  
        }  
    }
```

Here's what occur when we click the **login** button, get the **text** from edit text.
Call to the **native functions** (that we talked previously) and an **string is created** that sum the **d** value and the result of `processObjectArrayFromNative`
Finally, this string is **passed** to an **md5sum**.

Let's inspect the **libnative**.
```bash
Sharif_CTF/lib/armeabi
└── libadnjni.so
```

I'll use **ghidra**
![[sharif_ctf_2016_2.png]]

We can see that the **strcmp** is comparing the value of `ef57f3fe3cf603c03890ee588878c0ec`
If we insert this value in the **input** field, we get the flag
![[sharif_ctf_2016_3.png]]

Flag is
**`Sharif_CTF(833489ef285e6fa80690099efc5d9c9d)`**

I hope you found it useful (: