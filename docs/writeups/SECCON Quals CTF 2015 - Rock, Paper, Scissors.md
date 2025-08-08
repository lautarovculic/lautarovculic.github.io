**Description**: Please win 1000 times in rock-paper-scissors
**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/rps.apk

![[secconApk1.png]]

Install the **apk** with **adb**
```bash
adb install -r rps.apk
```

Then, decompile it with **apktool**
```bash
apktool d rps.apk
```

We can see the **game Rock, Paper and Scissors**.
If we **win**, +1.
**Draw** keep points and **loose all the points**
We need (description say) **1000** points. Statistically impossible

So let's inspect the **source code** with **jadx** (GUI version)
We can see the **logic** on the **onClick** method
```java
public void onClick(View v) {  
        if (this.flag != 1) {  
            this.flag = 1;  
            TextView tv3 = (TextView) findViewById(R.id.textView3);  
            tv3.setText("");  
            TextView tv = (TextView) findViewById(R.id.textView);  
            TextView tv2 = (TextView) findViewById(R.id.textView2);  
            this.m = 0;  
            Random rm = new Random();  
            this.n = rm.nextInt(3);  
            String[] ss = {"CPU: Paper", "CPU: Rock", "CPU: Scissors"};  
            tv2.setText(ss[this.n]);  
            if (v == this.P) {  
                tv.setText("YOU: Paper");  
                this.m = 0;  
            }  
            if (v == this.r) {  
                tv.setText("YOU: Rock");  
                this.m = 1;  
            }  
            if (v == this.S) {  
                tv.setText("YOU: Scissors");  
                this.m = 2;  
            }  
            this.handler.postDelayed(this.showMessageTask, 1000L);  
        }  
    }
```

But we are interested in this piece of **MainActivity** java code
```java
public class MainActivity extends Activity implements View.OnClickListener {  
    Button P;  
    Button S;  
    int flag;  
    int m;  
    int n;  
    Button r;  
    int cnt = 0;  
    private final Handler handler = new Handler();  
    private final Runnable showMessageTask = new Runnable() { 
    
        public void run() {  
            TextView tv3 = (TextView) MainActivity.this.findViewById(R.id.textView3);  
            if (MainActivity.this.n - MainActivity.this.m == 1) {  
                MainActivity.this.cnt++;  
                tv3.setText("WIN! +" + String.valueOf(MainActivity.this.cnt));  
            } else if (MainActivity.this.m - MainActivity.this.n == 1) {  
                MainActivity.this.cnt = 0;  
                tv3.setText("LOSE +0");  
            } else if (MainActivity.this.m == MainActivity.this.n) {  
                tv3.setText("DRAW +" + String.valueOf(MainActivity.this.cnt));  
            } else if (MainActivity.this.m < MainActivity.this.n) {  
                MainActivity.this.cnt = 0;  
                tv3.setText("LOSE +0");  
            } else {  
                MainActivity.this.cnt++;  
                tv3.setText("WIN! +" + String.valueOf(MainActivity.this.cnt));  
            }  
            if (1000 == MainActivity.this.cnt) {  
                tv3.setText("SECCON{" + String.valueOf((MainActivity.this.cnt + MainActivity.this.calc()) * 107) + "}");  
            }  
            MainActivity.this.flag = 0;  
        }  
    };
[...]
[...]
[...]
}
```

Here is an simple logic. The **structure of the flag** is so easy.
If the **counter** (of **wins**) is 1000, then. The flag is
`SECCON{1000+calc*107}`
We can **disassemble** the **lib**.
With **ghidra** we can look the function of **libcalc.so** (look inside of **lib/x86** folder that **apktool** drop)
![[secconApk2.png]]
The value that **calc** function returns is **7**.
So the flag is `SECCON{1000+7*107}` => `SECCON{107749}`

But where are you going?
We don't resolve the CTF of this way.
We need **make the flag printable**.

So, come back and check the code.
We can see that the **cnt** (counter of wins) variable is initialized in 0.
```java
public class MainActivity extends Activity implements View.OnClickListener {  
    Button P;  
    Button S;  
    int flag;  
    int m;  
    int n;  
    Button r;  
    int cnt = 0;
[...]
[...]
```

Because we can't change the **if** conditions in the smali code (cnt must have the 1000 value).
So we need modify the value of **cnt when it is initialized** to **999**, because the flag is trigger **when** cnt is **1000** after win.

Looking in the **MainActivity.smali** file, we can find the `int cnt = 0;` line in **51** and **52**
```smali
51 const/4 v0, 0x0
52 iput v0, p0, Lcom/example/seccon2015/rock_paper_scissors/MainActivity;->cnt:LiAccessibility:
```

We need change `const/4 v0, 0x0` to `const/16 v0, 0x3E7`
**const/4**: is for small values that fit in 4 bits (up to 0xF or 15 in decimal). Since 999 is a larger value, you need to use const/16 to store a 16-bit value.
**const/16**: allows you to assign **values of up to 16 bits**, such as **0x3E7** which corresponds to 999 in decimal.

So the **51** line must look like `const/16 v0, 0x3E7`
Save the file and now is time for **rebuild** the apk.

With **apktool** rebuild the app
```bash
apktool b rps
```

Generate a **key**
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

**Sign** the apk
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore rps/dist/rps.apk alias
```

Uninstall the app installed in the device and install the **new apk**
```bash
adb install -r rps/dist/rps.apk
```

Now we **launch** the app. Now the **cnt** is 999, so we need **win** just one round for **print the flag**.
*If we loose, we need close and re-launch the app again*

![[secconApk3.png]]


I hope you found it useful (: