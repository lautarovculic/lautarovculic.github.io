**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/c6acf741819c9632cffd12aec0b61aa0dcee0b9f262ccc24262fd8458512c85c
**Password**: infected

![[laby2016_swip3r1.png]]

Install the **apk** with **adb**
```bash
adb install -r Swip3r.apk
```

Then, decompile this with **apktool**
```bash
apktool d Swip3r.apk
```
The app crashes when we press the button **give me the child**.
Let's inspect the **source code** with **jadx**.

There are **two** java classes.
Pay attention, the **MainActivity** (Home) is **Swip3r**, no **MainActivity**.
You can **notice** this reading the **AndroidManifest.xml** file
```XML
<activity  
    android:label="@string/app_name"  
    android:name="ru.labyrenth.swiping.swip3r.MainActivity"  
    android:parentActivityName="ru.labyrenth.swiping.swip3r.Swip3r"/>  
<activity  
    android:label="Swip3r"  
    android:name="ru.labyrenth.swiping.swip3r.Swip3r">  
    <intent-filter>  
        <action android:name="android.intent.action.MAIN"/>  
        <category android:name="android.intent.category.LAUNCHER"/>  
    </intent-filter>  
</activity>
```

The **Swip3r** class (MainActivity) isn't our interest.
We will work with the **MainActivity** class.
This activity loads an **native library** called **`swiipiin`**.
We can found this as **`libswiipiin`**
```bash
lib
└── armeabi
    └── libswiipiin.so
```
But here I can't find anything.

After inspecting the source code, I notice that the **app** takes the **gestures** of the **touch screen**.
This is the **onFling** method that we need pay attention
```java
public boolean onFling(MotionEvent motionEvent, MotionEvent motionEvent2, float f, float f2) {  
        if (motionEvent.getY() - motionEvent2.getY() > 50.0f) {  
            ((TextView) findViewById(R.id.startT)).setText("");  
            this.a = 0;  
            if (this.a == 0 && !this.n) {  
                this.p.setImageResource(R.drawable.dbowie_time);  
                this.a = 1;  
                this.c = 0;  
                this.g = 4;  
                this.h = 0;  
                this.n = true;  
                this.d = 9;  
            }  
            if (!this.n) {  
                this.p.setImageResource(R.drawable.dbowie_time);  
                this.a = 12;  
                this.i = 13;  
                this.f = 46;  
                this.e = 55;  
                this.d = 4;  
                ((TextView) findViewById(R.id.wo00ops)).setText(well(this.h, this.j, this.b, this.f, this.l, this.i, this.e, this.k));  
            }  
            if (this.j == 61441 && this.b == this.l + 12) {  
                if (this.k == 45333) {  
                    this.l = 8;  
                    this.b = (this.b - this.l) - 10;  
                }  
                ((TextView) findViewById(R.id.wo00ops)).setText(well(this.h, this.j, this.b, this.f, this.l, this.i, this.e, this.k));  
            }  
        } else if (motionEvent2.getY() - motionEvent.getY() > 50.0f) {  
            if (this.c == 1 && this.a == 2) {  
                if (this.d == 4) {  
                    this.p.setImageResource(R.drawable.dbowie_oops);  
                    this.c = 2;  
                    this.a = 3;  
                    this.f = 62481;  
                    this.h = 56;  
                    this.i = this.h - 40;  
                }  
            } else if (this.d == 9) {  
                this.a = 10;  
                this.n = false;  
                this.a = 51;  
                this.p.setImageResource(R.drawable.babycry);  
                this.m++;  
                ((TextView) findViewById(R.id.oops)).setText(String.format("0oo0oopps!: %d", Integer.valueOf(this.m)));  
            } else {  
                this.p.setImageResource(R.drawable.babycry);  
                this.c = 0;  
                this.a = 0;  
                this.m++;  
                ((TextView) findViewById(R.id.oops)).setText(String.format("0oo0oopps!: %d", Integer.valueOf(this.m)));  
            }  
        } else if (motionEvent.getX() - motionEvent2.getX() > 50.0f) {  
            if (this.a != 1 || !this.n) {  
                this.p.setImageResource(R.drawable.babycry);  
                this.c = 0;  
                this.a = 0;  
                this.m++;  
                ((TextView) findViewById(R.id.oops)).setText(String.format("0oo0oopps!: %d", Integer.valueOf(this.m)));  
            } else if (this.g == 4 && this.h == 0) {  
                this.p.setImageResource(R.drawable.dbowie_such_a_pity);  
                this.c = 1;  
                this.a = 2;  
                this.l = 7;  
                this.d = 4;  
            }  
        } else if (motionEvent2.getX() - motionEvent.getX() <= 50.0f) {  
            this.p.setImageResource(R.drawable.babycry);  
            this.m++;  
            ((TextView) findViewById(R.id.oops)).setText(String.format("0oo0oopps!: %d", Integer.valueOf(this.m)));  
        } else if (this.c == 2 && this.a == 3) {  
            if (this.f == 62481) {  
                this.j = 61441;  
                this.k = 45333;  
                this.p.setImageResource(R.drawable.bowiebaby);  
                ((TextView) findViewById(R.id.oops)).setText("");  
                ((TextView) findViewById(R.id.wo00ops)).setText(a(this.k));  
                this.h = 333;  
                this.b = 1;  
                this.e = this.b + this.h;  
                this.b = 19;  
            }  
        } else if (this.a == 51 || this.l == 7) {  
            this.f = 45;  
            this.h = 222;  
            this.k = 47806;  
            ((TextView) findViewById(R.id.wo00ops)).setText(well(this.h, this.j, this.b, this.f, this.l, this.i, this.e, this.k));  
        } else {  
            this.p.setImageResource(R.drawable.babycry);  
            this.c = 0;  
            this.a = 0;  
            this.f = 9;  
            this.m++;  
            ((TextView) findViewById(R.id.oops)).setText(String.format("0oo0oopps!: %d", Integer.valueOf(this.m)));  
        }  
        return true;  
    }
```

This use **coordinates** and check if the **movement** is **up, down, left or right**.
According to the **correct** swipe steps, we will get the flag.
After some **tries** and erros.
Reading the **source** code and the **resources folder** (`res/drawable`). I match with the **correct pattern** and is **`up, left, down, right, up, left, down, right`**.
I install the **apk** in my **physic test device** because the **emulator** don't take the gestures.

So, after try, I get the **flag**
![[laby2016_swip3r2.png]]

**Flag:**
**`PAN{jAr3d_sayz_'swwip3_!NO!_swipp11nn'}`**

I hope you found it useful (:
