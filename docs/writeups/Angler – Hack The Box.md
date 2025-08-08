![[angler1.png]]
**Difficult:** Medium
**Category**: Mobile
**OS**: Android

**Description**: The skilled fisherman used his full strength and expertise to hook the fish. Can you beat him and set the fish free?

---

First we’ll download the **.apk** file. The pass is **hackthebox**

And then **decompile** with **apktool**
```bash
apktool d Angler.apk
```
The **SDK** version is **32**, then we can use an **Android 12 (SDK 31)**

Let’s try install the **.apk**
```bash
adb install -r Angler.apk
```

![[angler2.png]]

Also, let’s check the source code with **jadx-gui**

This is the **MainActivity.java**
```java
public class MainActivity extends g {
    public static final /* synthetic */ int A = 0;
    public TextView v;

    /* renamed from: w, reason: collision with root package name */
    public TextView f1753w;

    /* renamed from: x, reason: collision with root package name */
    public ImageView f1754x;

    /* renamed from: y, reason: collision with root package name */
    public String f1755y = "@|uqcu0t\u007f~7d0{y||0}u1\u001aY7||0du||0i\u007fe0gxubu0dxu0v|qw0yc>";

    /* renamed from: z, reason: collision with root package name */
    public final a f1756z = new a();

    /* loaded from: classes.dex */
    public class a extends BroadcastReceiver {
        public a() {
        }

        @Override // android.content.BroadcastReceiver
        public final void onReceive(Context context, Intent intent) {
            PrintStream printStream;
            String str;
            if (intent.getStringExtra("Is_on").equals("yes")) {
                MainActivity mainActivity = MainActivity.this;
                int i3 = MainActivity.A;
                Window window = mainActivity.getWindow();
                window.addFlags(Integer.MIN_VALUE);
                window.clearFlags(67108864);
                window.setStatusBarColor(mainActivity.getResources().getColor(R.color.purple_200));
                d.a r3 = mainActivity.r();
                Objects.requireNonNull(r3);
                r3.b(new ColorDrawable(mainActivity.getResources().getColor(R.color.teal_700)));
                mainActivity.f1754x.setImageResource(R.drawable.please);
                mainActivity.v.setTextColor(mainActivity.getResources().getColor(R.color.purple_200));
                mainActivity.v.setText("1%");
                mainActivity.f1753w.setText(d.d(mainActivity.f1755y));
                Toast.makeText(context, "Look me inside", 1).show();
                printStream = System.out;
                str = MainActivity.this.getInfo(d.d("XDR"));
            } else {
                printStream = System.out;
                str = "I am Strong, no one can defeat me";
            }
            printStream.println(str);
        }
    }

    static {
        System.loadLibrary("angler");
    }

    public native String getInfo(String str);

    @Override // androidx.fragment.app.p, androidx.activity.ComponentActivity, w.g, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        this.v = (TextView) findViewById(R.id.textView2);
        this.f1753w = (TextView) findViewById(R.id.textView);
        this.f1754x = (ImageView) findViewById(R.id.imageView);
        registerReceiver(this.f1756z, new IntentFilter("android.intent.action.BATTERY_LOW"));
    }
}
```

Here is a **Broadcast receiver** that expected an **extra string** “**Is_on**” “**yes**” in the **android.intent.action.BATTERY_LOW**
```java
public final void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
    this.v = (TextView) findViewById(R.id.textView2);
    this.f1753w = (TextView) findViewById(R.id.textView);
    this.f1754x = (ImageView) findViewById(R.id.imageView);
    registerReceiver(this.f1756z, new IntentFilter("android.intent.action.BATTERY_LOW"));
}
```

If this **string is set as yes**, then, **proceed** with this code
```java
if (intent.getStringExtra("Is_on").equals("yes")) {
MainActivity mainActivity = MainActivity.this;
int i3 = MainActivity.A;
Window window = mainActivity.getWindow();
window.addFlags(Integer.MIN_VALUE);
window.clearFlags(67108864);
window.setStatusBarColor(mainActivity.getResources().getColor(R.color.purple_200));
d.a r3 = mainActivity.r();
Objects.requireNonNull(r3);
r3.b(new ColorDrawable(mainActivity.getResources().getColor(R.color.teal_700)));
mainActivity.f1754x.setImageResource(R.drawable.please);
mainActivity.v.setTextColor(mainActivity.getResources().getColor(R.color.purple_200));
mainActivity.v.setText("1%");
mainActivity.f1753w.setText(d.d(mainActivity.f1755y));
Toast.makeText(context, "Look me inside", 1).show();
printStream = System.out;
str = MainActivity.this.getInfo(d.d("XDR"));
```

Then, we can use **adb** for launch this activity manager.
```bash
sudo adb shell am broadcast -a android.intent.action.BATTERY_LOW --es Is_on yes
```

Output:
```bash
Broadcasting: Intent { act=android.intent.action.BATTERY_LOW flg=0x400000 (has extras) }
Broadcast completed: result=0
```

Result
![[angler3.png]]

**am**
Activity manager

**broadcast**
Send a broadcast message

**-a**
Intent action

**android.intent.action.BATTERY_LOW**
The intent action

**—es**
Extra string

Now, in this point, the app will execute this piece of code:
```java
str = MainActivity.this.getInfo(d.d("XDR"));
```

That is
```java
static {
        System.loadLibrary("angler");
}
public native String getInfo(String str);
```

Because **getInfo();** is an **native method in android**.
And the info is the content **of d.d(“XDR”)**, where in the static code, I don’t found any interesting.
And the **method is compiled in C**, then, probably we need play with some **debugger** for an **Dynamic Analysis**.

But before, we need know what **arch** of **proc** we are using, for that you can run
```bash
adb shell getprop ro.product.cpu.abi
```

And, in my case is **x86_64** then, I’ll use **Angler/lib/x86_64/libangler.so**
It’s time for use **ghidra** and analyze
And we can see the function **Java_com_example_angler_MainActivity_getInfo**

Where if inspect the code we can see that **getInfo** calls two functions, i**llusion** and **ne**.
![[angler4.png]]

**illusion function**
```c
void illusion(char *param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  byte local_58 [16];
  void *local_48;
  basic_string<> local_40 [16];
  void *local_30;
  long local_28;

  local_28 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = 100;
  do {
    std::__ndk1::basic_string<>::basic_string<>(local_40,"HTB{");
                    /* try { // try from 00148970 to 0014897a has its CatchHandler @ 001489cd */
    a((basic_string)local_58);
    if ((local_58[0] & 1) != 0) {
      operator.delete(local_48);
    }
    if (((byte)local_40[0] & 1) != 0) {
      operator.delete(local_30);
    }
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  if (*(long *)(in_FS_OFFSET + 0x28) != local_28) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Here we can see **HTB{** like the start of the flag but we need keep analyzing.

**ne function**
```bash
a lot of text
```

But we can do focus on
```c
iVar3 = strcmp(in_RSI,(char *)pbVar10);
if (iVar3 == 0) {
  std::__ndk1::basic_string<>::basic_string<>((basic_string<> *)param_1,"You found the flag");
}
else {
                  /* try { // try from 00149d0b to 00149d8e has its CatchHandler @ 00149dbb */
  std::__ndk1::basic_string<>::basic_string<>
            ((basic_string<> *)param_1,"I am not here, I am there");
}
```

This methods **have the strcmp** (String compare)
That **if** the strings are **equals**, then **You found the flag**
**else**, **I am not here**, **I am there**

So, let’s keep this code
```bash
frida -U Angler
```

![[angler5.png]]

Then for list **exports** and **imports** We can use the **Module** **Enumerate**
```bash
[Pixel 3 XL::Angler ]->Module.enumerateImports("libangler.so")
[Pixel 3 XL::Angler ]->Module.enumerateImports("libangler.so")
```

Copy and save the **output** in **two** **json** file (exp/imp).json
I just copy the **export content** all that my terminal allowed me, then.

Searching for the **illusion** function in **exp.json**
```bash
cat exp.json | grep illusion -n
```

Output
```bash
6420:        "name": "_Z8illusionPKc"
```

But, we know the **format of the json then**
```bash
cat exp.json | grep illusion -A 1 -B 1
```

-A 1 and -B 1 for grep 1 line above and 1 line below
```json
"address": "0x77888e94a930",
"name": "_Z8illusionPKc",
"type": "function"
```
The name is **_Z8illusionPKc**

And for **strcmp**
```bash
cat imp.json | grep strcmp -A 1 -B 2
```

```json
"address": "0x778ba02582d0",
"module": "/apex/com.android.runtime/lib64/bionic/libc.so",
"name": "strcmp",
"type": "function"
```

Now we need **hook the native library methods**
We can use the **Interceptor methods** of **frida** for **intercept** the **strcmp calls**.

Here’s an script.js
```javascript
// Find the module containing strcmp
var libangler = Module.findBaseAddress("libangler.so");

// Find the address of strcmp within libangler.so
var strcmpPtr = Module.findExportByName(null, "strcmp");

// Intercept strcmp calls
Interceptor.attach(strcmpPtr, {
    onEnter: function(args) {
        // Get the compared strings
        var str1 = Memory.readUtf8String(args[0]);
        var str2 = Memory.readUtf8String(args[1]);

        // Log the compared strings
        console.log("strcmp called with strings:", str1, str2);
    }
});
```

Then
```bash
frida -U -l script.js Angler
```

And run **again** the **broadcast message** of the **start**.
```bash
sudo adb shell am broadcast -a android.intent.action.BATTERY_LOW --es Is_on yes
```

And
![[angler6.png]]

Just parse the **hexcode**
![[angler7.png]]
And get the flag

I hope you found it useful (: