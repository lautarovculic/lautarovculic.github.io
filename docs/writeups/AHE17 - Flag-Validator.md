### AHE17 : Android Hacking Events 2017
For this challenge, probably we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

For download the **APK**
https://team-sik.org/wp-content/uploads/2017/06/FlagValidator.apk_.zip


![[flagValidator1.png]]

With **apktool** will extract the content of the **apk** file
```bash
apktool d FlagValidator.apk
```

Let's see the content of **MainActivity.java** that say so clear the structure of the flag.
In the **onValidateClick** method
```java
public void onValidateClick(View view) {  
        new StringBuilder("Validate Token input: ").append((Object) this.input.getText());  
        String[] split = this.input.getText().toString().split("-");  
        if (split.length != 4) {  
            Toast.makeText(this, "Wrong token format, don't forget - between xxx !", 1).show();  
        } else {  
            a.a(split[0]);  
            a.b(split[1]);  
            a.c(split[2]);  
            a.d(split[3]);  
        }  
        new StringBuilder("Subparts ").append(m.cardinality());  
        if (m.cardinality() != 4) {  
            Toast.makeText(this, "Still " + (4 - m.cardinality()) + " token missing !", 1).show();  
            return;  
        }  
        StringBuffer stringBuffer = new StringBuffer();  
        stringBuffer.append(split[0]);  
        stringBuffer.append("-");  
        stringBuffer.append(split[1]);  
        stringBuffer.append("-");  
        stringBuffer.append(split[2]);  
        stringBuffer.append("-");  
        stringBuffer.append(split[3]);  
        new StringBuilder("Flag combined ").append(stringBuffer.toString());  
        if ("1017e4fefe8381aec8c3fbaf8f8148f53f81d340".equals(org.team_sik.flagvalidator.a.a.a.a.a(stringBuffer.toString(), "SHA1"))) {  
            AlertDialog.Builder builder = new AlertDialog.Builder(this);  
            builder.setMessage("Congratulation !").setCancelable(false).setPositiveButton("Yeah", new DialogInterface.OnClickListener() { // from class: org.team_sik.flagvalidator.MainActivity.1  
                @Override // android.content.DialogInterface.OnClickListener  
                public final void onClick(DialogInterface dialogInterface, int i) {  
                    dialogInterface.dismiss();  
                }  
            });  
            builder.create().show();  
        }  
    }
```

For **every part** we have a **different method**
Here is the **four methods** in **org.team_sik.flagvalidator.a.a.b**
```java
public static void a(String str) {  
        if ("cHVtcjRX".equals(org.team_sik.flagvalidator.a.a.a.a.a(str))) {  
            MainActivity.m.set(1, true);  
        } else {  
            MainActivity.m.set(1, false);  
        }  
    }  
  
    public static void b(String str) {  
        if (org.team_sik.flagvalidator.a.a.a.a.a(a).equals(str)) {  
            MainActivity.m.set(2, true);  
        } else {  
            MainActivity.m.set(2, false);  
        }  
    }  
  
    public static void c(String str) {  
        try {  
            Field declaredField = Class.forName(org.team_sik.flagvalidator.a.a.a.a.a(new int[]{1879986099, 1260141997, 1879986140, 1260142047, -885815433, -256489066, 1879986119, 1260142024, -885815439, -256489003, 1879986156, 1260142046, -885815431, -256489005, 1879986077, 1260142027, -885815428, -256488999, 1879986132, 1260142043, -885815439, -256489004, 1879986138, 1260142025, -885815439, -256489012, 1879986140, 1260142047, -885815490, -256488971, 1879986130, 1260142020, -885815426, -256488967, 1879986128, 1260142041, -885815431, -256489010, 1879986138, 1260142041, -885815447, -885815536, -256489032})).getDeclaredField("TOKEN2");  
            declaredField.setAccessible(true);  
            new StringBuilder("Flag value ").append((String) declaredField.get(new MainActivity()));  
            if (((String) declaredField.get(new MainActivity())).equals(str)) {  
                MainActivity.m.set(3, true);  
            } else {  
                MainActivity.m.set(3, false);  
            }  
        } catch (ClassNotFoundException e) {  
            Log.e("VAL", "Something went wrong :-(");  
        } catch (IllegalAccessException e2) {  
            Log.e("VAL", "Something went wrong :-(");  
        } catch (NoSuchFieldException e3) {  
            Log.e("VAL", "Something went wrong :-(");  
        }  
    }  
  
    public static void d(String str) {  
        if ("af246d4dacd2f683ff850dcfe465562f".equals(org.team_sik.flagvalidator.a.a.a.a.a(str, "MD5"))) {  
            MainActivity.m.set(4, true);  
        } else {  
            MainActivity.m.set(4, false);  
        }  
    }
```

### Method 1
```java
public static void a(String str) {  
        if ("cHVtcjRX".equals(org.team_sik.flagvalidator.a.a.a.a.a(str))) {  
            MainActivity.m.set(1, true);  
        } else {  
            MainActivity.m.set(1, false);  
        }  
    }
```

We have the string **cHVtcjRX**
That have this logic
```java
public static String a(String str) {  
        String sb = new StringBuilder(str).reverse().toString();  
        String str2 = "";  
        try {  
            str2 = Base64.encodeToString(sb.getBytes("utf-8"), 2);  
        } catch (UnsupportedEncodingException e) {  
            e.printStackTrace();  
        }  
        return str2;  
    }
```

This about an **base64** encode and **reversed**.
```bash
echo 'cHVtcjRX' | base64 -d | rev
```

Output: **W4rmup**

### Method 2
```java
public static void b(String str) {  
        if (org.team_sik.flagvalidator.a.a.a.a.a(a).equals(str)) {  
            MainActivity.m.set(2, true);  
        } else {  
            MainActivity.m.set(2, false);  
        }  
    }
```

And this is the logic
```java
public static String a(int[] iArr) {  
        StringBuilder sb = new StringBuilder();  
        int i = iArr[0];  
        int i2 = iArr[1];  
        int i3 = iArr[iArr.length - 2];  
        int i4 = iArr[iArr.length - 1];  
        for (int i5 = 2; i5 < iArr.length - 2; i5++) {  
            sb.append((char) (iArr[i5] ^ new int[]{i, i2, i3, i4}[(i5 - 2) % 4]));  
        }  
        return sb.toString();  
    }
```

There are another value of **a** which is
```java
private static final int[] a = {-1602723372, 811074983, -1602723401, 811075023, -949198329, 1053776347, -1602723400, 811074964, -949198243, 1053776336, -1602723353, -949198285, 1053776311};
```

This is a simple logic in java working with **array**. We can do an **python script** that do the same job an get a fast **output**
```python
#!/usr/bin/env python3

def a(iArr):
    sb = []
    i = iArr[0]
    i2 = iArr[1]
    i3 = iArr[-2]
    i4 = iArr[-1]

    for i5 in range(2, len(iArr) - 2):
        decoded_char = chr(iArr[i5] ^ [i, i2, i3, i4][(i5 - 2) % 4])
        sb.append(decoded_char)

    return ''.join(sb)

iArr = [-1602723372, 811074983, -1602723401, 811075023, -949198329, 1053776347, 
        -1602723400, 811074964, -949198243, 1053776336, -1602723353, -949198285, 1053776311]

final = a(iArr)
print(final)
```

Output: **ch4ll3ng3**

### Method 3
```java
public static void c(String str) {  
        try {  
            Field declaredField = Class.forName(org.team_sik.flagvalidator.a.a.a.a.a(new int[]{1879986099, 1260141997, 1879986140, 1260142047, -885815433, -256489066, 1879986119, 1260142024, -885815439, -256489003, 1879986156, 1260142046, -885815431, -256489005, 1879986077, 1260142027, -885815428, -256488999, 1879986132, 1260142043, -885815439, -256489004, 1879986138, 1260142025, -885815439, -256489012, 1879986140, 1260142047, -885815490, -256488971, 1879986130, 1260142020, -885815426, -256488967, 1879986128, 1260142041, -885815431, -256489010, 1879986138, 1260142041, -885815447, -885815536, -256489032})).getDeclaredField("TOKEN2");  
            declaredField.setAccessible(true);  
            new StringBuilder("Flag value ").append((String) declaredField.get(new MainActivity()));  
            if (((String) declaredField.get(new MainActivity())).equals(str)) {  
                MainActivity.m.set(3, true);  
            } else {  
                MainActivity.m.set(3, false);  
            }  
        } catch (ClassNotFoundException e) {  
            Log.e("VAL", "Something went wrong :-(");  
        } catch (IllegalAccessException e2) {  
            Log.e("VAL", "Something went wrong :-(");  
        } catch (NoSuchFieldException e3) {  
            Log.e("VAL", "Something went wrong :-(");  
        }  
    }
```

In the **MainActivity.java** we can see **TOKEN2**
```java
public class MainActivity extends d {  
    public static BitSet m;  
    private String TAG = getClass().getSimpleName();  
    private String TOKEN2 = value();  
    private EditText input;  
  
    static {  
        System.loadLibrary("native-lib");  
        m = new BitSet(4);  
    }
```

And **value()** is
```java
public native String value();
```

An string of the **native libraries**.
Let's use **ghidra** for see the **libraries** and what we can found inside.
I'll use this **.so** file
```bash
FlagValidator/lib
└── x86
    └── libnative-lib.so
```

![[flagValidator2.png]]

The third flag is **5UcC33D3d**

### Method 4
```java
public static void d(String str) {  
        if ("af246d4dacd2f683ff850dcfe465562f".equals(org.team_sik.flagvalidator.a.a.a.a.a(str, "MD5"))) {  
            MainActivity.m.set(4, true);  
        } else {  
            MainActivity.m.set(4, false);  
        }  
    }
```

This **MD5** is so broke.
You can find in crackstation the **string** according to the **MD5** value

Value: **continue1**

Then the final flag looks like
**W4rmup-ch4ll3ng3-5UcC33D3d-continue1**

Just insert in the text box and
![[flagValidator3.png]]

I hope you found it useful (: