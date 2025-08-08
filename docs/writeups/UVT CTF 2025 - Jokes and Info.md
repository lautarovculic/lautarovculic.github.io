**Description**: We found an apk. It is useless, or isn't it?

**Download**: https://lautarovculic.com/my_files/jokes_and_info.apk
**NOTE**: This challenge makes a request to a host, which is probably no longer available at the time you are reading this write-up.
You can learn anyway.

![[uvtCTF2025_1.png]]

Install the **APK** file with **ADB**
```bash
adb install -r jokes_and_info.apk
```

We can see some `JSON` cards information in the `MainActivity`.
Let's check the **source code** with **jadx**.

In `MainActivity` we can see the `Utils()` **class**.
```java
private final Utils utils = new Utils();
```

Inside, we observe that the `libnative.so` are loaded:
```java
public class Utils {  
    private native String getHiddenFlag();  
  
    public native String getJoke();  
  
    public native String getUVTCTF();  
  
    static {  
        System.loadLibrary("native-lib");  
    }  
}
```
And also, call to **three functions**.
Looking for strings in the code, I didn't see the `JSON` content, so, may be this can be a **URL Request**?

Obviously, the `getHiddenFlag()` is what we need.

Decompile the **APK** with **APKTool**
```bash
apktool d jokes_and_info.apk
```

And then, inside of `lib` directory we can see the `libnative.so`.
Load this into **Ghidra** tool and notice the three functions that previously has been seen in the *java code*:
- `Java_com_example_uvt_1ctf_12025_Utils_ getHiddenFlag`
- `Java_com_example_uvt_1ctf_12025_Utils_ getJoke`
- `Java_com_example_uvt_1ctf_12025_Utils_ getUVTCTF`

The `getHiddenFlag()` function is:
```C
Java_com_example_uvt_1ctf_12025_Utils_getHiddenFlag(long *param_1)
{
    void *__ptr;
    undefined8 uVar1;
    
    __ptr = (void *)FUN_00100be0("91.99.1.179", 0xa4fa, "/somebody-found-a-random-flag-path");
    uVar1 = (**(code **)(*param_1 + 0x538))(param_1, __ptr);
    free(__ptr);
    return uVar1;
}
```

We found **a path**, a **host** and also **the port**, which is:
```bash
echo $((0xa4fa))
```
`42234`.

So, the final **URL** is -> http://91.99.1.179:42234/somebody-found-a-random-flag-path

Get the flag with **cURL**:
```bash
curl -X GET "http://91.99.1.179:42234/somebody-found-a-random-flag-path"
```

Flag:  **`UVT{m0b1l3_.s0_m4y_c0nt4in_s3ns1tiv3_1nf0}`**

I hope you found it useful (: