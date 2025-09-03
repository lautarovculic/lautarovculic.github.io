**Description**: Embark on a thrilling adventure with GeofenceGamble! Explore your city to discover and collect virtual relics of varying rarities scattered across real-world locations.

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-GeofenceGamble_1.png]]

Let's install the `.apk` file using **ADB**.
```bash
adb install -r GeofenceGamble.apk
```

In my case, I use a physical device for this challenge. *Once the app is launched and permissions are granted*, multiple **root detection checks are triggered**.
In fact, these mechanism are:
- `checkSuPaths`

- `checkForMagisk`

- `checkForBusyBox` <- *Detected on my device*

- `checkBuildTags`

- `checkDangerousProps`

- `checkSELinuxPermissive`

- `checkForHooks`

- `checkForRootManagementApps`

- `checkForDangerousApps`

- `checkForEmulatorFiles`

- `checkEmulatorProps`

- `checkEmulatorHardwareName`

- `checkQemuProps` <- *Detected on my device*

- `canWriteToSystemFolder`

- `checkNativeRootIndicators`


Since *BusyBox is embedded in my device’s system partition and cannot be easily removed*, I decided to **bypass all the checks dynamically with Frida**.
But, first let's search the code where these mechanism was implemented!
### Bypass
Let's analyze the **source code** using **JADX**.
I search for busybox word and I found this class: **`RootDetector`** in **`com.eightksec.geofencegamble.security`** package.

```java
public static final /* data */ class RootDetectionResult {  
        public static final int $stable = 0;  
        private final boolean isRooted;  
        private final String methodName;  
  
        public static /* synthetic */ RootDetectionResult copy$default(RootDetectionResult rootDetectionResult, String str, boolean z, int i, Object obj) {  
            if ((i & 1) != 0) {  
                str = rootDetectionResult.methodName;  
            }  
            if ((i & 2) != 0) {  
                z = rootDetectionResult.isRooted;  
            }  
            return rootDetectionResult.copy(str, z);  
        }  
  
        /* renamed from: component1, reason: from getter */  
        public final String getMethodName() {  
            return this.methodName;  
        }  
  
        /* renamed from: component2, reason: from getter */  
        public final boolean getIsRooted() {  
            return this.isRooted;  
        }  
  
        public final RootDetectionResult copy(String methodName, boolean isRooted) {  
            Intrinsics.checkNotNullParameter(methodName, "methodName");  
            return new RootDetectionResult(methodName, isRooted);  
        }  
  
        public boolean equals(Object other) {  
            if (this == other) {  
                return true;  
            }  
            if (!(other instanceof RootDetectionResult)) {  
                return false;  
            }  
            RootDetectionResult rootDetectionResult = (RootDetectionResult) other;  
            return Intrinsics.areEqual(this.methodName, rootDetectionResult.methodName) && this.isRooted == rootDetectionResult.isRooted;  
        }  
  
        public int hashCode() {  
            return (this.methodName.hashCode() * 31) + Boolean.hashCode(this.isRooted);  
        }  
  
        public String toString() {  
            return "RootDetectionResult(methodName=" + this.methodName + ", isRooted=" + this.isRooted + ')';  
        }  
  
        public RootDetectionResult(String methodName, boolean z) {  
            Intrinsics.checkNotNullParameter(methodName, "methodName");  
            this.methodName = methodName;  
            this.isRooted = z;  
        }  
  
        public final String getMethodName() {  
            return this.methodName;  
        }  
  
        public final boolean isRooted() {  
            return this.isRooted;  
        }  
    }  
  
    public final boolean isDeviceRootedOrEmulator() {  
        List<RootDetectionResult> performChecks = performChecks();  
        logDetectionResults(performChecks);  
        List<RootDetectionResult> list = performChecks;  
        if ((list instanceof Collection) && list.isEmpty()) {  
            return false;  
        }  
        Iterator<T> it = list.iterator();  
        while (it.hasNext()) {  
            if (((RootDetectionResult) it.next()).isRooted()) {  
                return true;  
            }  
        }  
        return false;  
    }  
  
    public final List<RootDetectionResult> getDetectionInfo() {  
        return performChecks();  
    }  
  
    private final List<RootDetectionResult> performChecks() {  
        ArrayList arrayList = new ArrayList();  
        arrayList.add(new RootDetectionResult("SU Binary Paths (Java)", checkSuPaths()));  
        arrayList.add(new RootDetectionResult("Build Tags (test-keys)", checkBuildTags()));  
        arrayList.add(new RootDetectionResult("Dangerous Props", checkDangerousProps()));  
        arrayList.add(new RootDetectionResult("RW System Paths", canWriteToSystemFolder()));  
        arrayList.add(new RootDetectionResult("Hooking Frameworks (Java)", checkForHooks()));  
        arrayList.add(new RootDetectionResult("Magisk Specific Files/Sockets", checkForMagisk()));  
        arrayList.add(new RootDetectionResult("Root Management Apps", checkForRootManagementApps()));  
        arrayList.add(new RootDetectionResult("Potentially Dangerous Apps", checkForDangerousApps()));  
        arrayList.add(new RootDetectionResult("BusyBox Binary", checkForBusyBox()));  
        arrayList.add(new RootDetectionResult("SELinux Status (Permissive)", checkSELinuxPermissive()));  
        arrayList.add(new RootDetectionResult("SU Binary Paths (Native)", NativeRootChecker.INSTANCE.checkSuExists()));  
        arrayList.add(new RootDetectionResult("Suspicious Libs in /proc/maps (Native)", NativeRootChecker.INSTANCE.checkProcMaps()));  
        arrayList.add(new RootDetectionResult("Emulator Files", checkForEmulatorFiles()));  
        arrayList.add(new RootDetectionResult("Emulator Props (Generic)", checkEmulatorProps()));  
        arrayList.add(new RootDetectionResult("Emulator Hardware/Device Name", checkEmulatorHardwareName()));  
        arrayList.add(new RootDetectionResult("Emulator QEMU Props", checkQemuProps()));  
        return arrayList;  
    }  
  
    private final boolean checkSuPaths() {  
        String[] strArr = {"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"};  
        for (int i = 0; i < 10; i++) {  
            if (new File(strArr[i]).exists()) {  
                return true;  
            }  
        }  
        return false;  
    }  
  
    private final boolean checkBuildTags() {  
        String str = Build.TAGS;  
        return str != null && StringsKt.contains$default((CharSequence) str, (CharSequence) "test-keys", false, 2, (Object) null);  
    }  
  
    private final boolean checkDangerousProps() {  
        for (Map.Entry entry : MapsKt.mapOf(TuplesKt.m207to("ro.debuggable", "1"), TuplesKt.m207to("ro.secure", "0")).entrySet()) {  
            if (Intrinsics.areEqual(getSystemProperty((String) entry.getKey()), (String) entry.getValue())) {  
                return true;  
            }  
        }  
        return false;  
    }  
  
    private final boolean canWriteToSystemFolder() {  
        File file;  
        String[] strArr = {"/system", "/system/bin", "/system/sbin", "/system/xbin", "/vendor/bin", "/sbin", "/etc"};  
        for (int i = 0; i < 7; i++) {  
            try {  
                file = new File(strArr[i], "test_write_" + System.currentTimeMillis());  
                if (file.exists()) {  
                    file.delete();  
                }  
            } catch (Exception unused) {  
            }  
            if (file.createNewFile()) {  
                file.delete();  
                return true;  
            }  
            continue;  
        }  
        return false;  
    }  
  
    private final boolean checkNativeRootIndicators() {  
        String[] strArr = new String[1];  
        try {  
            Process exec = Runtime.getRuntime().exec("which su");  
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()));  
            String readLine = bufferedReader.readLine();  
            bufferedReader.close();  
            int waitFor = exec.waitFor();  
            exec.destroy();  
            if (waitFor != 0 || readLine == null) {  
                return false;  
            }  
            return readLine.length() > 0;  
        } catch (Exception e) {  
            Log.w(this.TAG, "Error executing command: which su", e);  
            return false;  
        }  
    }  
  
    private final boolean checkForHooks() {  
        ApplicationInfo applicationInfo;  
        try {  
            throw new Exception("Hook Check");  
        } catch (Exception e) {  
            StackTraceElement[] stackTrace = e.getStackTrace();  
            Intrinsics.checkNotNullExpressionValue(stackTrace, "getStackTrace(...)");  
            for (StackTraceElement stackTraceElement : stackTrace) {  
                String className = stackTraceElement.getClassName();  
                Intrinsics.checkNotNull(className);  
                String str = className;  
                if (StringsKt.contains$default((CharSequence) str, (CharSequence) "de.robv.android.xposed", false, 2, (Object) null) || StringsKt.contains$default((CharSequence) str, (CharSequence) "com.saurik.substrate", false, 2, (Object) null) || StringsKt.contains$default((CharSequence) str, (CharSequence) "com.cigital.freak", false, 2, (Object) null) || StringsKt.contains$default((CharSequence) str, (CharSequence) "com.lody.virtual", false, 2, (Object) null)) {  
                    return true;  
                }  
            }  
            String[] strArr = {"de.robv.android.xposed.XposedHelpers", "de.robv.android.xposed.XposedBridge", "com.saurik.substrate.MS", "com.lody.virtual.client.core.VirtualCore"};  
            for (int i = 0; i < 4; i++) {  
                String str2 = strArr[i];  
                try {  
                    Class.forName(str2);  
                    return true;  
                } catch (ClassNotFoundException unused) {  
                } catch (Exception e2) {  
                    Log.w(this.TAG, "Error checking for hook class " + str2, e2);  
                }  
            }  
            try {  
                applicationInfo = this.context.getPackageManager().getApplicationInfo("de.robv.android.xposed.installer", 0);  
                Intrinsics.checkNotNullExpressionValue(applicationInfo, "getApplicationInfo(...)");  
            } catch (PackageManager.NameNotFoundException unused2) {  
            } catch (Exception e3) {  
                Log.w(this.TAG, "Error checking Xposed files", e3);  
            }  
            return new File(applicationInfo.dataDir, "bin/XposedBridge.jar").exists();  
        }  
    }  
  
    private final boolean checkForMagisk() {  
        String[] strArr = {"/sbin/.magisk", "/sbin/.core", "/sbin/.su", "/sbin/magisk", "/cache/.disable_magisk", "/cache/magisk.log", "/cache/magisk_mount", "/cache/magisk_merge", "/data/adb/magisk", "/data/adb/magisk.img", "/data/adb/magisk.db", "/data/adb/magisk_simple", "/data/adb/modules", "/data/adb/su", "/data/magisk.db"};  
        for (int i = 0; i < 15; i++) {  
            if (new File(strArr[i]).exists()) {  
                return true;  
            }  
        }  
        return detectMagiskUnixDomainSocket();  
    }
    
private final boolean checkForRootManagementApps() {  
        PackageManager packageManager = this.context.getPackageManager();  
        String[] strArr = {"com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.topjohnwu.magisk", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus", "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot", "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license", "com.cyanogenmod.filemanager", "com.jrummy.busybox.installer", "com.jrummyapps.busybox.installer", "stericson.busybox", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch", "com.freedom.assist", "com.cheatengine.ceapp", "com.networksignalinfo.pro", "com.google.android.apps.authenticator2.license", "com.android.vending.billing.InAppBillingService.LOCK", "com.android.vending.billing.InAppBillingService.LUCK", "com.blackmartalpha", "org.blackmart.market", "com.kingroot.kinguser", "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global", "com.alephzain.framaroot"};  
        for (int i = 0; i < 37; i++) {  
            String str = strArr[i];  
            try {  
                packageManager.getPackageInfo(str, 0);  
                return true;  
            } catch (PackageManager.NameNotFoundException unused) {  
            } catch (Exception e) {  
                Log.w(this.TAG, "Error checking package " + str, e);  
            }  
        }  
        return false;  
    }  
  
    private final boolean checkForDangerousApps() {  
        return checkForRootManagementApps();  
    }  
  
    private final boolean checkForBusyBox() {  
        String[] strArr = {"/system/bin/busybox", "/system/xbin/busybox", "/sbin/busybox", "/data/local/bin/busybox", "/data/local/xbin/busybox", "/system/sd/xbin/busybox", "/data/busybox", "/data/adb/modules/busybox*"};  
        for (int i = 0; i < 8; i++) {  
            if (new File(strArr[i]).exists()) {  
                return true;  
            }  
        }  
        try {  
            Process exec = Runtime.getRuntime().exec(new String[]{"which", "busybox"});  
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()));  
            String readLine = bufferedReader.readLine();  
            int waitFor = exec.waitFor();  
            bufferedReader.close();  
            exec.destroy();  
            if (waitFor == 0 && readLine != null) {  
                if (readLine.length() > 0) {  
                    return true;  
                }  
            }  
        } catch (Exception e) {  
            Log.w(this.TAG, "Error executing 'which busybox'", e);  
        }  
        return false;  
    }  
  
    private final boolean checkSELinuxPermissive() {  
        String str;  
        String obj;  
        try {  
            Process exec = Runtime.getRuntime().exec("getenforce");  
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()));  
            String readLine = bufferedReader.readLine();  
            if (readLine == null || (obj = StringsKt.trim((CharSequence) readLine).toString()) == null) {  
                str = null;  
            } else {  
                str = obj.toLowerCase(Locale.ROOT);  
                Intrinsics.checkNotNullExpressionValue(str, "toLowerCase(...)");  
            }  
            bufferedReader.close();  
            exec.destroy();  
            if (str != null) {  
                return !Intrinsics.areEqual(str, "enforcing");  
            }  
            return false;  
        } catch (Exception e) {  
            Log.w(this.TAG, "Error checking SELinux status via getenforce", e);  
            return false;  
        }  
    }  
  
    private final boolean checkForEmulatorFiles() {  
        String[] strArr = {"/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace", "/system/bin/qemu-props", "/dev/socket/genymotion", "/dev/socket/genyd", "/dev/socket/genymotion_audio", "/dev/socket/andyd", "/dev/socket/andy-render", "/dev/socket/noxd", "/dev/socket/nox-bridge", "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/alarm", "/system/lib/egl/libGLES_android.so", "/system/bin/androVM-prop", "/system/bin/microvirt-prop"};  
        for (int i = 0; i < 16; i++) {  
            if (new File(strArr[i]).exists()) {  
                return true;  
            }  
        }  
        return false;  
    }  
  
    private final boolean checkEmulatorProps() {  
        String str;  
        for (Map.Entry entry : MapsKt.mapOf(TuplesKt.m207to("ro.hardware", CollectionsKt.listOf((Object[]) new String[]{"goldfish", "ranchu", "qemu", "vbox86", "android_x86", "intel", "amd"})), TuplesKt.m207to("ro.kernel.qemu", CollectionsKt.listOf("1")), TuplesKt.m207to("ro.kernel.qemu.gles", CollectionsKt.listOf("1")), TuplesKt.m207to("ro.product.model", CollectionsKt.listOf((Object[]) new String[]{"sdk", "google_sdk", "android sdk built for x86", "emulator", "genymotion", "nox", "virtualbox"})), TuplesKt.m207to("ro.product.manufacturer", CollectionsKt.listOf((Object[]) new String[]{"genymotion", EnvironmentCompat.MEDIA_UNKNOWN, "corellium", "bluestacks", "virtualbox"})), TuplesKt.m207to("ro.product.brand", CollectionsKt.listOf((Object[]) new String[]{"generic", "generic_x86", "generic_arm"})), TuplesKt.m207to("ro.board.platform", CollectionsKt.listOf((Object[]) new String[]{"android", "goldfish", "vbox86p"})), TuplesKt.m207to("ro.build.fingerprint", CollectionsKt.listOf((Object[]) new String[]{"generic", "emulator", "vbox", "test-keys"})), TuplesKt.m207to("ro.build.tags", CollectionsKt.listOf("test-keys")), TuplesKt.m207to("ro.build.characteristics", CollectionsKt.listOf("emulator"))).entrySet()) {  
            String str2 = (String) entry.getKey();  
            List list = (List) entry.getValue();  
            String systemProperty = getSystemProperty(str2);  
            if (systemProperty != null) {  
                str = systemProperty.toLowerCase(Locale.ROOT);  
                Intrinsics.checkNotNullExpressionValue(str, "toLowerCase(...)");  
            } else {  
                str = null;  
            }  
            if (str != null) {  
                Iterator it = list.iterator();  
                while (it.hasNext()) {  
                    if (StringsKt.contains$default((CharSequence) str, (CharSequence) it.next(), false, 2, (Object) null)) {  
                        return true;  
                    }  
                }  
            }  
        }  
        return false;  
    }  
  
    private final boolean checkEmulatorHardwareName() {  
        String HARDWARE = Build.HARDWARE;  
        Intrinsics.checkNotNullExpressionValue(HARDWARE, "HARDWARE");  
        String lowerCase = HARDWARE.toLowerCase(Locale.ROOT);  
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");  
        String DEVICE = Build.DEVICE;  
        Intrinsics.checkNotNullExpressionValue(DEVICE, "DEVICE");  
        String lowerCase2 = DEVICE.toLowerCase(Locale.ROOT);  
        Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");  
        String PRODUCT = Build.PRODUCT;  
        Intrinsics.checkNotNullExpressionValue(PRODUCT, "PRODUCT");  
        String lowerCase3 = PRODUCT.toLowerCase(Locale.ROOT);  
        Intrinsics.checkNotNullExpressionValue(lowerCase3, "toLowerCase(...)");  
        String MODEL = Build.MODEL;  
        Intrinsics.checkNotNullExpressionValue(MODEL, "MODEL");  
        String lowerCase4 = MODEL.toLowerCase(Locale.ROOT);  
        Intrinsics.checkNotNullExpressionValue(lowerCase4, "toLowerCase(...)");  
        String MANUFACTURER = Build.MANUFACTURER;  
        Intrinsics.checkNotNullExpressionValue(MANUFACTURER, "MANUFACTURER");  
        String lowerCase5 = MANUFACTURER.toLowerCase(Locale.ROOT);  
        Intrinsics.checkNotNullExpressionValue(lowerCase5, "toLowerCase(...)");  
        List listOf = CollectionsKt.listOf((Object[]) new String[]{"goldfish", "ranchu", "qemu", "vbox", "nox", "andy", "genymotion", "ttvm", "android_x86", "emulator", "sdk", "google_sdk", "virtual"});  
        boolean z = listOf instanceof Collection;  
        if (!z || !listOf.isEmpty()) {  
            Iterator it = listOf.iterator();  
            while (it.hasNext()) {  
                if (StringsKt.contains$default((CharSequence) lowerCase, (CharSequence) it.next(), false, 2, (Object) null)) {  
                    return true;  
                }  
            }  
        }  
        if (!z || !listOf.isEmpty()) {  
            Iterator it2 = listOf.iterator();  
            while (it2.hasNext()) {  
                if (StringsKt.contains$default((CharSequence) lowerCase2, (CharSequence) it2.next(), false, 2, (Object) null)) {  
                    return true;  
                }  
            }  
        }  
        if (!z || !listOf.isEmpty()) {  
            Iterator it3 = listOf.iterator();  
            while (it3.hasNext()) {  
                if (StringsKt.contains$default((CharSequence) lowerCase3, (CharSequence) it3.next(), false, 2, (Object) null)) {  
                    return true;  
                }  
            }  
        }  
        if (!z || !listOf.isEmpty()) {  
            Iterator it4 = listOf.iterator();  
            while (it4.hasNext()) {  
                if (StringsKt.contains$default((CharSequence) lowerCase4, (CharSequence) it4.next(), false, 2, (Object) null)) {  
                    return true;  
                }  
            }  
        }  
        if (!z || !listOf.isEmpty()) {  
            Iterator it5 = listOf.iterator();  
            while (it5.hasNext()) {  
                if (StringsKt.contains$default((CharSequence) lowerCase5, (CharSequence) it5.next(), false, 2, (Object) null) && !Intrinsics.areEqual(lowerCase5, "google")) {  
                    return true;  
                }  
            }  
        }  
        return false;  
    }  
  
    private final boolean checkQemuProps() {  
        String[] strArr = {"ro.kernel.qemu.avd_name", "ro.kernel.qemu.gles", "ro.kernel.qemu", "qemu.sf.lcd_density", "qemu.hw.mainkeys"};  
        for (int i = 0; i < 5; i++) {  
            if (getSystemProperty(strArr[i]) != null) {  
                return true;  
            }  
        }  
        return false;  
    }  
  
    private final String getSystemProperty(String propName) {  
        try {  
            Process exec = Runtime.getRuntime().exec("getprop " + propName);  
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()), 8192);  
            String readLine = bufferedReader.readLine();  
            String obj = readLine != null ? StringsKt.trim((CharSequence) readLine).toString() : null;  
            bufferedReader.close();  
            try {  
                exec.destroy();  
            } catch (Exception unused) {  
            }  
            String str = obj;  
            if (str == null) {  
                return null;  
            }  
            if (str.length() == 0) {  
                return null;  
            }  
            return obj;  
        } catch (Exception e) {  
            Log.w(this.TAG, "Error getting system property: " + propName, e);  
            return null;  
        }  
    }  
  
    private final void logDetectionResults(List<RootDetectionResult> results) {  
        Log.i(this.TAG, "--- Root/Emulator Detection Results ---");  
        boolean z = false;  
        for (RootDetectionResult rootDetectionResult : results) {  
            rootDetectionResult.isRooted();  
            if (rootDetectionResult.isRooted()) {  
                z = true;  
            }  
        }  
        Log.i(this.TAG, "Overall Status: ".concat(z ? "DEVICE FLAGGED (Rooted or Emulator)" : "Device Clear"));  
        Log.i(this.TAG, "-------------------------------------");  
    }  
}
```

That's the whole root detection class.
Notice that **all detection functions return a boolean (`true` if suspicious)**. By hooking them with Frida and **forcing `false`**, we *neutralize every single detection vector without modifying the APK statically*.

Run the *frida server* in your device and here's the frida script:
```javascript
Java.perform(() => {
    const RootDetector = Java.use("com.eightksec.geofencegamble.security.RootDetector");

    const methods = [
        "checkSuPaths",
        "checkForMagisk",
        "checkForBusyBox",
        "checkBuildTags",
        "checkDangerousProps",
        "checkSELinuxPermissive",
        "checkForHooks",
        "checkForRootManagementApps",
        "checkForDangerousApps",
        "checkForEmulatorFiles",
        "checkEmulatorProps",
        "checkEmulatorHardwareName",
        "checkQemuProps",
        "canWriteToSystemFolder",
        "checkNativeRootIndicators"
    ];

    for (const name of methods) {
        try {
            RootDetector[name].implementation = function () {
                console.log("[Bypassed] " + name);
                return false;
            };
        } catch (err) {
            console.log("[!] Error hooking: " + name);
        }
    }

    const NativeRootChecker = Java.use("com.eightksec.geofencegamble.security.NativeRootChecker");
    NativeRootChecker.checkSuExists.implementation = function () {
        console.log("[Bypassed] NativeRootChecker.checkSuExists");
        return false;
    };
    NativeRootChecker.checkProcMaps.implementation = function () {
        console.log("[Bypassed] NativeRootChecker.checkProcMaps");
        return false;
    };
});
```

Then, with the following command *we launch the application without security mechanism*.
```bash
frida -U -f com.eightksec.geofencegamble -l bypasses.js
```

### Relic Hunting
Let's focus **just in the classes that we need for solve the challenge**. Due that there are a plenty of code due some functionalities like leaderboard, Ill mentions the pieces of code that we'll use for create the *final Frida script*.

Let's start with **`LocationUtils`** class:
```java
private static final float COLLECTION_RADIUS_METERS = 50.0f;
```

```java
public final boolean isWithinCollectionRadius(GeoPoint userLocation, GeoPoint relicLocation) {
    Intrinsics.checkNotNullParameter(userLocation, "userLocation");
    Intrinsics.checkNotNullParameter(relicLocation, "relicLocation");
    return calculateDistance(
        userLocation.getLatitude(), 
        userLocation.getLongitude(), 
        relicLocation.getLatitude(), 
        relicLocation.getLongitude()
    ) <= 50.0d;
}
```
The most important part of the code, `<= 50.0d`.
Basically, **if relic is in the radius of 50 meters**, we *can collect that*.

The UI *displays “Distance:”* using:
```java
public final double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
    double radians = Math.toRadians(lat2 - lat1);
    double radians2 = Math.toRadians(lon2 - lon1);
    double d = 2;
    double d2 = radians / d;
    double d3 = radians2 / d;
    double sin = (Math.sin(d2) * Math.sin(d2)) + 
                 (Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) * Math.sin(d3) * Math.sin(d3));
    return EARTH_RADIUS_METERS * d * Math.atan2(Math.sqrt(sin), Math.sqrt(1 - sin));
}
```

```java
public final String formatDistance(double distance) {
    if (distance < 1000.0d) {
        return new StringBuilder().append((int) distance).append('m').toString();
    }
    String format = String.format("%.1fkm", Arrays.copyOf(new Object[]{Double.valueOf(distance / 1000)}, 1));
    Intrinsics.checkNotNullExpressionValue(format, "format(...)");
    return format;
}

public final GeoPoint calculateDestinationPoint(GeoPoint startPoint, double distanceMeters, double bearingDegrees) {
    Intrinsics.checkNotNullParameter(startPoint, "startPoint");
    double d = distanceMeters / EARTH_RADIUS_METERS;
    double radians = Math.toRadians(bearingDegrees);
    double radians2 = Math.toRadians(startPoint.getLatitude());
    double radians3 = Math.toRadians(startPoint.getLongitude());
    double asin = Math.asin((Math.sin(radians2) * Math.cos(d)) + (Math.cos(radians2) * Math.sin(d) * Math.cos(radians)));
    return new GeoPoint(
        Math.toDegrees(asin), 
        Math.toDegrees((((radians3 + Math.atan2((Math.sin(radians) * Math.sin(d)) * Math.cos(radians2), Math.cos(d) - (Math.sin(radians2) * Math.sin(asin)))) + 9.42477796076938d) % 6.283185307179586d) - 3.141592653589793d)
    );
}
```

*Hooking* `isWithinCollectionRadius()` to **true** and `calculateDistance()` to **0.0 disables the internal checks**. For extra protection, also patch the `android.location.Location.distanceBetween(...)` framework **to ~1 m**.

Now, **`MapScreenKt`** class. This is another crucial code that we can abuse for **get the current coordinates** (the app will randomize the relics location every time that we *start the game*).
Probably you noticed a functionality, that is, **copy the coordinates into clipboard**!

The **most important function** is:
```java
public static final void SelectedRelicCard(final CityRelic relic, final GeoPoint geoPoint, final GameViewModel viewModel, Modifier modifier, Composer composer, final int i, final int i2) {
    Intrinsics.checkNotNullParameter(relic, "relic");
    Intrinsics.checkNotNullParameter(viewModel, "viewModel");
    Composer startRestartGroup = composer.startRestartGroup(680482479);
    ComposerKt.sourceInformation(startRestartGroup, "C(SelectedRelicCard)P(2!1,3)219@8555L7,220@8613L7,226@8751L38,222@8627L2050:MapScreen.kt#f7u6gd");
    Modifier modifier2 = (i2 & 8) != 0 ? Modifier.INSTANCE : modifier;
    if (ComposerKt.isTraceInProgress()) {
        ComposerKt.traceEventStart(680482479, i, -1, "com.eightksec.geofencegamble.ui.screens.SelectedRelicCard (MapScreen.kt:218)");
    }
    ProvidableCompositionLocal < Context > localContext = AndroidCompositionLocals_androidKt.getLocalContext();
    ComposerKt.sourceInformationMarkerStart(startRestartGroup, 2023513938, "CC:CompositionLocal.kt#9igjgp");
    Object consume = startRestartGroup.consume(localContext);
    ComposerKt.sourceInformationMarkerEnd(startRestartGroup);
    final Context context = (Context) consume;
    ProvidableCompositionLocal < ClipboardManager > localClipboardManager = CompositionLocalsKt.getLocalClipboardManager();
    ComposerKt.sourceInformationMarkerStart(startRestartGroup, 2023513938, "CC:CompositionLocal.kt#9igjgp");
    Object consume2 = startRestartGroup.consume(localClipboardManager);
    ComposerKt.sourceInformationMarkerEnd(startRestartGroup);
    final ClipboardManager clipboardManager = (ClipboardManager) consume2;
    CardKt.Card(PaddingKt.m807padding3ABfNKs(SizeKt.fillMaxWidth$default(modifier2, 0.0 f, 1, null), C0735Dp.m5978constructorimpl(16)), null, null, CardDefaults.INSTANCE.m1533cardElevationaqJV_2Y(C0735Dp.m5978constructorimpl(8), 0.0 f, 0.0 f, 0.0 f, 0.0 f, 0.0 f, startRestartGroup, (CardDefaults.$stable << 18) | 6, 62), null, ComposableLambdaKt.composableLambda(startRestartGroup, -110752899, true, new Function3 < ColumnScope, Composer, Integer, Unit > () {
        {
            super(3);
        }

        @Override
        public Unit invoke(ColumnScope columnScope, Composer composer2, Integer num) {
            invoke(columnScope, composer2, num.intValue());
            return Unit.INSTANCE;
        }

        public final void invoke(ColumnScope Card, Composer composer2, int i3) {
            CityRelic cityRelic;
            int i4;
            Intrinsics.checkNotNullParameter(Card, "$this$Card");
            ComposerKt.sourceInformation(composer2, "C228@8806L1865:MapScreen.kt#f7u6gd");
            if ((i3 & 81) != 16 || !composer2.getSkipping()) {
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventStart(-110752899, i3, -1, "com.eightksec.geofencegamble.ui.screens.SelectedRelicCard.<anonymous> (MapScreen.kt:228)");
                }
                Modifier m807padding3ABfNKs = PaddingKt.m807padding3ABfNKs(Modifier.INSTANCE, C0735Dp.m5978constructorimpl(16));
                final CityRelic cityRelic2 = CityRelic.this;
                GeoPoint geoPoint2 = geoPoint;
                final GameViewModel gameViewModel = viewModel;
                final ClipboardManager clipboardManager2 = clipboardManager;
                final Context context2 = context;
                composer2.startReplaceableGroup(-483455358);
                ComposerKt.sourceInformation(composer2, "CC(Column)P(2,3,1)77@3865L61,78@3931L133:Column.kt#2w3rfo");
                MeasurePolicy columnMeasurePolicy = ColumnKt.columnMeasurePolicy(Arrangement.INSTANCE.getTop(), Alignment.INSTANCE.getStart(), composer2, 0);
                composer2.startReplaceableGroup(-1323940314);
                ComposerKt.sourceInformation(composer2, "CC(Layout)P(!1,2)78@3182L23,80@3272L420:Layout.kt#80mrfh");
                int currentCompositeKeyHash = ComposablesKt.getCurrentCompositeKeyHash(composer2, 0);
                CompositionLocalMap currentCompositionLocalMap = composer2.getCurrentCompositionLocalMap();
                Function0 < ComposeUiNode > constructor = ComposeUiNode.INSTANCE.getConstructor();
                Function3 < SkippableUpdater < ComposeUiNode > , Composer, Integer, Unit > modifierMaterializerOf = LayoutKt.modifierMaterializerOf(m807padding3ABfNKs);
                if (!(composer2.getApplier() instanceof Applier)) {
                    ComposablesKt.invalidApplier();
                }
                composer2.startReusableNode();
                if (composer2.getInserting()) {
                    composer2.createNode(constructor);
                } else {
                    composer2.useNode();
                }
                Composer m3181constructorimpl = Updater.m3181constructorimpl(composer2);
                Updater.m3188setimpl(m3181constructorimpl, columnMeasurePolicy, ComposeUiNode.INSTANCE.getSetMeasurePolicy());
                Updater.m3188setimpl(m3181constructorimpl, currentCompositionLocalMap, ComposeUiNode.INSTANCE.getSetResolvedCompositionLocals());
                Function2 < ComposeUiNode, Integer, Unit > setCompositeKeyHash = ComposeUiNode.INSTANCE.getSetCompositeKeyHash();
                if (m3181constructorimpl.getInserting() || !Intrinsics.areEqual(m3181constructorimpl.rememberedValue(), Integer.valueOf(currentCompositeKeyHash))) {
                    m3181constructorimpl.updateRememberedValue(Integer.valueOf(currentCompositeKeyHash));
                    m3181constructorimpl.apply(Integer.valueOf(currentCompositeKeyHash), setCompositeKeyHash);
                }
                modifierMaterializerOf.invoke(SkippableUpdater.m3172boximpl(SkippableUpdater.m3173constructorimpl(composer2)), composer2, 0);
                composer2.startReplaceableGroup(2058660585);
                ComposerKt.sourceInformationMarkerStart(composer2, 276693656, "C79@3979L9:Column.kt#2w3rfo");
                ColumnScopeInstance columnScopeInstance = ColumnScopeInstance.INSTANCE;
                ComposerKt.sourceInformationMarkerStart(composer2, -2101581030, "C229@8914L10,229@8863L73,230@9010L10,230@8949L83,233@9115L886,255@10328L41,257@10383L278:MapScreen.kt#f7u6gd");
                TextKt.m2369Text4IGK_g(cityRelic2.getRelicName(), (Modifier) null, 0 L, 0 L, (FontStyle) null, (FontWeight) null, (FontFamily) null, 0 L, (TextDecoration) null, (TextAlign) null, 0 L, 0, false, 0, 0, (Function1 <? super TextLayoutResult, Unit > ) null, MaterialTheme.INSTANCE.getTypography(composer2, MaterialTheme.$stable).getTitleLarge(), composer2, 0, 0, 65534);
                TextKt.m2369Text4IGK_g("Rarity: " + cityRelic2.getRarity(), (Modifier) null, 0 L, 0 L, (FontStyle) null, (FontWeight) null, (FontFamily) null, 0 L, (TextDecoration) null, (TextAlign) null, 0 L, 0, false, 0, 0, (Function1 <? super TextLayoutResult, Unit > ) null, MaterialTheme.INSTANCE.getTypography(composer2, MaterialTheme.$stable).getBodyMedium(), composer2, 0, 0, 65534);
                Alignment.Vertical centerVertically = Alignment.INSTANCE.getCenterVertically();
                composer2.startReplaceableGroup(693286680);
                ComposerKt.sourceInformation(composer2, "CC(Row)P(2,1,3)90@4553L58,91@4616L130:Row.kt#2w3rfo");
                Modifier.Companion companion = Modifier.INSTANCE;
                MeasurePolicy rowMeasurePolicy = RowKt.rowMeasurePolicy(Arrangement.INSTANCE.getStart(), centerVertically, composer2, 48);
                composer2.startReplaceableGroup(-1323940314);
                ComposerKt.sourceInformation(composer2, "CC(Layout)P(!1,2)78@3182L23,80@3272L420:Layout.kt#80mrfh");
                int currentCompositeKeyHash2 = ComposablesKt.getCurrentCompositeKeyHash(composer2, 0);
                CompositionLocalMap currentCompositionLocalMap2 = composer2.getCurrentCompositionLocalMap();
                Function0 < ComposeUiNode > constructor2 = ComposeUiNode.INSTANCE.getConstructor();
                Function3 < SkippableUpdater < ComposeUiNode > , Composer, Integer, Unit > modifierMaterializerOf2 = LayoutKt.modifierMaterializerOf(companion);
                if (!(composer2.getApplier() instanceof Applier)) {
                    ComposablesKt.invalidApplier();
                }
                composer2.startReusableNode();
                if (composer2.getInserting()) {
                    composer2.createNode(constructor2);
                } else {
                    composer2.useNode();
                }
                Composer m3181constructorimpl2 = Updater.m3181constructorimpl(composer2);
                Updater.m3188setimpl(m3181constructorimpl2, rowMeasurePolicy, ComposeUiNode.INSTANCE.getSetMeasurePolicy());
                Updater.m3188setimpl(m3181constructorimpl2, currentCompositionLocalMap2, ComposeUiNode.INSTANCE.getSetResolvedCompositionLocals());
                Function2 < ComposeUiNode, Integer, Unit > setCompositeKeyHash2 = ComposeUiNode.INSTANCE.getSetCompositeKeyHash();
                if (m3181constructorimpl2.getInserting() || !Intrinsics.areEqual(m3181constructorimpl2.rememberedValue(), Integer.valueOf(currentCompositeKeyHash2))) {
                    m3181constructorimpl2.updateRememberedValue(Integer.valueOf(currentCompositeKeyHash2));
                    m3181constructorimpl2.apply(Integer.valueOf(currentCompositeKeyHash2), setCompositeKeyHash2);
                }
                modifierMaterializerOf2.invoke(SkippableUpdater.m3172boximpl(SkippableUpdater.m3173constructorimpl(composer2)), composer2, 0);
                composer2.startReplaceableGroup(2058660585);
                ComposerKt.sourceInformationMarkerStart(composer2, -326681643, "C92@4661L9:Row.kt#2w3rfo");
                RowScopeInstance rowScopeInstance = RowScopeInstance.INSTANCE;
                ComposerKt.sourceInformationMarkerStart(composer2, 1954254333, "C236@9357L10,234@9185L301,239@9503L39,240@9559L428:MapScreen.kt#f7u6gd");
                StringBuilder sb = new StringBuilder("Location: ");
                StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
                String format = String.format("%.6f", Arrays.copyOf(new Object[] {
                    Double.valueOf(cityRelic2.getLatitude())
                }, 1));
                Intrinsics.checkNotNullExpressionValue(format, "format(...)");
                StringBuilder append = sb.append(format).append(", ");
                StringCompanionObject stringCompanionObject2 = StringCompanionObject.INSTANCE;
                String format2 = String.format("%.6f", Arrays.copyOf(new Object[] {
                    Double.valueOf(cityRelic2.getLongitude())
                }, 1));
                Intrinsics.checkNotNullExpressionValue(format2, "format(...)");
                TextKt.m2369Text4IGK_g(append.append(format2).toString(), RowScope.weight$default(rowScopeInstance, Modifier.INSTANCE, 1.0 f, false, 2, null), 0 L, 0 L, (FontStyle) null, (FontWeight) null, (FontFamily) null, 0 L, (TextDecoration) null, (TextAlign) null, 0 L, 0, false, 0, 0, (Function1 <? super TextLayoutResult, Unit > ) null, MaterialTheme.INSTANCE.getTypography(composer2, MaterialTheme.$stable).getBodyMedium(), composer2, 0, 0, 65532);
                Composer composer3 = composer2;
                SpacerKt.Spacer(SizeKt.m861width3ABfNKs(Modifier.INSTANCE, C0735Dp.m5978constructorimpl(8)), composer3, 6);
                IconButtonKt.IconButton(new Function0 < Unit > () {
                    {
                        super(0);
                    }

                    @Override
                    public Unit invoke() {
                        invoke2();
                        return Unit.INSTANCE;
                    }

                    public final void invoke2() {
                        clipboardManager2.setText(new AnnotatedString(CityRelic.this.getLatitude() + ", " + CityRelic.this.getLongitude(), null, null, 6, null));
                        ToastHelper.showInfo$default(ToastHelper.INSTANCE, context2, "Coordinates copied!", 0, 4, null);
                    }
                }, null, false, null, null, ComposableSingletons$MapScreenKt.INSTANCE.m6269getLambda2$app_release(), composer3, ProfileVerifier.CompilationStatus.f239xf2722a21, 30);
                ComposerKt.sourceInformationMarkerEnd(composer3);
                ComposerKt.sourceInformationMarkerEnd(composer3);
                composer3.endReplaceableGroup();
                composer3.endNode();
                composer3.endReplaceableGroup();
                composer3.endReplaceableGroup();
                composer3.startReplaceableGroup(-2101579849);
                ComposerKt.sourceInformation(composer3, "*252@10278L10,252@10189L111");
                if (geoPoint2 == null) {
                    i4 = 6;
                    cityRelic = cityRelic2;
                } else {
                    cityRelic = cityRelic2;
                    i4 = 6;
                    TextKt.m2369Text4IGK_g("Distance: " + LocationUtils.INSTANCE.formatDistance(LocationUtils.INSTANCE.calculateDistance(geoPoint2.getLatitude(), geoPoint2.getLongitude(), cityRelic2.getLatitude(), cityRelic2.getLongitude())), (Modifier) null, 0 L, 0 L, (FontStyle) null, (FontWeight) null, (FontFamily) null, 0 L, (TextDecoration) null, (TextAlign) null, 0 L, 0, false, 0, 0, (Function1 <? super TextLayoutResult, Unit > ) null, MaterialTheme.INSTANCE.getTypography(composer3, MaterialTheme.$stable).getBodyMedium(), composer2, 0, 0, 65534);
                    composer3 = composer2;
                    Unit unit = Unit.INSTANCE;
                    Unit unit2 = Unit.INSTANCE;
                }
                composer3.endReplaceableGroup();
                SpacerKt.Spacer(SizeKt.m842height3ABfNKs(Modifier.INSTANCE, C0735Dp.m5978constructorimpl(12)), composer3, i4);
                ButtonKt.Button(new Function0 < Unit > () { {
                        super(0);
                    }

                    @Override
                    public Unit invoke() {
                        invoke2();
                        return Unit.INSTANCE;
                    }

                    public final void invoke2() {
                        GameViewModel.this.collectSelectedRelic();
                    }
                }, columnScopeInstance.align(Modifier.INSTANCE, Alignment.INSTANCE.getEnd()), !cityRelic.isCollected() && gameViewModel.getGameState().getValue().getGameStarted(), null, null, null, null, null, null, ComposableSingletons$MapScreenKt.INSTANCE.m6270getLambda3$app_release(), composer2, 805306368, TypedValues.PositionType.TYPE_PERCENT_HEIGHT);
                ComposerKt.sourceInformationMarkerEnd(composer2);
                ComposerKt.sourceInformationMarkerEnd(composer2);
                composer2.endReplaceableGroup();
                composer2.endNode();
                composer2.endReplaceableGroup();
                composer2.endReplaceableGroup();
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventEnd();
                    return;
                }
                return;
            }
            composer2.skipToGroupEnd();
        }
    }), startRestartGroup, ProfileVerifier.CompilationStatus.f239xf2722a21, 22);
    if (ComposerKt.isTraceInProgress()) {
        ComposerKt.traceEventEnd();
    }
    ScopeUpdateScope endRestartGroup = startRestartGroup.endRestartGroup();
    if (endRestartGroup != null) {
        final Modifier modifier3 = modifier2;
        endRestartGroup.updateScope(new Function2 < Composer, Integer, Unit > () { {
                super(2);
            }

            @Override
            public Unit invoke(Composer composer2, Integer num) {
                invoke(composer2, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(Composer composer2, int i3) {
                MapScreenKt.SelectedRelicCard(CityRelic.this, geoPoint, viewModel, modifier3, composer2, RecomposeScopeImplKt.updateChangedFlags(i | 1), i2);
            }
        });
    }
}
```

Yes, is a large function. And we need pay attention to this part:
```java
public final void invoke2() {
    clipboardManager2.setText(new AnnotatedString(
        CityRelic.this.getLatitude() + ", " + CityRelic.this.getLongitude(), 
        null, 
        null, 
        6, 
        null
    ));
    ToastHelper.showInfo$default(
        ToastHelper.INSTANCE, 
        context2, 
        "Coordinates copied!", 
        0, 
        4, 
        null
    );
}
```
The most important, is that the “Copy” button puts “**lat, lon**” on the **clipboard**.
And the *distance shown on the card: also goes through `LocationUtils`*.

By **intercepting the copy we can read those coordinates and use them to “move” our location to the relic**.

And finally, the **`LocationService`** class!
The *key function* is `startLocationUpdates` in this service:
```java
public final void startLocationUpdates(final Function2<? super GeoPoint, ? super Boolean, Unit> onLocationUpdate) {
    Intrinsics.checkNotNullParameter(onLocationUpdate, "onLocationUpdate");
    stopLocationUpdates();
    this.locationListener = new LocationListener() { // from class: com.eightksec.geofencegamble.service.LocationService$startLocationUpdates$1
        @Override // android.location.LocationListener
        public void onProviderDisabled(String provider) {
            Intrinsics.checkNotNullParameter(provider, "provider");
        }

        @Override // android.location.LocationListener
        public void onProviderEnabled(String provider) {
            Intrinsics.checkNotNullParameter(provider, "provider");
        }

        @Override // android.location.LocationListener
        public void onStatusChanged(String provider, int status, Bundle extras) {
        }

        @Override // android.location.LocationListener
        public void onLocationChanged(Location location) {
            boolean isFromMockProvider;
            Intrinsics.checkNotNullParameter(location, "location");
            if (Build.VERSION.SDK_INT >= 31) {
                isFromMockProvider = location.isMock();
            } else {
                isFromMockProvider = location.isFromMockProvider();
            }
            onLocationUpdate.invoke(new GeoPoint(location.getLatitude(), location.getLongitude()), Boolean.valueOf(isFromMockProvider));
        }
    };
    try {
        if (this.locationManager.isProviderEnabled("gps")) {
            LocationManager locationManager = this.locationManager;
            LocationListener locationListener = this.locationListener;
            Intrinsics.checkNotNull(locationListener);
            locationManager.requestLocationUpdates("gps", 5000L, 10.0f, locationListener);
            return;
        }
        Log.w(this.TAG, "GPS provider is not enabled. Cannot request updates.");
    } catch (SecurityException e) {
        Log.e(this.TAG, "SecurityException requesting location updates", e);
    } catch (Exception e2) {
        Log.e(this.TAG, "Exception requesting location updates", e2);
    }
}
```

Internally it **registers a `LocationListener`** and, in `onLocationChanged`, calls:
```java
@Override // android.location.LocationListener
public void onLocationChanged(Location location) {
    boolean isFromMockProvider;
    Intrinsics.checkNotNullParameter(location, "location");
    if (Build.VERSION.SDK_INT >= 31) {
        isFromMockProvider = location.isMock();
    } else {
        isFromMockProvider = location.isFromMockProvider();
    }
    onLocationUpdate.invoke(new GeoPoint(location.getLatitude(), location.getLongitude()), Boolean.valueOf(isFromMockProvider));
}
```
The `GameViewModel` subscribes to its callback; the map (`MapScreen`) **collects the `currentLocation` and updates the overlays**.

If we **capture that `Function2` in `startLocationUpdates(...)`, we can call it ourselves with a fake GeoPoint**  (without marking mock).

### Final Script
So, I put **all the bypasses and hooks in one script**, including the protection bypasses we worked on in the beginning.

```javascript
Java.perform(() => {
    // root
    const RootDetector = Java.use("com.eightksec.geofencegamble.security.RootDetector");
    const rootMethods = [
        "checkSuPaths",
        "checkForMagisk",
        "checkForBusyBox",
        "checkBuildTags",
        "checkDangerousProps",
        "checkSELinuxPermissive",
        "checkForHooks",
        "checkForRootManagementApps",
        "checkForDangerousApps",
        "checkForEmulatorFiles",
        "checkEmulatorProps",
        "checkEmulatorHardwareName",
        "checkQemuProps",
        "canWriteToSystemFolder",
        "checkNativeRootIndicators"
    ];
    for (const name of rootMethods) {
        try {
            RootDetector[name].implementation = function () {
                console.log("[Bypassed] " + name);
                return false;
            };
        } catch (err) {
            console.log("! Error hooking: " + name + " -> " + err);
        }
    }

    const NativeRootChecker = Java.use("com.eightksec.geofencegamble.security.NativeRootChecker");
    try {
        NativeRootChecker.checkSuExists.implementation = function () {
            console.log("[Bypassed] NativeRootChecker.checkSuExists");
            return false;
        };
        NativeRootChecker.checkProcMaps.implementation = function () {
            console.log("[Bypassed] NativeRootChecker.checkProcMaps");
            return false;
        };
    } catch (e) {
        console.log("! Error hooking NativeRootChecker: " + e);
    }

	// distance bypass
    try {
        const LocationUtils = Java.use("com.eightksec.geofencegamble.utils.LocationUtils");
        // isWithinCollectionRadius >> always true
        LocationUtils.isWithinCollectionRadius.implementation = function (userLocation, relicLocation) {
            if (relicLocation) {
                console.log(`[Bypassed] isWithinCollectionRadius -> true (relic @ ${relicLocation.getLatitude()}, ${relicLocation.getLongitude()})`);
            } else {
                console.log(`[Bypassed] isWithinCollectionRadius -> true`);
            }
            return true;
        };
        // calculateDistance always 0.0
        LocationUtils.calculateDistance.implementation = function (lat1, lon1, lat2, lon2) {
            console.log(`[Bypassed] calculateDistance ${lat1},${lon1} -> ${lat2},${lon2} = 0m`);
            return 0.0;
        };
    } catch (e) {
        console.log("! Error hooking LocationUtils: " + e);
    }

    // patch android.location.Location.distanceBetween
    try {
        const ALocation = Java.use("android.location.Location");
        ALocation.distanceBetween.overload('double','double','double','double','[F').implementation =
            function (lat1, lon1, lat2, lon2, results) {
                // 1m for every pointss
                try { results[0] = 1.0; } catch (_) {}
                try { results[1] = 0.0; } catch (_) {} // initial bearing
                try { results[2] = 0.0; } catch (_) {} // final bearing
                console.log(`[Bypassed] Location.distanceBetween(${lat1},${lon1} -> ${lat2},${lon2}) = 1m`);
                return; // void
            };
    } catch (e) {
        console.log("! Error hooking Location.distanceBetween: " + e);
    }

	// get callback onLocationUpdate
	// intercept setText and push false update
    const GeoPoint = Java.use('org.osmdroid.util.GeoPoint');
    const JBoolean = Java.use('java.lang.Boolean');

    let onLocationUpdateCb = null;
    try {
        const LocationService = Java.use('com.eightksec.geofencegamble.service.LocationService');
        // startLocationUpdates - Function2
        LocationService.startLocationUpdates.overload('kotlin.jvm.functions.Function2').implementation = function (cb) {
            console.log('[Hook] Captured onLocationUpdate callback');
            onLocationUpdateCb = cb;
            // call original function
            return this.startLocationUpdates(cb);
        };
    } catch (e) {
        console.log("! Error hooking LocationService.startLocationUpdates: " + e);
    }

    try {
        // clipboard
        const AndroidClipboardManager = Java.use('androidx.compose.ui.platform.AndroidClipboardManager');
        const AnnotatedString = Java.use('androidx.compose.ui.text.AnnotatedString');

        AndroidClipboardManager.setText.overload('androidx.compose.ui.text.AnnotatedString').implementation = function (annotStr) {

            const ret = this.setText(annotStr);

            try {
                // get text
                const raw = annotStr.toString(); // plain text
                const m = raw.match(/(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/);
                if (m) {
                    const lat = parseFloat(m[1]);
                    const lon = parseFloat(m[2]);
                    console.log(`Parsed coords from clipboard: ${lat}, ${lon}`);
                    if (onLocationUpdateCb) {
                        const gp = GeoPoint.$new(lat, lon);
                        // false (avoid mock)
                        const isMock = JBoolean.valueOf(false);
                        // Function2
                        try {
                            onLocationUpdateCb.invoke(gp, isMock);
                            console.log('Fired fake onLocationUpdate() -> player moved to relic');
                        } catch (invErr) {
                            try {
                                // explicits overloads
                                onLocationUpdateCb['invoke'].overload('java.lang.Object','java.lang.Object').call(onLocationUpdateCb, gp, isMock);
                                console.log('Fired fake onLocationUpdate() via overload');
                            } catch (invErr2) {
                                console.log('! invoke() failed: ' + invErr + ' / ' + invErr2);
                            }
                        }
                    } else {
                        console.log('! onLocationUpdate callback not captured yet');
                    }
                }
            } catch (err) {
                console.log('! Teleport parsing error: ' + err);
            }

            return ret;
        };
    } catch (e) {
        console.log("! Error hooking AndroidClipboardManager.setText: " + e);
    }

    console.log('All ready :)');
});
```

In short:
- **`RootDetector.*`** → `return false`.

- **`NativeRootChecker.checkSuExists / checkProcMaps`** → `return false`.

- **`LocationUtils.isWithinCollectionRadius`** → `return true`.

- **`LocationUtils.calculateDistance`** → `return 0.0`.

- **`android.location.Location.distanceBetween(double,double,double,double,float[])`** → write `results[0]=1.0`.

- **Capture `Function2` in `LocationService.startLocationUpdates(cb)`** → save `cb`.

- **Intercept `AndroidClipboardManager.setText(AnnotatedString)`** → parse `"lat, lon"` and do `cb.invoke(new GeoPoint(lat,lon), false)`.


I hope you found it useful (:
