**Description**: BadPreference looks like a clean, production-ready app until you flip the right switch. Somewhere in the app’s internal preferences lies a hidden mode that unlocks a secret flag, but it won’t reveal itself through the UI or static strings alone.

**Link**: https://academy.8ksec.io/course/ios-application-exploitation-challenges

![[8ksec-badPreferences1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Recon
Inside of `Payload/BadPreference.app` you can find the `BadPreference.debug.dylib` file library. **Import** into **Ghidra** and let's **analyze that**!

Immediately, I went to **Exports** in the **Symbol Tree** and I noticed the **`checkForDebugMode`** function. So, let's take a look!

Here's the *pseudo-code*
```C
void BadPreference::ContentView::checkForDebugMode(ContentView param_1)

{
  [...]
  VARIABLES
  [...]
  
  local_70 = (char *)0x0;
  local_68 = (void *)0x0;
  local_88 = (String)ZEXT816(0);
  local_98 = (char *)0x0;
  local_90 = (void *)0x0;
  tVar10 = Swift::$_allocateUninitializedArray(0x11);
  pSVar8 = (String *)tVar10.1;
  SVar11 = Swift::String::init("c",1,1);
  *pSVar8 = SVar11;
  SVar11 = Swift::String::init("o",1,1);
  pSVar8[1] = SVar11;
  SVar11 = Swift::String::init("m",1,1);
  pSVar8[2] = SVar11;
  SVar11 = Swift::String::init(".",1,1);
  pSVar8[3] = SVar11;
  SVar11 = Swift::String::init("a",1,1);
  pSVar8[4] = SVar11;
  SVar11 = Swift::String::init("p",1,1);
  pSVar8[5] = SVar11;
  SVar11 = Swift::String::init("p",1,1);
  pSVar8[6] = SVar11;
  SVar11 = Swift::String::init(".",1,1);
  pSVar8[7] = SVar11;
  SVar11 = Swift::String::init("d",1,1);
  pSVar8[8] = SVar11;
  SVar11 = Swift::String::init("e",1,1);
  pSVar8[9] = SVar11;
  SVar11 = Swift::String::init("b",1,1);
  pSVar8[10] = SVar11;
  SVar11 = Swift::String::init("u",1,1);
  pSVar8[0xb] = SVar11;
  SVar11 = Swift::String::init("g",1,1);
  pSVar8[0xc] = SVar11;
  SVar11 = Swift::String::init("M",1,1);
  pSVar8[0xd] = SVar11;
  SVar11 = Swift::String::init("o",1,1);
  pSVar8[0xe] = SVar11;
  SVar11 = Swift::String::init("d",1,1);
  pSVar8[0xf] = SVar11;
  SVar11 = Swift::String::init("e",1,1);
  pSVar8[0x10] = SVar11;
  AVar2 = Swift::$_finalizeUninitializedArray(tVar10.0);
  local_60 = CONCAT44(extraout_var,AVar2);
  pcVar3 = &$$demangling_cache_variable_for_type_metadata_for_[Swift.String];
  ___swift_instantiateConcreteTypeFromMangledName();
  pcVar4 = pcVar3;
  Swift::Array<String>::$lazy_protocol_witness_table_accessor();
  SVar11.bridgeObject = pcVar4;
  SVar11.str = pcVar3;
  SVar11 = (extension_Swift)::Swift::BidirectionalCollection::$joined(SVar11);
  SVar12 = (extension_Swift)::Swift::BidirectionalCollection::$joined(SVar11);
  _swift_bridgeObjectRelease(SVar11.bridgeObject);
  $$outlined_destroy_of_[Swift.String](&local_60);
  local_110 = SVar12.bridgeObject;
  local_118 = SVar12.str;
  local_70 = local_118;
  local_68 = local_110;
  tVar10 = Swift::$_allocateUninitializedArray(4);
  pCVar9 = (Character *)tVar10.1;
  CVar13 = Swift::Character::init("t",1,1);
  *pCVar9 = CVar13;
  CVar13 = Swift::Character::init("r",1,1);
  pCVar9[1] = CVar13;
  CVar13 = Swift::Character::init("u",1,1);
  pCVar9[2] = CVar13;
  CVar13 = Swift::Character::init("e",1,1);
  pCVar9[3] = CVar13;
  AVar2 = Swift::$_finalizeUninitializedArray(tVar10.0);
  local_78 = CONCAT44(extraout_var_00,AVar2);
  ___swift_instantiateConcreteTypeFromMangledName();
  Swift::Array<Character>::$lazy_protocol_witness_table_accessor();
  SVar11 = Swift::String::$init((char)&local_78);
  puVar5 = &_OBJC_CLASS_$_NSUserDefaults;
  local_88 = SVar11;
  _objc_opt_self();
  _objc_msgSend();
  _objc_retainAutoreleasedReturnValue();
  _swift_bridgeObjectRetain(local_110);
  pNVar6 = (extension_Foundation)::Swift::String::_bridgeToObjectiveC();
  _swift_bridgeObjectRelease(local_110);
  puVar7 = puVar5;
  _objc_msgSend(puVar5,"stringForKey:",pNVar6);
  _objc_retainAutoreleasedReturnValue();
  (*(code *)PTR__objc_release_00010048)(pNVar6);
  (*(code *)PTR__objc_release_00010048)(puVar5);
  if (puVar7 == (undefined *)0x0) {
    local_1f0 = (char *)0x0;
    local_1e8 = (void *)0x0;
  }
  else {
    SVar12 = (extension_Foundation)::Swift::String::$_unconditionallyBridgeFromObjectiveC();
    (*(code *)PTR__objc_release_00010048)(puVar7);
    local_200 = SVar12.str;
    local_1f8 = SVar12.bridgeObject;
    local_1f0 = local_200;
    local_1e8 = local_1f8;
  }
  if (local_1e8 != (void *)0x0) {
    SVar12.bridgeObject = local_1e8;
    SVar12.str = local_1f0;
    local_98 = local_1f0;
    local_90 = local_1e8;
    SVar14.bridgeObject = in_x5;
    SVar14.str = in_x4;
    bVar1 = Swift::String::==_infix(SVar12,SVar11,SVar14);
    if (bVar1) {
      uStack_28 = unaff_x20[1];
      local_30 = (undefined *)*unaff_x20;
      $$outlined_retain_of_SwiftUI.State<Swift.Bool>();
      $$outlined_retain_of_SwiftUI.State<Swift.Bool>(&local_30);
      uStack_a8 = uStack_28;
      local_b0.unknown = local_30;
      local_b1 = 1;
      ___swift_instantiateConcreteTypeFromMangledName
                (&$$demangling_cache_variable_for_type_metadata_for_SwiftUI.State<Swift.Bool>);
      SwiftUI::State::set_wrappedValue(&local_b0,(char)&local_b1);
      $$outlined_destroy_of_SwiftUI.State<Swift.Bool>(&local_b0);
      $$outlined_release_of_SwiftUI.State<Swift.Bool>(&local_30);
      tVar10 = Swift::$_allocateUninitializedArray(0x16);
      pCVar9 = (Character *)tVar10.1;
      CVar13 = Swift::Character::init("C",1,1);
      *pCVar9 = CVar13;
      CVar13 = Swift::Character::init("T",1,1);
      pCVar9[1] = CVar13;
      CVar13 = Swift::Character::init("F",1,1);
      pCVar9[2] = CVar13;
      CVar13 = Swift::Character::init("{",1,1);
      pCVar9[3] = CVar13;
      CVar13 = Swift::Character::init("t",1,1);
      pCVar9[4] = CVar13;
      CVar13 = Swift::Character::init("h",1,1);
      pCVar9[5] = CVar13;
      CVar13 = Swift::Character::init("e",1,1);
      pCVar9[6] = CVar13;
      CVar13 = Swift::Character::init("_",1,1);
      pCVar9[7] = CVar13;
      CVar13 = Swift::Character::init("p",1,1);
      pCVar9[8] = CVar13;
      CVar13 = Swift::Character::init("r",1,1);
      pCVar9[9] = CVar13;
      CVar13 = Swift::Character::init("e",1,1);
      pCVar9[10] = CVar13;
      CVar13 = Swift::Character::init("f",1,1);
      pCVar9[0xb] = CVar13;
      CVar13 = Swift::Character::init("s",1,1);
      pCVar9[0xc] = CVar13;
      CVar13 = Swift::Character::init("_",1,1);
      pCVar9[0xd] = CVar13;
      CVar13 = Swift::Character::init("a",1,1);
      pCVar9[0xe] = CVar13;
      CVar13 = Swift::Character::init("r",1,1);
      pCVar9[0xf] = CVar13;
      CVar13 = Swift::Character::init("e",1,1);
      pCVar9[0x10] = CVar13;
      CVar13 = Swift::Character::init("_",1,1);
      pCVar9[0x11] = CVar13;
      CVar13 = Swift::Character::init("b",1,1);
      pCVar9[0x12] = CVar13;
      CVar13 = Swift::Character::init("a",1,1);
      pCVar9[0x13] = CVar13;
      CVar13 = Swift::Character::init("d",1,1);
      pCVar9[0x14] = CVar13;
      CVar13 = Swift::Character::init("}",1,1);
      pCVar9[0x15] = CVar13;
      AVar2 = Swift::$_finalizeUninitializedArray(tVar10.0);
      local_c0 = CONCAT44(extraout_var_01,AVar2);
      SVar12 = Swift::String::$init((char)&stack0xfffffffffffffff0 + 'P');
      uStack_48 = unaff_x20[3];
      local_50 = (undefined *)unaff_x20[2];
      local_40 = unaff_x20[4];
      $$outlined_retain_of_SwiftUI.State<>();
      $$outlined_retain_of_SwiftUI.State<>(&local_50);
      uStack_d8 = uStack_48;
      local_e0.unknown = local_50;
      local_d0 = local_40;
      _swift_bridgeObjectRetain(SVar12.bridgeObject);
      local_f0 = SVar12;
      ___swift_instantiateConcreteTypeFromMangledName
                (&$$demangling_cache_variable_for_type_metadata_for_SwiftUI.State<Swift.String>);
      SwiftUI::State::set_wrappedValue(&local_e0,(char)&local_f0);
      $$outlined_destroy_of_SwiftUI.State<>(&local_e0);
      $$outlined_release_of_SwiftUI.State<>(&local_50);
      _swift_bridgeObjectRelease(SVar12.bridgeObject);
      _swift_bridgeObjectRelease(local_1e8);
    }
    else {
      _swift_bridgeObjectRelease(local_1e8);
    }
  }
  local_120 = SVar11.bridgeObject;
  _swift_bridgeObjectRelease(local_120);
  _swift_bridgeObjectRelease(local_110);
  return;
}
```

We can easily read the flag, **but it is not allowed as a solution for the challenge**.

So, let's explain this code.

As you can read easily the flag, you can notice another **array**:
```C
  tVar10 = Swift::$_allocateUninitializedArray(0x11);
  pSVar8 = (String *)tVar10.1;
  SVar11 = Swift::String::init("c",1,1);
  *pSVar8 = SVar11;
  SVar11 = Swift::String::init("o",1,1);
  pSVar8[1] = SVar11;
  SVar11 = Swift::String::init("m",1,1);
  pSVar8[2] = SVar11;
  SVar11 = Swift::String::init(".",1,1);
  pSVar8[3] = SVar11;
  SVar11 = Swift::String::init("a",1,1);
  pSVar8[4] = SVar11;
  SVar11 = Swift::String::init("p",1,1);
  pSVar8[5] = SVar11;
  SVar11 = Swift::String::init("p",1,1);
  pSVar8[6] = SVar11;
  SVar11 = Swift::String::init(".",1,1);
  pSVar8[7] = SVar11;
  SVar11 = Swift::String::init("d",1,1);
  pSVar8[8] = SVar11;
  SVar11 = Swift::String::init("e",1,1);
  pSVar8[9] = SVar11;
  SVar11 = Swift::String::init("b",1,1);
  pSVar8[10] = SVar11;
  SVar11 = Swift::String::init("u",1,1);
  pSVar8[0xb] = SVar11;
  SVar11 = Swift::String::init("g",1,1);
  pSVar8[0xc] = SVar11;
  SVar11 = Swift::String::init("M",1,1);
  pSVar8[0xd] = SVar11;
  SVar11 = Swift::String::init("o",1,1);
  pSVar8[0xe] = SVar11;
  SVar11 = Swift::String::init("d",1,1);
  pSVar8[0xf] = SVar11;
  SVar11 = Swift::String::init("e",1,1);
  pSVar8[0x10] = SVar11;
  AVar2 = Swift::$_finalizeUninitializedArray(tVar10.0);
```

Which is **`com.app.debugMode`**.

**Some lines below**:
```C
  tVar10 = Swift::$_allocateUninitializedArray(4);
  pCVar9 = (Character *)tVar10.1;
  CVar13 = Swift::Character::init("t",1,1);
  *pCVar9 = CVar13;
  CVar13 = Swift::Character::init("r",1,1);
  pCVar9[1] = CVar13;
  CVar13 = Swift::Character::init("u",1,1);
  pCVar9[2] = CVar13;
  CVar13 = Swift::Character::init("e",1,1);
  pCVar9[3] = CVar13;
  AVar2 = Swift::$_finalizeUninitializedArray(tVar10.0);
```

We can see **`true`**. So, basically, we need set `com.app.debugMode` to `true`.

These values are chars, but, *below of each array*, will be **concatenated**.
```C
  AVar2 = Swift::$_finalizeUninitializedArray(tVar10.0);
  local_78 = CONCAT44(extraout_var_00,AVar2);
```

So, how we can set to `true`?

We can see that the app uses the `NSUserDefaults.standardUserDefaults();`

What is **`NSUserDefaults`**?

`NSUserDefaults` (now **`UserDefaults`** in **Swift**) is the **native iOS KV (Key Value) store for small, per-app preferences** (`key→value`). Lightweight **persistence**, fast access, and *no encryption*.

Where we can found them?
```bash
/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/<bundle>.plist
```

**Automatic synchronization:**

The system *automatically synchronizes the in-memory cache with the user's defaults database at periodic intervals*, ensuring changes are saved. **While manual** `synchronize()` calls were *sometimes used in older versions or specific scenarios*, they are generally not recommended or necessary in modern iOS development.

We can use `syncronyze()` for the challenge so, we can apply quickly the changes.

**Accessing Values**

You can **set and retrieve values** using methods like `setObject:forKey:`, `stringForKey:`, `integerForKey:`, `boolForKey:`, etc.
### Solution
We only need to change a *preference*: set the **string value** `"true"` for the key `com.app.debugMode` in the app’s standard `UserDefaults` domain to *unlock the debug mode and reveal the flag*.
```javascript
if (ObjC.available) {
  ObjC.schedule(ObjC.mainQueue, function () {
    var d = ObjC.classes.NSUserDefaults.standardUserDefaults();
    d.setObject_forKey_("true","com.app.debugMode");
    d.synchronize();
    console.log("--hook-- debugMode=true");
  });
}
```

Run the frida command:
```bash
frida -U -n BadPreference -l enableDebugMode.js
```
Then, relaunch the application and you must see the **app in debug mode**.

![[8ksec-badPreferences2.png]]

You can also verify that the debug mode was persistence looking for the *preferences* in the **sandbox app** directory. You must find them:
```bash
find /var/mobile/Containers/Data/Application -path "*/Library/Preferences/*.plist" -name "com.8ksec.BadPreference*.plist" 2>/dev/nul
```
Then
```bash
plutil Library/Preferences/com.8ksec.BadPreference.YX4C7J2RLK.plist
```
Output:
```bash
{
    "com.app.debugMode" = true;
}
```

For **revert the changes, you just need modify the frida script**, putting `false`.

**Flag**: **`CTF{the_prefs_are_bad}`**

I hope you found it useful (:
