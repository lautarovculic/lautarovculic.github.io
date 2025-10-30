WhereAmIReally is an iOS app that only reveals the flag if you’re in the right place "physically". It checks your GPS coordinates against a geofenced area and validates the authenticity of your location before granting access.

**Link**: https://academy.8ksec.io/course/ios-application-exploitation-challenges

![[8ksec-whereAmIReally1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Bypassing Jailbreak Detection
In first place, when we *launch the application*, we can see an message in the screen that says: **Jailbroken device detected**.

![[8ksec-whereAmIReally2.png]]

So, we need bypass that. But, for that, we can spend less time if we **reverse the application**.
Inside of `Payload/WhereAmIReally.app` directory, we can see the *debug* dylib file **`WhereAmIReally.debug.dylib`**.
Create a new **Ghidra** project and then, import that file.

In the **Exports** we can see the function **`isJailbroken()`**:
```C

bool __thiscall WhereAmIReally::JailbreakChecker::isJailbroken(JailbreakChecker *this)

{
  [...]
  VARIABLES
  [...]
  
  tVar8 = Swift::$_allocateUninitializedArray(0x18);
  pSVar7 = (String *)tVar8.1;
  SVar9 = Swift::String::init("/Applications/Cydia.app",0x17,1);
  *pSVar7 = SVar9;
  SVar9 = Swift::String::init("/Applications/Sileo.app",0x17,1);
  pSVar7[1] = SVar9;
  SVar9 = Swift::String::init("/Library/MobileSubstrate/MobileSubstrate.dylib",0x2e,1);
  pSVar7[2] = SVar9;
  SVar9 = Swift::String::init("/var/jb/usr/bin/bash",0x14,1);
  pSVar7[3] = SVar9;
  SVar9 = Swift::String::init("/var/jb/usr/bin/sshd",0x14,1);
  pSVar7[4] = SVar9;
  SVar9 = Swift::String::init("/private/var/mobile/Library/SBSettings/Plugins",0x2e,1);
  pSVar7[5] = SVar9;
  SVar9 = Swift::String::init("/Library/MobileSubstrate/DynamicLibraries",0x29,1);
  pSVar7[6] = SVar9;
  SVar9 = Swift::String::init("/Applications/RockApp.app",0x19,1);
  pSVar7[7] = SVar9;
  SVar9 = Swift::String::init("/Applications/Icy.app",0x15,1);
  pSVar7[8] = SVar9;
  SVar9 = Swift::String::init("/Applications/WinterBoard.app",0x1d,1);
  pSVar7[9] = SVar9;
  SVar9 = Swift::String::init("/Applications/SBSettings.app",0x1c,1);
  pSVar7[10] = SVar9;
  SVar9 = Swift::String::init("/Applications/MxTube.app",0x18,1);
  pSVar7[0xb] = SVar9;
  SVar9 = Swift::String::init("/Applications/IntelliScreen.app",0x1f,1);
  pSVar7[0xc] = SVar9;
  SVar9 = Swift::String::init("/Applications/FakeCarrier.app",0x1d,1);
  pSVar7[0xd] = SVar9;
  SVar9 = Swift::String::init("/Applications/blackra1n.app",0x1b,1);
  pSVar7[0xe] = SVar9;
  SVar9 = Swift::String::init("/private/var/stash",0x12,1);
  pSVar7[0xf] = SVar9;
  SVar9 = Swift::String::init("/private/var/lib/cydia",0x16,1);
  pSVar7[0x10] = SVar9;
  SVar9 = Swift::String::init("/private/var/log/syslog",0x17,1);
  pSVar7[0x11] = SVar9;
  SVar9 = Swift::String::init("/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",0x3e,
                              1);
  pSVar7[0x12] = SVar9;
  SVar9 = Swift::String::init("/private/var/mobile/Library/Preferences/com.saurik.Cydia",0x38,1);
  pSVar7[0x13] = SVar9;
  SVar9 = Swift::String::init("/private/var/tmp/cydia.log",0x1a,1);
  pSVar7[0x14] = SVar9;
  SVar9 = Swift::String::init("/private/var/lib/dpkg/info",0x1a,1);
  pSVar7[0x15] = SVar9;
  SVar9 = Swift::String::init("/private/var/lib/dpkg/status",0x1c,1);
  pSVar7[0x16] = SVar9;
  SVar9 = Swift::String::init("/private/var/lib/dpkg/available",0x1f,1);
  pSVar7[0x17] = SVar9;
  AVar1 = Swift::$_finalizeUninitializedArray(tVar8.0);
  uVar2 = CONCAT44(extraout_var,AVar1);
  local_30 = uVar2;
  _swift_bridgeObjectRetain();
  ___swift_instantiateConcreteTypeFromMangledName();
  Swift::Array<String>::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::Collection::$makeIterator();
  while( true ) {
    IVar3.unknown =
         &$$demangling_cache_variable_for_type_metadata_for_Swift.IndexingIterator<[Swift.String]>;
    ___swift_instantiateConcreteTypeFromMangledName();
    Swift::IndexingIterator::$next(IVar3);
    if (local_50 == 0) {
      $$outlined_destroy_of_Swift.IndexingIterator<>(&local_40);
      _swift_bridgeObjectRelease(uVar2);
      return false;
    }
    puVar4 = &_OBJC_CLASS_$_NSFileManager;
    _objc_opt_self();
    _objc_msgSend();
    _objc_retainAutoreleasedReturnValue();
    _swift_bridgeObjectRetain(local_50);
    pNVar5 = (extension_Foundation)::Swift::String::_bridgeToObjectiveC();
    _swift_bridgeObjectRelease(local_50);
    puVar6 = puVar4;
    _objc_msgSend(puVar4,"fileExistsAtPath:",pNVar5);
    (*(code *)PTR__objc_release_00014080)(pNVar5);
    (*(code *)PTR__objc_release_00014080)(puVar4);
    if (((uint)puVar6 & 1) != 0) break;
    _swift_bridgeObjectRelease(local_50);
  }
  _swift_bridgeObjectRelease(local_50);
  $$outlined_destroy_of_Swift.IndexingIterator<>(&local_40);
  _swift_bridgeObjectRelease(uVar2);
  return true;
}
```

This `isJailbroken()` method implements a *classic jailbreak detection technique* based on **checking suspicious files and directories**.
*Creates an array with 24 paths (`0x18` in hex)* of files and directories **typical** of jailbroken devices.
List of paths it searches for:
- **Jailbreak apps**: `/Applications/Cydia.app`, `/Applications/Sileo.app`
- **Tools**: `/var/jb/usr/bin/bash`, `/var/jb/usr/bin/sshd`
- **MobileSubstrate**: `/Library/MobileSubstrate/MobileSubstrate.dylib`
- **Tweaking apps**: `RockApp`, `Icy`, `WinterBoard`, `SBSettings`, etc.
- **Modified system directories**: `/private/var/stash`, `/private/var/lib/cydia`
- **Cydia configuration files**.
For each path:
- Use **`NSFileManager`** to check if it exists (`fileExistsAtPath:`).
- If *any file/directory is found* then return **`true`** (jailbroken).

We need get the *Identifier* for the app, for that:
```bash
frida-ps -Uai | grep WhereAmIReally
```
In my case is `com.8ksec.WhereAmIReally.YX4C7J2RLK`

*If we know what the app is checking for,* we can **directly hook and return `false` to any jailbreak file check**.
So, we can simply do this Frida script:
```javascript
(function(){
  const targets = [
    "Cydia.app","Sileo.app","MobileSubstrate","/var/jb/",
    "cydia.plist","cydia.log","/var/lib/dpkg/"
  ];
  const match = p => {
    try { return targets.some(s => p.indexOf(s) !== -1); }
    catch(_){ return false; }
  };

  try {
    const FM = ObjC.classes.NSFileManager;
    Interceptor.attach(FM['- fileExistsAtPath:'].implementation, {
      onEnter(args){ this.block = match(ObjC.Object(args[2]).toString()); },
      onLeave(r){ if (this.block) r.replace(ptr('0')); }
    });
  } catch(_){}
})();
```
Run the Frida command:
```bash
frida -U -f com.8ksec.WhereAmIReally.YX4C7J2RLK -l jailBypass.js
```

And we can see that the *jailbreak detection was bypassed*!

**NOTE**
*Your device may need to perform additional validations to bypass the jailbreak. The Ghidra feature provides the complete list. Please review the tweaks, tools, and libraries you have on your device and add them to the script.*
### Recon Location
Here we have a lot of functions we need to analyze, and some of them are really long. So I'll mention the """important""" code.

First, we have a **kind of mock, which performs some validations**. For example, if the geolocation **is simulated** and the **source of the information**.

The **`locationManager()`** function have these checks.
It is a **`CoreLocation`** callback method **that processes location updates**.
This function **receives an array of `CLLocations`** and get the *last location*.

**Anti simulation/Xcode** detection:
```C
[...]
if (local_1c8 == (void *)0x0) {
    (*(code *)PTR__objc_release_00014080)(local_1b8);
} else {
    local_208 = local_1d0;
    local_200 = local_1c8;
    local_220 = local_1c8;
    local_228 = local_1d0;
    local_a0 = local_1d0;
    local_98 = local_1c8;
    (*(code *)PTR__objc_release_00014080)(local_1b8);
    local_b0 = local_228;
    local_a8 = local_220;
    local_c0 = Swift::String::init("com.apple.dt", 0xc, 1);
    in_x3 = local_c0.str;
    local_218 = &local_c0;
    Swift::String::$lazy_protocol_witness_table_accessor();
    bVar3 = (extension_Foundation)::Swift::StringProtocol::$contains((char)local_218);
    local_20c = (dword)CONCAT71(extraout_var, bVar3);
    $outlined_destroy_of_Swift.String(local_218);
    if ((local_20c & 1) == 0) {
        _swift_bridgeObjectRelease(local_220);
    } else {
        local_250 = PTR_$type_metadata_for_Any_00014548 + 8;
        tVar14 = Swift::$_allocateUninitializedArray(1);
        local_260 = (String *)tVar14.1;
        local_258 = tVar14._0_8_;
        SVar21.str = (char *)((int)&mach_header_00000000.magic + 1);
        SVar15 = Swift::String::init("[WARNING] Running from Xcode or simulator", 0x29, 1);
        local_260[1].bridgeObject = PTR_$type_metadata_for_Swift.String_00014390;
        *local_260 = SVar15;
        pcVar9 = local_250;
[...]
[...]
[...]
```

**Abnormal speed** detection:
```C
[...]
if (local_40 != (undefined *)0x0) {
    local_130 = local_40;
    local_138 = local_40;
    local_50 = local_40;
    _objc_msgSend(local_40, "speed");
    uVar11 = 0x4072c00000000000;
    cVar1 = (char)&stack0xfffffffffffffff0;
    if (in_d0 <= 300.0) { // 300 m/s = 1080 km/h !!
        puVar6 = &_OBJC_CLASS_$_NSBundle;
        _objc_opt_self();
        _objc_msgSend();
        _objc_retainAutoreleasedReturnValue();
        local_1b8 = puVar6;
        _objc_msgSend();
        _objc_retainAutoreleasedReturnValue();
        local_1b0 = puVar6;
        if (puVar6 == (undefined *)0x0) {
            local_1d0 = (char *)0x0;
            local_1c8 = (void *)0x0;
[...]
[...]
[...]
```

**Old timestamp** detection:
```C
[...]
DVar7.unknown = local_138;
_objc_msgSend(local_138, "timestamp");
_objc_retainAutoreleasedReturnValue();
local_278 = DVar7.unknown;
DVar7 = Foundation::Date::$_unconditionallyBridgeFromObjectiveC(DVar7);
local_268 = Foundation::Date::get_timeIntervalSinceNow(DVar7);
(**(code **)(local_110 + 8))(local_100, local_118);
local_270 = -60.0;
(*(code *)PTR__objc_release_00014080)(local_278);
dVar12 = local_268;
if (local_268 < local_270) {
    local_2a0 = PTR_$type_metadata_for_Any_00014548 + 8;
    tVar14 = Swift::$_allocateUninitializedArray(1);
    local_2b0 = (String *)tVar14.1;
    local_2a8 = tVar14._0_8_;
    SVar15.str = (char *)((int)&mach_header_00000000.magic + 1);
    SVar20 = Swift::String::init("[WARNING] Location timestamp too old", 0x24, 1);
    local_2b0[1].bridgeObject = PTR_$type_metadata_for_Swift.String_00014390;
    *local_2b0 = SVar20;
    pcVar9 = local_2a0;
[...]
[...]
[...]
```

**Abnormal altitude** detection:
```C
_objc_msgSend(local_138, "altitude");
local_2b8 = 10000.0;
local_2c0 = dVar12;
(*(code *)PTR__objc_retain_00014088)(local_138);
dVar12 = local_2b8;
if (local_2c0 <= local_2b8) {
    _objc_msgSend(local_138, "altitude");
    dVar13 = -100.0;
    local_2c4 = (dword)(dVar12 < -100.0);
}
```

Also, there are another **`locationManager()`** more **short** in **Exports**. But this handle the **permissions** of location.
Anyway, we will set the **authorization** always as **true** (3).
```C
void __thiscall
WhereAmIReally::LocationManager::locationManager
          (LocationManager *this, CLLocationManager *param_1,
          CLAuthorizationStatus didChangeAuthorization)
{
    bool bVar1;

    __C::CLAuthorizationStatus::typeMetadataAccessor();
    __C::CLAuthorizationStatus::$lazy_protocol_witness_table_accessor();
    bVar1 = Swift::$==_infix(0xc4, 0xc0);
    if (bVar1) {
        bVar1 = true;
    } else {
        bVar1 = Swift::$==_infix(0xbc, 0xb8);
    }
    if (bVar1 != false) {
        (**(code **)((*(uint *)this & *(uint *)PTR__swift_isaMask_000145e0) + 0xa0))(1);
    }
    return;
}
```

- `0xc4/0xc0`: Probably `authorizedWhenInUse` (4) or `authorizedAlways` (3).
- `0xbc/0xb8`: *Probably another authorized state*.

In our hook, we will use this part of script:
```javascript
// authorization
try {
    const LM = ObjC.classes.CLLocationManager;
    if (LM['+ authorizationStatus']) {
        Interceptor.attach(LM['+ authorizationStatus'].implementation, { 
            onLeave(r) { 
                r.replace(ptr('3')); // authorizedAlways
            } 
        });
    }
    log('auth/location services forced');
} catch (_) {}
```

Also, this will the **hook for anti simulation** code:
```javascript
// anti-"simulated"
try {
    const SI = ObjC.classes.CLLocationSourceInformation;
    if (SI && SI['- isSimulatedBySoftware']) {
        Interceptor.attach(SI['- isSimulatedBySoftware'].implementation, { 
            onLeave(r) { 
                r.replace(ptr('0')); 
            } 
        });
    }
    log('anti-simulation ON');
} catch (_) {}
```

But, **what is the correct location for complete the challenge**...?
Let's move to the **`$$WhereAmIReally.ContentView.(df`** functions!
You can found that in the **Symbol Tree** panel:
![[8ksec-whereAmIReally3.png]]

We can see the **`isMocked()`** function:
```C
bool $WhereAmIReally.ContentView.(isMocked_in__8E3FC3B3FEF0CBBE848D4767CE9AAAEA)(location: ___C.CLLocation) -> _Swift.Bool
               (int param_1)
{
    sdword sVar1;
    bool bVar2;
    int iVar3;
    dword local_3c;
    byte local_23;
    undefined local_22;
    byte local_21;

    _objc_msgSend(param_1, "sourceInformation");
    _objc_retainAutoreleasedReturnValue();
    if (param_1 == 0) {
        local_3c = 2;
    } else {
        iVar3 = param_1;
        _objc_msgSend(param_1, "isSimulatedBySoftware");
        local_3c = (dword)iVar3;
        (*(code *)PTR__objc_release_00014080)(param_1);
    }
    local_22 = (undefined)local_3c;
    local_21 = 1;
    sVar1 = (local_3c & 0xff) - 2;
    if ((sVar1 == 0) || ($outlined_init_with_copy_of_Swift.Bool?(sVar1, &local_22, &local_23), local_21 == 2)) {
        bVar2 = false;
    } else {
        bVar2 = (local_23 & 1) == (local_21 & 1);
    }
    return bVar2;
}
```

Additionally we will see a *function that is decrypting a hardcoded string*. Not our business.
What is our interest? **`isWithinGeofence()`**:
```C
bool $WhereAmIReally.ContentView.(isWithinGeofence_in__8E3FC3B3FEF0CBBE848D4767CE9AAAEA)(location: _ __C.CLLocation) -> _Swift.Bool
               (undefined8 param_1)
{
    CLLocation *pCVar1;
    double latitude;
    double longitude;

    latitude = double::init(0x4048888888888889);
    longitude = double::init(0x400299999999999a);
    pCVar1 = __C::CLLocation::typeMetadataAccessor();
    pCVar1 = __C::CLLocation::__allocating_init(pCVar1, latitude, longitude);
    _objc_msgSend(param_1, "distanceFromLocation:");
    (*(code *)PTR__objc_release_00014080)(pCVar1);
    return latitude <= 100.0;
}
```
This is the **most important feature of the challenge**: it *defines the exact coordinates* where you must "**be**" to *solve it*.
```C
latitude = double::init(0x4048888888888889);
longitude = double::init(0x400299999999999a);
```
- **latitude**: `49.0666666667` approximately.
- **longitude**: `2.3250000000` approximately.
Also, this function **check the distance**:
```C
_objc_msgSend(param_1, "distanceFromLocation:");
(*(code *)PTR__objc_release_00014080)(pCVar1);
return latitude <= 100.0;
```
### Spoofing Location
Here's the **final javascript** that we need for *inject* the exact coordinates that the app need to **show us the flag**:
```javascript
'use strict';

setImmediate(function () {
  // binary coordinates
  const LAT = 49.0666666667;
  const LON = 2.3250000000;

  function log(s){ try{ console.log(s); }catch(_){} }

  if (!ObjC.available) { log('ObjC runtime not ready'); return; }

  // anti-"simulated"
  try {
    const SI = ObjC.classes.CLLocationSourceInformation;
    if (SI && SI['- isSimulatedBySoftware'])
      Interceptor.attach(SI['- isSimulatedBySoftware'].implementation, { onLeave(r){ r.replace(ptr('0')); } });
    log('anti-simulation ON');
  } catch (_) {}

  // authorization
  try {
    const LM = ObjC.classes.CLLocationManager;
    if (LM['+ authorizationStatus'])
      Interceptor.attach(LM['+ authorizationStatus'].implementation, { onLeave(r){ r.replace(ptr('3')); } }); // authorizedAlways
    log('auth/location services forced');
  } catch (_) {}

  // helper: build CLLocation(LAT,LON)
  function makeLoc() {
    try {
      const CLL = ObjC.classes.CLLocation;
      return CLL.alloc().initWithLatitude_longitude_(LAT, LON);
    } catch (e) { log('makeLoc error: ' + e); return null; }
  }

  // hook swift delegate - inject our fake location
  const SwiftLM = ObjC.classes['_TtC14WhereAmIReally15LocationManager'];
  const SEL = '- locationManager:didUpdateLocations:';
  if (SwiftLM && SwiftLM[SEL]) {
    Interceptor.attach(SwiftLM[SEL].implementation, {
      onEnter(args) {
        try {
          const fake = makeLoc(); if (!fake) return;
          const NSArray = ObjC.classes.NSArray;
          const arr = NSArray.arrayWithObject_(fake);
          args[3] = arr.handle;
          log(`---injected--- ${LAT.toFixed(6)}, ${LON.toFixed(6)}`);
        } catch (e) { log('inject err ' + e); }
      }
    });
    log('---hooked--- -locationManager:didUpdateLocations:');
  } else {
    log('swift LocationManager or method not found');
  }
});
```

You can run **both scripts** (jailbreak detection and spoof location):
```bash
frida -U -f com.8ksec.WhereAmIReally.YX4C7J2RLK -l jailBypass.js -l spoofLocation.js
```
Output:
```bash
Spawning `com.8ksec.WhereAmIReally.YX4C7J2RLK`...
anti-simulation ON
auth/location services forced
---hooked--- -locationManager:didUpdateLocations:
Spawned `com.8ksec.WhereAmIReally.YX4C7J2RLK`. Resuming main thread!
[iPhone::com.8ksec.WhereAmIReally.YX4C7J2RLK ]->
---injected--- 49.066667, 2.325000
---injected--- 49.066667, 2.325000
---injected--- 49.066667, 2.325000
```

![[8ksec-whereAmIReally4.png]]

And we **got the flag**!
**Flag**: **`CTF{EVFJNVGNWV}`**
#### Glossary
- **`CLLocationManager`** (Objective-C)
Apple's framework used to *receive GPS updates*, request location permissions, detect entry/exit of geofences, etc. It is the actual delegate in iOS.
- **`_TtC14WhereAmIReally15LocationManager`** (Swift)
This app's internal Swift class implements **delegate methods**, such as `locationManager:didUpdateLocations:`. We **intercept this class because it processes the location within the app binary**.
- **`CLLocation`**
Object that *encapsulates latitude, longitude, speed, altitude, timestamp*, etc.
Our injection **replaces this object with a controlled one** that represents the desired geolocation.
- **`CLLocationSourceInformation`**
*Introduced in iOS 15*. Allows you to **determine if a location was simulated by software**.
Key method: `isSimulatedBySoftware` → Bool. *We hook it to return false*.
- **`NSFileManager`**
API used to **validate the existence of system files**.
In `isJailbroken()` is used to detect jailbreak paths.

I hope you found it useful (:
