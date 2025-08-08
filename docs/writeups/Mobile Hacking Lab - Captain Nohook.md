**Description**: Welcome to the **iOS Application Security Lab: Captain No Hook Anti-Debugging Challenge**. This challenge focuses on a fictitious app called Captain No Hook, which implements advanced anti-debugging / jailbreak detection techniques. Your objective is to bypass these protections and retrieve the hidden flag within the app.

**Download**: https://lautarovculic.com/my_files/noHook.ipa
**Link:** https://www.mobilehackinglab.com/path-player?courseid=lab-captain-nohook

![[noHook1.png]]

Install an **IPA** file can be difficult.
So, for make it more easy, I made a YouTube video with the process using **Sideloadly**.
**LINK**: https://www.youtube.com/watch?v=YPpo9owRKGE

Let's **unzip the `.ipa`** file.
We can see that when we *open the App*, we have an button that says "**Flag 'ere!**"
But if we press the button, an *pop-up message* spawn:
"**Noncompliant device detected!**"
"*Yerr hook won't work!*"

We need bypass these protections, *anti jailbreak / debug*.
Probably we need use frida for this work.

Let's start analyzing the **binary file** searching for some useful strings.
In the **`.plist`** file I don't found anything useful.

In first instance, I just search for some strings that I just thought in the moment
```bash
strings "Captain Nohook" | grep -iE "frida|hook|gadget|debug|jailbreak|jail|debugging|anti|challenge|implement|detect|bypass|protect|secure|hidden|flag|noncompliant|device"
```

Output:
```bash
Captain_Nohook/ViewController.swift
Flag 'ere!
Noncompliant device detected!
Yerr hook won't work!
Arrr, find yerr hidden flag here!
_TtC14Captain_Nohook14ViewController
flag
T@"UILabel",N,W,Vflag
Captain_Nohook/AppDelegate.swift
_TtC14Captain_Nohook11AppDelegate
debugDescription
_TtC14Captain_Nohook13SceneDelegate
_TtC14Captain_Nohook30ReverseEngineeringToolsChecker
/usr/sbin/frida-server
FridaGadget
frida
Captain_Nohook/device-checker.swift
Suspicious PFlag value
Captain_Nohook/GeneratedAssetSymbols.swift
_TtC14Captain_NohookP33_D0721D92BE78DE45B644111BD41CC63A19ResourceBundleClass
no-hook
_TtC11CryptoSwift11SecureBytes
setHidden:
isHidden
flag
setFlag:
whereIsflag:
application:didRegisterForRemoteNotificationsWithDeviceToken:
applicationProtectedDataWillBecomeUnavailable:
applicationProtectedDataDidBecomeAvailable:
application:shouldSaveSecureApplicationState:
application:shouldRestoreSecureApplicationState:
debugDescription
Captain_Nohook
Captain_Nohook
$s14Captain_Nohook19ResourceBundleClass33_D0721D92BE78DE45B644111BD41CC63ALLC
SecureBytes
flag
pSelectFlag
```

We can see some interesting *functions* and may be *classes*.
So, let's inspect this output better in **ghidra**. Import the binary and let's search for these functions.

We have an **function** called **`_disable_gdb`**
```CPP
void _disable_gdb(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)0xfffffffffffffffd;
  _dlsym(0xfffffffffffffffd,"ptrace");
  (*pcVar1)(0x1f,0,0);
  return;
}
```

Also, **two similar functions** are in the binary
**`amIReverseEngineered`**
```CPP
dword __thiscall Captain_Nohook::ReverseEngineeringToolsChecker::amIReverseEngineered(void)

{
  undefined auVar1 [16];
  
  auVar1 = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(performChecks_in__75B14952DDFE2A7 8282659A6E004BB4A)()_->_Captain_Nohook.ReverseEngineeringToolsChecker.ReverseEngineeringToolsStatu s
                     ();
  _swift_bridgeObjectRelease(auVar1._8_8_);
  return (auVar1._0_4_ ^ 1) & 1;
}
```
Which if we see the details:
```CPP
undefined  [16]
$$static_Captain_Nohook.ReverseEngineeringToolsChecker.(performChecks_in__75B14952DDFE2A78282659A6E0 04BB4A)()_->_Captain_Nohook.ReverseEngineeringToolsChecker.ReverseEngineeringToolsStatus
          (void)

{
  byte bVar1;
  char cVar2;
  void *pvVar3;
  Array<FailedCheck> AVar4;
  undefined4 uVar5;
  dword dVar6;
  undefined4 extraout_var;
  char *pcVar7;
  IndexingIterator IVar8;
  undefined8 uVar9;
  void *pvVar10;
  tuple2.conflict12 tVar11;
  undefined auVar12 [16];
  char local_88 [8];
  char *local_80;
  void *local_78;
  char local_70;
  char local_69;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  byte local_48 [8];
  String local_40;
  byte local_29;
  
  local_50 = 0;
  local_60 = 0;
  local_58 = 0;
  local_70 = '\0';
  local_29 = 1;
  local_48[0] = 1;
  pvVar10 = (void *)0x1;
  local_40 = Swift::String::init("",0,1);
  ___swift_instantiateConcreteTypeFromMangledName
            ((int *)&
                    $$demangling_cache_variable_for_type_metadata_for_(check:_Captain_Nohook.FailedC heck,failMessage:_Swift.String)
            );
  tVar11 = Swift::$_allocateUninitializedArray(0);
  local_50 = tVar11._0_8_;
  AVar4 = Captain_Nohook::FailedCheck::get_allCases();
  local_68 = CONCAT44(extraout_var,AVar4);
  ___swift_instantiateConcreteTypeFromMangledName
            ((int *)&$$demangling_cache_variable_for_type_metadata_for_[Captain_Nohook.FailedCheck])
  ;
  pcVar7 = Swift::Array<>::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::Collection::$makeIterator();
LAB_10000d760:
  IVar8.unknown =
       (undefined *)
       ___swift_instantiateConcreteTypeFromMangledName
                 (&
                  $$demangling_cache_variable_for_type_metadata_for_Swift.IndexingIterator<[Captain_ Nohook.FailedCheck]>
                 );
  Swift::IndexingIterator::$next(IVar8);
  cVar2 = local_69;
  if (local_69 == '\n') {
    $$outlined_destroy_of_Swift.IndexingIterator<>(&local_60);
    uVar9 = local_50;
    dVar6 = (dword)local_29;
    _swift_bridgeObjectRetain();
    dVar6 = Captain_Nohook::ReverseEngineeringToolsChecker::ReverseEngineeringToolsStatus::init
                      (dVar6 & 1);
    $$outlined_destroy_of_[(check:_Captain_Nohook.FailedCheck,failMessage:_Swift.String)](&local_50)
    ;
    $$outlined_destroy_of_(passed:_Swift.Bool,failMessage:_Swift.String)((int)local_48);
    auVar12._4_4_ = 0;
    auVar12._0_4_ = dVar6 & 1;
    auVar12._8_8_ = uVar9;
    return auVar12;
  }
  local_70 = local_69;
  switch(local_69) {
  case '\x01':
    uVar5 = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(checkExistenceOfSuspiciousFiles_ in__75B14952DDFE2A78282659A6E004BB4A)()_->_(passed:_Swift.Bool,failMessage:_Swift.String)
                      ();
    local_48[0] = (byte)uVar5 & 1;
    pvVar3 = local_40.bridgeObject;
    local_40.bridgeObject = pvVar10;
    local_40.str = pcVar7;
    _swift_bridgeObjectRelease(pvVar3);
    break;
  default:
    goto LAB_10000d760;
  case '\x06':
    uVar5 = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(checkDYLD_in__75B14952DDFE2A7828 2659A6E004BB4A)()_->_(passed:_Swift.Bool,failMessage:_Swift.String)
                      ();
    local_48[0] = (byte)uVar5 & 1;
    pvVar3 = local_40.bridgeObject;
    local_40.bridgeObject = pvVar10;
    local_40.str = pcVar7;
    _swift_bridgeObjectRelease(pvVar3);
    break;
  case '\a':
    uVar5 = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(checkOpenedPorts_in__75B14952DDF E2A78282659A6E004BB4A)()_->_(passed:_Swift.Bool,failMessage:_Swift.String)
                      ();
    local_48[0] = (byte)uVar5 & 1;
    pvVar3 = local_40.bridgeObject;
    local_40.bridgeObject = pvVar10;
    local_40.str = pcVar7;
    _swift_bridgeObjectRelease(pvVar3);
    break;
  case '\b':
    local_48[0] = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(checkPSelectFlag_in__75B14 952DDFE2A78282659A6E004BB4A)()_->_(passed:_Swift.Bool,failMessage:_Swift.String)
                            ();
    pvVar3 = local_40.bridgeObject;
    local_40.bridgeObject = pvVar10;
    local_40.str = pcVar7;
    _swift_bridgeObjectRelease(pvVar3);
  }
  bVar1 = local_48[0];
  if ((local_29 & 1) == 0) {
    bVar1 = 0;
  }
  local_29 = bVar1 & 1;
  if ((local_48[0] & 1) == 0) {
    pcVar7 = local_40.str;
    pvVar3 = local_40.bridgeObject;
    _swift_bridgeObjectRetain();
    local_88[0] = cVar2;
    local_80 = pcVar7;
    local_78 = pvVar3;
    pcVar7 = (char *)___swift_instantiateConcreteTypeFromMangledName
                               ((int *)&
                                       $$demangling_cache_variable_for_type_metadata_for_[(check:_Ca ptain_Nohook.FailedCheck,failMessage:_Swift.String)]
                               );
    Swift::Array<undefined>::append((char)local_88,(Array<undefined>)pcVar7);
  }
  goto LAB_10000d760;
}
```

Also, the function:
**`amIReverseEngineeredWithFailedChecks`**
```CPP
undefined  [16] __thiscall
Captain_Nohook::ReverseEngineeringToolsChecker::amIReverseEngineeredWithFailedChecks(void)

{
  undefined auVar1 [16];
  undefined auVar2 [16];
  
  auVar1 = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(performChecks_in__75B14952DDFE2A7 8282659A6E004BB4A)()_->_Captain_Nohook.ReverseEngineeringToolsChecker.ReverseEngineeringToolsStatu s
                     ();
  auVar2._8_8_ = auVar1._8_8_;
  _swift_bridgeObjectRetain();
  _swift_bridgeObjectRelease(auVar2._8_8_);
  auVar2._4_4_ = 0;
  auVar2._0_4_ = (auVar1._0_4_ ^ 1) & 1;
  return auVar2;
}
```
Details:
```CPP
undefined  [16]
$$static_Captain_Nohook.ReverseEngineeringToolsChecker.(performChecks_in__75B14952DDFE2A78282659A6E0 04BB4A)()_->_Captain_Nohook.ReverseEngineeringToolsChecker.ReverseEngineeringToolsStatus
          (void)

{
  byte bVar1;
  char cVar2;
  void *pvVar3;
  Array<FailedCheck> AVar4;
  undefined4 uVar5;
  dword dVar6;
  undefined4 extraout_var;
  char *pcVar7;
  IndexingIterator IVar8;
  undefined8 uVar9;
  void *pvVar10;
  tuple2.conflict12 tVar11;
  undefined auVar12 [16];
  char local_88 [8];
  char *local_80;
  void *local_78;
  char local_70;
  char local_69;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  byte local_48 [8];
  String local_40;
  byte local_29;
  
  local_50 = 0;
  local_60 = 0;
  local_58 = 0;
  local_70 = '\0';
  local_29 = 1;
  local_48[0] = 1;
  pvVar10 = (void *)0x1;
  local_40 = Swift::String::init("",0,1);
  ___swift_instantiateConcreteTypeFromMangledName
            ((int *)&
                    $$demangling_cache_variable_for_type_metadata_for_(check:_Captain_Nohook.FailedC heck,failMessage:_Swift.String)
            );
  tVar11 = Swift::$_allocateUninitializedArray(0);
  local_50 = tVar11._0_8_;
  AVar4 = Captain_Nohook::FailedCheck::get_allCases();
  local_68 = CONCAT44(extraout_var,AVar4);
  ___swift_instantiateConcreteTypeFromMangledName
            ((int *)&$$demangling_cache_variable_for_type_metadata_for_[Captain_Nohook.FailedCheck])
  ;
  pcVar7 = Swift::Array<>::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::Collection::$makeIterator();
LAB_10000d760:
  IVar8.unknown =
       (undefined *)
       ___swift_instantiateConcreteTypeFromMangledName
                 (&
                  $$demangling_cache_variable_for_type_metadata_for_Swift.IndexingIterator<[Captain_ Nohook.FailedCheck]>
                 );
  Swift::IndexingIterator::$next(IVar8);
  cVar2 = local_69;
  if (local_69 == '\n') {
    $$outlined_destroy_of_Swift.IndexingIterator<>(&local_60);
    uVar9 = local_50;
    dVar6 = (dword)local_29;
    _swift_bridgeObjectRetain();
    dVar6 = Captain_Nohook::ReverseEngineeringToolsChecker::ReverseEngineeringToolsStatus::init
                      (dVar6 & 1);
    $$outlined_destroy_of_[(check:_Captain_Nohook.FailedCheck,failMessage:_Swift.String)](&local_50)
    ;
    $$outlined_destroy_of_(passed:_Swift.Bool,failMessage:_Swift.String)((int)local_48);
    auVar12._4_4_ = 0;
    auVar12._0_4_ = dVar6 & 1;
    auVar12._8_8_ = uVar9;
    return auVar12;
  }
  local_70 = local_69;
  switch(local_69) {
  case '\x01':
    uVar5 = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(checkExistenceOfSuspiciousFiles_ in__75B14952DDFE2A78282659A6E004BB4A)()_->_(passed:_Swift.Bool,failMessage:_Swift.String)
                      ();
    local_48[0] = (byte)uVar5 & 1;
    pvVar3 = local_40.bridgeObject;
    local_40.bridgeObject = pvVar10;
    local_40.str = pcVar7;
    _swift_bridgeObjectRelease(pvVar3);
    break;
  default:
    goto LAB_10000d760;
  case '\x06':
    uVar5 = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(checkDYLD_in__75B14952DDFE2A7828 2659A6E004BB4A)()_->_(passed:_Swift.Bool,failMessage:_Swift.String)
                      ();
    local_48[0] = (byte)uVar5 & 1;
    pvVar3 = local_40.bridgeObject;
    local_40.bridgeObject = pvVar10;
    local_40.str = pcVar7;
    _swift_bridgeObjectRelease(pvVar3);
    break;
  case '\a':
    uVar5 = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(checkOpenedPorts_in__75B14952DDF E2A78282659A6E004BB4A)()_->_(passed:_Swift.Bool,failMessage:_Swift.String)
                      ();
    local_48[0] = (byte)uVar5 & 1;
    pvVar3 = local_40.bridgeObject;
    local_40.bridgeObject = pvVar10;
    local_40.str = pcVar7;
    _swift_bridgeObjectRelease(pvVar3);
    break;
  case '\b':
    local_48[0] = $$static_Captain_Nohook.ReverseEngineeringToolsChecker.(checkPSelectFlag_in__75B14 952DDFE2A78282659A6E004BB4A)()_->_(passed:_Swift.Bool,failMessage:_Swift.String)
                            ();
    pvVar3 = local_40.bridgeObject;
    local_40.bridgeObject = pvVar10;
    local_40.str = pcVar7;
    _swift_bridgeObjectRelease(pvVar3);
  }
  bVar1 = local_48[0];
  if ((local_29 & 1) == 0) {
    bVar1 = 0;
  }
  local_29 = bVar1 & 1;
  if ((local_48[0] & 1) == 0) {
    pcVar7 = local_40.str;
    pvVar3 = local_40.bridgeObject;
    _swift_bridgeObjectRetain();
    local_88[0] = cVar2;
    local_80 = pcVar7;
    local_78 = pvVar3;
    pcVar7 = (char *)___swift_instantiateConcreteTypeFromMangledName
                               ((int *)&
                                       $$demangling_cache_variable_for_type_metadata_for_[(check:_Ca ptain_Nohook.FailedCheck,failMessage:_Swift.String)]
                               );
    Swift::Array<undefined>::append((char)local_88,(Array<undefined>)pcVar7);
  }
  goto LAB_10000d760;
}
```

And we have this **function**
**`get_failedChecks`**
```CPP
undefined8
Captain_Nohook::ReverseEngineeringToolsChecker::ReverseEngineeringToolsStatus::get_failedChecks
          (undefined8 param_1,undefined8 param_2)

{
  _swift_bridgeObjectRetain();
  return param_2;
}
```

More **functions**...
`undefined8 Captain_Nohook::ImageResource::get_noHook(void)`
```CPP
undefined8 Captain_Nohook::ImageResource::get_noHook(void)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  puVar1 = noHook::unsafeMutableAddressor();
  uVar3 = *puVar1;
  uVar2 = puVar1[2];
  _swift_bridgeObjectRetain();
  _objc_retain(uVar2);
  return uVar3;
}
```
And
`UIImage * (extension_Captain_Nohook)::__C::UIImage::get_noHook(void)`

That we can see in *both functions*
```CPP
undefined8 * Captain_Nohook::ImageResource::noHook::unsafeMutableAddressor(void)

{
  undefined8 local_18;
  
  if ($$one-time_initialization_token_for_noHook != -1) {
    _swift_once(&$$one-time_initialization_token_for_noHook,one_time_init_for_noHook,local_18);
  }
  return &_$s14Captain_Nohook13ImageResourceV6noHookACvpZ;
}
```

`void Captain_Nohook::ImageResource::one_time_init_for_noHook(void)`
Which contains
```CPP
void Captain_Nohook::ImageResource::one_time_init_for_noHook(void)

{
  undefined8 *puVar1;
  undefined8 bundle;
  void *pvVar2;
  String SVar3;
  
  SVar3 = Swift::String::init("no-hook",7,1);
  pvVar2 = SVar3.bridgeObject;
  puVar1 = _D0721D92BE78DE45B644111BD41CC63A::resourceBundle::unsafeMutableAddressor();
  bundle = *puVar1;
  _objc_retain();
  _$s14Captain_Nohook13ImageResourceV6noHookACvpZ = init(SVar3.str,pvVar2,bundle);
  DAT_100181c78 = pvVar2;
  DAT_100181c80 = bundle;
  return;
}
```

The **`get_passed`** function:
```CPP
dword Captain_Nohook::ReverseEngineeringToolsChecker::ReverseEngineeringToolsStatus::get_passed
                (dword param_1)

{
  return param_1 & 1;
}
```

The
`NSPersistentContainer * __thiscall Captain_Nohook::AppDelegate::get_persistentContainer(AppDelegate *this)`

```CPP
NSPersistentContainer * __thiscall
Captain_Nohook::AppDelegate::get_persistentContainer(AppDelegate *this)

{
  AppDelegate *pAVar1;
  undefined8 uVar2;
  NSPersistentContainer *local_78;
  undefined auStack_48 [24];
  undefined auStack_30 [24];
  AppDelegate *local_18;
  
  pAVar1 = this + _TtC14Captain_Nohook11AppDelegate::$__lazy_storage_$_persistentContainer;
  local_18 = this;
  _swift_beginAccess(pAVar1,auStack_30,0x20,0);
  local_78 = *(NSPersistentContainer **)pAVar1;
  _objc_retain();
  _swift_endAccess(auStack_30);
  if (local_78 == (NSPersistentContainer *)0x0) {
    local_78 = $$closure_#1_()_->___C.NSPersistentContainer_in_Captain_Nohook.AppDelegate.persistent Container.getter_:___C.NSPersistentContainer
                         ();
    _objc_retain();
    pAVar1 = this + _TtC14Captain_Nohook11AppDelegate::$__lazy_storage_$_persistentContainer;
    _swift_beginAccess(pAVar1,auStack_48,0x21,0);
    uVar2 = *(undefined8 *)pAVar1;
    *(NSPersistentContainer **)pAVar1 = local_78;
    _objc_release(uVar2);
    _swift_endAccess(auStack_48);
    _objc_retain(local_78);
    _objc_release(local_78);
  }
  else {
    _objc_retain();
    _objc_release(local_78);
  }
  return local_78;
}
```

And the **most important function**
The **`get_flag`**
```CPP
undefined  [16] __thiscall Captain_Nohook::ViewController::getFlag(ViewController *this)

{
  undefined *puVar1;
  StaticString SVar2;
  char *pcVar3;
  int iVar4;
  code *pcVar5;
  dword dVar6;
  Array<undefined> AVar7;
  Array<__int8> AVar8;
  undefined4 extraout_var;
  Encoding EVar9;
  char *pcVar10;
  AES *this_00;
  undefined4 extraout_var_00;
  undefined4 extraout_var_01;
  undefined *puVar11;
  undefined4 extraout_var_02;
  undefined8 uVar12;
  Encoding EVar13;
  uint uVar14;
  void *pvVar15;
  DefaultStringInterpolation DVar16;
  undefined4 uVar17;
  undefined auVar18 [16];
  String SVar19;
  tuple2.conflict12 tVar20;
  undefined local_440 [8];
  int local_438;
  int local_430;
  String local_428;
  char *local_418;
  void *local_410;
  char *local_408;
  void *local_400;
  char *local_3f8;
  void *local_3f0;
  undefined *local_3e8;
  Encoding local_3e0;
  void *local_3d8;
  char *local_3d0;
  void *local_3c8;
  AES *local_3c0;
  undefined8 local_3b8;
  undefined *local_3b0;
  int local_3a8;
  void *local_3a0;
  undefined *local_398;
  AES *local_390;
  undefined8 local_388;
  uint local_380;
  undefined8 local_378;
  undefined4 local_36c;
  undefined **local_368;
  undefined8 local_360;
  int local_358;
  AES *local_350;
  int local_348;
  undefined *local_340;
  void *local_338;
  uint local_330;
  undefined *local_328;
  undefined *local_320;
  void *local_318;
  undefined *local_310;
  uint local_308;
  uint local_300;
  undefined *local_2f8;
  undefined *local_2f0;
  String *local_2e8;
  uint local_2e0;
  undefined *local_2d8;
  uint local_2d0;
  undefined **local_2c8;
  void *local_2c0;
  undefined **local_2b8;
  undefined8 local_2b0;
  DefaultStringInterpolation local_2a8;
  undefined *local_2a0;
  undefined *local_298;
  code *local_290;
  String *local_288;
  uint local_280;
  undefined *local_278;
  undefined *local_270;
  undefined8 local_268;
  undefined *local_260;
  undefined8 local_258;
  Encoding local_250;
  undefined *local_248;
  undefined *local_240;
  undefined *local_238;
  String local_230;
  undefined *local_220;
  int local_218;
  undefined8 local_210;
  undefined *local_208;
  uint local_200;
  int local_1f8;
  void *local_1f0;
  int local_1e8;
  undefined8 local_1e0;
  String local_1d8;
  undefined8 local_1c8;
  UIAlertAction *local_1c0;
  dword local_1b4;
  UIAlertController *local_1b0;
  ViewController *local_1a8;
  code *local_1a0;
  undefined *local_198;
  DefaultStringInterpolation local_190;
  StaticString local_188;
  char *local_180;
  char *local_178;
  int local_170;
  undefined *local_168;
  int local_160;
  uint local_158;
  Encoding local_150;
  UIAlertController *local_148;
  char *local_140;
  void *local_138;
  undefined *local_130;
  void *local_128;
  undefined *local_120;
  undefined *local_118;
  AES *local_110;
  int local_108;
  undefined *local_100 [3];
  undefined *local_e8;
  undefined **local_e0;
  undefined *local_d8;
  void *local_d0;
  undefined *local_c8;
  uint local_c0;
  String local_b8;
  undefined *local_a8;
  uint local_a0;
  String local_98;
  undefined *local_88;
  undefined *local_80;
  undefined8 local_78;
  undefined *local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  String local_48;
  ViewController *local_38;
  
  local_1a0 = 
  $$closure_#1_(__C.UIAlertAction)_->_()_in_Captain_Nohook.ViewController.getFlag()_->_Swift.String;
  local_198 = PTR_$$type_metadata_for_Swift.UInt8_10016d040;
  local_190.unknown = PTR_$$type_metadata_for_Swift.String_10016c750;
  local_188.unknown = "Fatal error";
  local_180 = "Unexpectedly found nil while unwrapping an Optional value";
  local_178 = "Captain_Nohook/ViewController.swift";
  local_38 = (ViewController *)0x0;
  local_48 = (String)ZEXT816(0);
  local_50 = 0;
  local_170 = 0;
  local_60 = 0;
  local_a8 = (undefined *)0x0;
  local_a0 = 0;
  local_c8 = (undefined *)0x0;
  local_c0 = 0;
  local_d8 = (undefined *)0x0;
  local_d0 = (void *)0x0;
  local_108 = 0;
  local_110 = (AES *)0x0;
  local_118 = (undefined *)0x0;
  local_130 = (undefined *)0x0;
  local_128 = (void *)0x0;
  local_140 = (char *)0x0;
  local_138 = (void *)0x0;
  local_148 = (UIAlertController *)0x0;
  local_1a8 = this;
  local_168 = (undefined *)Encoding::$typeMetadataAccessor();
  local_160 = *(int *)(local_168 + -8);
  local_158 = *(int *)(local_160 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  puVar1 = local_440 + -local_158;
  local_150.unknown = puVar1;
  local_38 = this;
  dVar6 = is_noncompliant_device();
  if ((dVar6 & 1) != 0) {
    local_1c8 = 0;
    auVar18 = __C::UIAlertController::typeMetadataAccessor();
    local_1b4 = 1;
    local_1d8 = Swift::String::init("Noncompliant device detected!",0x1d,1);
    SVar19 = Swift::String::init("Yerr hook won\'t work!",0x15,(byte)local_1b4 & 1);
    local_1b0 = __C::UIAlertController::$__allocating_init
                          (auVar18._0_8_,local_1d8.str,(int)local_1d8.bridgeObject,SVar19.str,
                           (int)SVar19.bridgeObject);
    local_148 = local_1b0;
    auVar18 = __C::UIAlertAction::typeMetadataAccessor();
    SVar19 = Swift::String::init("OK",2,(byte)local_1b4 & 1);
    local_1c0 = __C::UIAlertAction::$__allocating_init
                          (auVar18._0_8_,SVar19.str,(int)SVar19.bridgeObject,local_1c8,
                           (int)local_1a0,local_1c8);
    _objc_msgSend(local_1b0,"addAction:");
    _objc_release(local_1c0);
    _objc_msgSend(local_1a8,"presentViewController:animated:completion:",local_1b0,local_1b4 & 1,0);
    _objc_release(local_1b0);
  }
  iVar4 = local_170;
  local_230 = Swift::String::init("HhRVZ1fdevIW2GfW42oy9J4XrAz330o5amXtNc/t8+s=",0x2c,1);
  local_48 = local_230;
  tVar20 = Swift::$_allocateUninitializedArray(0x1f);
  local_220 = (undefined *)tVar20.1;
  *local_220 = 0x31;
  local_220[1] = 0x22;
  local_220[2] = 0x31;
  local_220[3] = 0x26;
  local_220[4] = 0x2d;
  local_220[5] = 0x37;
  local_220[6] = 0x3b;
  local_220[7] = 0x39;
  local_220[8] = 0x39;
  local_220[9] = 0x3b;
  local_220[10] = 0x30;
  local_220[0xb] = 0x3b;
  local_220[0xc] = 0x26;
  local_220[0xd] = 0x31;
  local_220[0xe] = 0x62;
  local_218 = 0xf;
  local_220[0xf] = 0x60;
  local_220[0x10] = 0x37;
  local_220[0x11] = 0x35;
  local_220[0x12] = 0x3a;
  local_220[0x13] = 0x3c;
  local_220[0x14] = 0x35;
  local_220[0x15] = 0x37;
  local_220[0x16] = 0x3f;
  local_220[0x17] = 0x3d;
  local_220[0x18] = 0x3a;
  local_220[0x19] = 0x20;
  local_220[0x1a] = 0x3b;
  local_220[0x1b] = 0x3a;
  local_220[0x1c] = 0x35;
  local_220[0x1d] = 0x27;
  local_220[0x1e] = 0x35;
  local_210 = Swift::$_finalizeUninitializedArray(tVar20._0_8_);
  local_200 = local_218 + 0x11U & 0xfffffffffffffff0;
  local_208 = puVar1;
  local_58 = local_210;
  local_50 = local_210;
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  local_1f8 = (int)puVar1 - local_200;
  *(undefined *)(local_1f8 + 0x10) = 0x54;
  local_1f0 = (void *)___swift_instantiateConcreteTypeFromMangledName
                                ((int *)&
                                        $$demangling_cache_variable_for_type_metadata_for_[Swift.UIn t8]
                                );
  Swift::Array<__int8>::$lazy_protocol_witness_table_accessor();
  AVar7 = (extension_Swift)::Swift::Collection::$map();
  puVar1 = local_208;
  local_258 = CONCAT44(extraout_var,AVar7);
  local_1e8 = iVar4;
  local_1e0 = local_258;
  if (iVar4 != 0) {
                    /* WARNING: Does not return */
    pcVar5 = (code *)SoftwareBreakpoint(1,0x10000965c);
    (*pcVar5)();
  }
  uVar12 = 1;
  local_268 = 1;
  local_60 = local_258;
  local_70 = (undefined *)Swift::DefaultStringInterpolation::init(1,1);
  DVar16.unknown = (undefined *)0x1;
  local_68 = uVar12;
  SVar19 = Swift::String::init("!",(__int16)local_268,1);
  local_260 = (undefined *)SVar19.bridgeObject;
  Swift::DefaultStringInterpolation::appendLiteral(SVar19,DVar16);
  EVar9.unknown = local_260;
  _swift_bridgeObjectRelease();
  local_250.unknown = (undefined *)&local_78;
  local_78 = local_258;
  Encoding::$get_utf8(EVar9);
  local_248 = Swift::Array<__int8>::$lazy_protocol_witness_table_accessor();
  EVar9.unknown = local_250.unknown;
  EVar13.unknown = local_150.unknown;
  (extension_Foundation)::Swift::String::$init(local_250);
  pcVar3 = local_180;
  SVar2.unknown = local_188.unknown;
  local_240 = EVar9.unknown;
  local_238 = EVar13.unknown;
  if (EVar13.unknown == (undefined *)0x0) {
    puVar1[-0x20] = 2;
    *(undefined8 *)(puVar1 + -0x18) = 0x1f;
    *(undefined4 *)(puVar1 + -0x10) = 0;
    Swift::_assertionFailure(SVar2,(StaticString)0xb,(StaticString)0x2,(uint)pcVar3,0x39);
                    /* WARNING: Does not return */
    pcVar5 = (code *)SoftwareBreakpoint(1,0x100008fa0);
    (*pcVar5)();
  }
  local_2c8 = &local_88;
  local_2b8 = &local_70;
  local_278 = EVar9.unknown;
  local_270 = EVar13.unknown;
  local_88 = EVar9.unknown;
  local_80 = EVar13.unknown;
  Swift::DefaultStringInterpolation::$appendInterpolation((char)local_2c8,local_190);
  $$outlined_destroy_of_Swift.String((int)local_2c8);
  DVar16.unknown = (undefined *)0x1;
  SVar19 = Swift::String::init("",0,1);
  local_2c0 = SVar19.bridgeObject;
  Swift::DefaultStringInterpolation::appendLiteral(SVar19,DVar16);
  _swift_bridgeObjectRelease(local_2c0);
  local_2a8.unknown = local_70;
  local_2b0 = local_68;
  _swift_bridgeObjectRetain();
  $$outlined_destroy_of_Swift.DefaultStringInterpolation((int)local_2b8);
  local_98 = Swift::String::init(local_2a8);
  local_288 = &local_98;
  Encoding::$get_utf8((Encoding)local_98.str);
  local_2a0 = Swift::String::$lazy_protocol_witness_table_accessor();
  uVar12 = (extension_Foundation)::Swift::StringProtocol::$data();
  dVar6 = (dword)uVar12 & 1;
  uVar14 = (uint)dVar6;
  EVar9.unknown = local_150.unknown;
  (extension_Foundation)::Swift::StringProtocol::$data(local_150,SUB41(dVar6,0));
  local_290 = *(code **)(local_160 + 8);
  local_298 = EVar9.unknown;
  local_280 = uVar14;
  (*local_290)(local_150.unknown,local_168);
  $$outlined_destroy_of_Swift.String((int)local_288);
  pcVar3 = local_180;
  SVar2.unknown = local_188.unknown;
  if ((local_280 & 0xf000000000000000) == 0xf000000000000000) {
    puVar1[-0x20] = 2;
    *(undefined8 *)(puVar1 + -0x18) = 0x1f;
    *(undefined4 *)(puVar1 + -0x10) = 0;
    Swift::_assertionFailure(SVar2,(StaticString)0xb,(StaticString)0x2,(uint)pcVar3,0x39);
                    /* WARNING: Does not return */
    pcVar5 = (code *)SoftwareBreakpoint(1,0x10000912c);
    (*pcVar5)();
  }
  local_2d8 = local_298;
  local_2d0 = local_280;
  local_300 = local_280;
  local_2f8 = local_298;
  local_a8 = local_298;
  local_a0 = local_280;
  local_b8 = Swift::String::init("hackallthethings",0x10,1);
  local_2e8 = &local_b8;
  Encoding::$get_utf8((Encoding)local_b8.str);
  uVar12 = (extension_Foundation)::Swift::StringProtocol::$data();
  uVar17 = SUB84(local_2a0,0);
  dVar6 = (dword)uVar12 & 1;
  uVar14 = (uint)dVar6;
  EVar9.unknown = local_150.unknown;
  (extension_Foundation)::Swift::StringProtocol::$data(local_150,SUB41(dVar6,0));
  local_2f0 = EVar9.unknown;
  local_2e0 = uVar14;
  (*local_290)(local_150.unknown,local_168);
  $$outlined_destroy_of_Swift.String((int)local_2e8);
  pcVar3 = local_180;
  SVar2.unknown = local_188.unknown;
  if ((local_2e0 & 0xf000000000000000) == 0xf000000000000000) {
    puVar1[-0x20] = 2;
    *(undefined8 *)(puVar1 + -0x18) = 0x20;
    *(undefined4 *)(puVar1 + -0x10) = 0;
    Swift::_assertionFailure(SVar2,(StaticString)0xb,(StaticString)0x2,(uint)pcVar3,0x39);
                    /* WARNING: Does not return */
    pcVar5 = (code *)SoftwareBreakpoint(1,0x100009248);
    (*pcVar5)();
  }
  local_310 = local_2f0;
  local_308 = local_2e0;
  local_330 = local_2e0;
  local_328 = local_2f0;
  local_c8 = local_2f0;
  local_c0 = local_2e0;
  $$default_argument_1_of_Foundation.Data.init(base64Encoded:___shared_Swift.String,options:___C.NSD ataBase64DecodingOptions)_->_Foundation.Data?
            ();
  pcVar10 = local_230.str;
  pvVar15 = local_230.bridgeObject;
  Foundation::Data::$init((NSDataBase64DecodingOptions)local_230.str);
  pcVar3 = local_180;
  SVar2.unknown = local_188.unknown;
  local_438 = local_1e8;
  local_320 = pcVar10;
  local_318 = pvVar15;
  if (((uint)pvVar15 & 0xf000000000000000) == 0xf000000000000000) {
    puVar1[-0x20] = 2;
    *(undefined8 *)(puVar1 + -0x18) = 0x21;
    *(undefined4 *)(puVar1 + -0x10) = 0;
    Swift::_assertionFailure(SVar2,(StaticString)0xb,(StaticString)0x2,(uint)pcVar3,0x39);
                    /* WARNING: Does not return */
    pcVar5 = (code *)SoftwareBreakpoint(1,0x1000092fc);
    (*pcVar5)();
  }
  local_3a0 = pvVar15;
  local_398 = pcVar10;
  local_340 = pcVar10;
  local_338 = pvVar15;
  local_d8 = pcVar10;
  local_d0 = pvVar15;
  this_00 = CryptoSwift::AES::typeMetadataAccessor();
  local_390 = this_00;
  AVar8 = (extension_CryptoSwift)::Foundation::Data::get_bytes(local_2f8,local_300);
  uVar12 = CONCAT44(extraout_var_00,AVar8);
  uVar14 = local_330;
  local_360 = uVar12;
  AVar8 = (extension_CryptoSwift)::Foundation::Data::get_bytes(local_328,local_330);
  local_388 = CryptoSwift::CBC::init(CONCAT44(extraout_var_01,AVar8));
  local_368 = local_100;
  local_e8 = &$$type_metadata_for_CryptoSwift.CBC;
  local_e0 = &$$protocol_witness_table_for_CryptoSwift.CBC_:_CryptoSwift.BlockMode_in_CryptoSwift;
  puVar11 = &DAT_10016d648;
  local_380 = uVar14;
  local_378 = uVar12;
  local_36c = uVar17;
  _swift_allocObject(&DAT_10016d648,0x29,7);
  *(undefined8 *)(puVar11 + 0x10) = local_388;
  *(uint *)(puVar11 + 0x18) = local_380;
  *(undefined8 *)(puVar11 + 0x20) = local_378;
  puVar11[0x28] = (byte)local_36c & 1;
  local_100[0] = puVar11;
  local_3c0 = CryptoSwift::AES::$__allocating_init(this_00,local_360,local_368,(AES)0x2);
  local_358 = local_438;
  local_348 = local_438;
  local_350 = local_3c0;
  if (local_438 == 0) {
    local_110 = local_3c0;
    AVar8 = (extension_CryptoSwift)::Foundation::Data::get_bytes(local_398,(uint)local_3a0);
    local_3b8 = CONCAT44(extraout_var_02,AVar8);
    local_3e8 = (extension_CryptoSwift)::CryptoSwift::Cipher::$decrypt
                          (local_3b8,local_390,0x10016dd08);
    local_3a8 = local_438;
    local_3b0 = local_3e8;
    _swift_bridgeObjectRelease(local_3b8);
    local_118 = local_3e8;
    _swift_bridgeObjectRetain();
    local_120 = local_3e8;
    pvVar15 = local_1f0;
    local_3e0.unknown = (undefined *)Foundation::Data::$init((char)&local_120);
    local_3d8 = pvVar15;
    local_130 = local_3e0.unknown;
    local_128 = pvVar15;
    Encoding::$get_utf8(local_3e0);
    EVar9.unknown = local_3e0.unknown;
    pvVar15 = local_3d8;
    (extension_Foundation)::Swift::String::$init(local_3e0);
    pcVar3 = local_180;
    SVar2.unknown = local_188.unknown;
    local_3d0 = EVar9.unknown;
    local_3c8 = pvVar15;
    if (pvVar15 == (void *)0x0) {
      puVar1[-0x20] = 2;
      *(undefined8 *)(puVar1 + -0x18) = 0x27;
      *(undefined4 *)(puVar1 + -0x10) = 0;
      Swift::_assertionFailure(SVar2,(StaticString)0xb,(StaticString)0x2,(uint)pcVar3,0x39);
                    /* WARNING: Does not return */
      pcVar5 = (code *)SoftwareBreakpoint(1,0x100009520);
      (*pcVar5)();
    }
    local_418 = EVar9.unknown;
    local_410 = pvVar15;
    local_3f8 = EVar9.unknown;
    local_3f0 = pvVar15;
    local_140 = EVar9.unknown;
    local_138 = pvVar15;
    outlined_consume(local_3e0.unknown,(uint)local_3d8);
    _swift_bridgeObjectRelease(local_3e8);
    _swift_release(local_3c0);
    outlined_consume(local_398,(uint)local_3a0);
    outlined_consume(local_328,local_330);
    outlined_consume(local_2f8,local_300);
    _swift_bridgeObjectRelease(local_258);
    _swift_bridgeObjectRelease(local_210);
    _swift_bridgeObjectRelease(local_230.bridgeObject);
    local_408 = local_418;
    local_400 = local_410;
  }
  else {
    local_430 = local_438;
    _swift_errorRetain();
    local_108 = local_430;
    _swift_errorRelease();
    _swift_errorRelease(local_430);
    local_428 = Swift::String::init("",0,1);
    outlined_consume(local_398,(uint)local_3a0);
    outlined_consume(local_328,local_330);
    outlined_consume(local_2f8,local_300);
    _swift_bridgeObjectRelease(local_258);
    _swift_bridgeObjectRelease(local_210);
    _swift_bridgeObjectRelease(local_230.bridgeObject);
    local_408 = local_428.str;
    local_400 = local_428.bridgeObject;
  }
  auVar18._8_8_ = local_400;
  auVar18._0_8_ = local_408;
  return auVar18;
}
```

Here's another function, called
**`is_noncompliant_device`**
```CPP
dword Captain_Nohook::is_noncompliant_device(void)

{
  dword dVar1;
  
  ReverseEngineeringToolsChecker::typeMetadataAccessor();
  dVar1 = ReverseEngineeringToolsChecker::amIReverseEngineered();
  return dVar1 & 1;
}
```
That call to **`amIReverseEngineered`** that we see **previously**.

We can see the **`viewDidLoad`** from **`ViewController`** class
```CPP
void __thiscall Captain_Nohook::ViewController::viewDidLoad(ViewController *this,int param_1)

{
  code *pcVar1;
  ViewController *pVVar2;
  ViewController *pVVar3;
  NSString *pNVar4;
  String SVar5;
  ViewController *local_38;
  ViewController *local_30;
  ViewController *local_28;
  ViewController *local_20;
  
  local_28 = this;
  local_20 = this;
  (**(code **)((*(uint *)this & *(uint *)PTR__swift_isaMask_10016d120) + 0x78))();
  if (param_1 == 0) {
    Swift::_assertionFailure
              ((StaticString)0x10015770a,(StaticString)0xb,(StaticString)0x2,0x100156270,0x44);
                    /* WARNING: Does not return */
    pcVar1 = (code *)SoftwareBreakpoint(1,0x1000088b0);
    (*pcVar1)();
  }
  _objc_msgSend(param_1,"setHidden:",1);
  _objc_release(param_1);
  _objc_retain(this);
  local_30 = typeMetadataAccessor();
  local_38 = this;
  _objc_msgSendSuper2(&local_38,"viewDidLoad");
  pVVar2 = this;
  _objc_release();
  _disable_gdb();
  (**(code **)((*(uint *)this & *(uint *)PTR__swift_isaMask_10016d120) + 0x60))();
  if (pVVar2 == (ViewController *)0x0) {
    Swift::_assertionFailure
              ((StaticString)0x10015770a,(StaticString)0xb,(StaticString)0x2,0x100156270,0x44);
                    /* WARNING: Does not return */
    pcVar1 = (code *)SoftwareBreakpoint(1,0x10000899c);
    (*pcVar1)();
  }
  pVVar3 = pVVar2;
  _objc_msgSend(pVVar2,"titleLabel");
  _objc_retainAutoreleasedReturnValue();
  _objc_release(pVVar2);
  if (pVVar3 != (ViewController *)0x0) {
    SVar5 = Swift::String::init("Flag \'ere!",10,1);
    pNVar4 = (extension_Foundation)::Swift::String::_bridgeToObjectiveC();
    _swift_bridgeObjectRelease(SVar5.bridgeObject);
    _objc_msgSend(pVVar3,"setText:",pNVar4);
    _objc_release(pNVar4);
    _objc_release(pVVar3);
  }
  return;
}
```

And also, **`whereIsFlag`** function
```CPP
void __thiscall Captain_Nohook::ViewController::whereIsflag(ViewController *this,UIButton *param_1)

{
  undefined *puVar1;
  ViewController *pVVar2;
  StaticString SVar3;
  char *pcVar4;
  code *pcVar5;
  int iVar6;
  UIButton *pUVar7;
  Configuration CVar8;
  Configuration *pCVar9;
  AttributedString.conflict AVar10;
  Configuration *pCVar11;
  AttributedString *pAVar12;
  int extraout_x8;
  undefined *apuStack_150 [4];
  Configuration local_130;
  code *local_128;
  AttributedString *local_120;
  dword local_118;
  dword local_114;
  UIButton *local_110;
  dword local_104;
  UIButton *local_100;
  Configuration *local_f8;
  NSString *local_f0;
  UIButton *local_e8;
  UIButton *local_e0;
  UIButton *local_d8;
  ViewController *local_d0;
  StaticString local_c8;
  char *local_c0;
  char *local_b8;
  undefined *local_b0;
  uint local_a8;
  CharacterView local_a0;
  UIButton *local_98;
  uint local_90;
  undefined *local_88;
  uint local_80;
  uint *local_78;
  Configuration *local_70;
  UIButton *local_68;
  String local_60;
  undefined auStack_50 [32];
  ViewController *local_30;
  UIButton *local_28;
  ViewController *local_20;
  
  local_78 = (uint *)PTR__swift_isaMask_10016d120;
  local_c8.unknown = "Fatal error";
  local_c0 = "Unexpectedly found nil while implicitly unwrapping an Optional value";
  local_b8 = "Captain_Nohook/ViewController.swift";
  local_28 = (UIButton *)0x0;
  local_30 = (ViewController *)0x0;
  local_d0 = this;
  local_98 = param_1;
  local_20 = this;
  local_b0 = (undefined *)Foundation::AttributedString::CharacterView::typeMetadataAccessor();
  local_a8 = *(int *)(*(int *)(local_b0 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  puVar1 = (undefined *)((int)&local_130 - local_a8);
  local_a0.unknown = puVar1;
  iVar6 = ___swift_instantiateConcreteTypeFromMangledName
                    ((int *)&
                            $$demangling_cache_variable_for_type_metadata_for_(extension_in_UIKit):_ _C.UIButton.Configuration?
                    );
  local_90 = *(int *)(*(int *)(iVar6 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  pUVar7 = local_98;
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  puVar1 = puVar1 + -local_90;
  local_80 = extraout_x8 + 0xfU & 0xfffffffffffffff0;
  local_88 = puVar1;
  (*(code *)PTR____chkstk_darwin_10016c2b0)();
  pCVar9 = (Configuration *)(puVar1 + -local_80);
  pCVar11 = pCVar9;
  local_70 = pCVar9;
  local_30 = this;
  local_28 = pUVar7;
  (**(code **)((*(uint *)this & *local_78) + 0x78))();
  pcVar4 = local_c0;
  SVar3.unknown = local_c8.unknown;
  local_68 = pUVar7;
  if (pUVar7 == (UIButton *)0x0) {
    *(undefined *)&pCVar9[-4].unknown = 2;
    pCVar9[-3].unknown = (undefined *)0x30;
    *(undefined4 *)&pCVar9[-2].unknown = 0;
    Swift::_assertionFailure(SVar3,(StaticString)0xb,(StaticString)0x2,(uint)pcVar4,0x44);
                    /* WARNING: Does not return */
    pcVar5 = (code *)SoftwareBreakpoint(1,0x10000a018);
    (*pcVar5)();
  }
  local_e8 = pUVar7;
  local_d8 = pUVar7;
  (**(code **)((*(uint *)local_d0 & *local_78) + 0x90))();
  pVVar2 = local_d0;
  local_f8 = pCVar11;
  local_f0 = (extension_Foundation)::Swift::String::_bridgeToObjectiveC();
  _swift_bridgeObjectRelease(local_f8);
  _objc_msgSend(local_e8,"setText:",local_f0);
  _objc_release(local_f0);
  pUVar7 = local_e8;
  _objc_release();
  (**(code **)((*(uint *)pVVar2 & *local_78) + 0x78))();
  pcVar4 = local_c0;
  SVar3.unknown = local_c8.unknown;
  local_e0 = pUVar7;
  if (pUVar7 == (UIButton *)0x0) {
    *(undefined *)&pCVar9[-4].unknown = 2;
    pCVar9[-3].unknown = (undefined *)0x31;
    *(undefined4 *)&pCVar9[-2].unknown = 0;
    Swift::_assertionFailure(SVar3,(StaticString)0xb,(StaticString)0x2,(uint)pcVar4,0x44);
                    /* WARNING: Does not return */
    pcVar5 = (code *)SoftwareBreakpoint(1,0x10000a108);
    (*pcVar5)();
  }
  local_110 = pUVar7;
  local_100 = pUVar7;
  _objc_msgSend(pUVar7,"isHidden");
  local_104 = (dword)pUVar7;
  _objc_release(local_110);
  if ((local_104 & 1) == 0) {
    (extension_UIKit)::__C::UIButton::$get_configuration((UIButton *)(uint)local_104);
    CVar8 = Configuration::$typeMetadataAccessor();
    pAVar12 = (AttributedString *)0x1;
    pCVar9 = local_70;
    (**(code **)(*(int *)(CVar8.unknown + -8) + 0x30))();
    pUVar7 = local_98;
    local_114 = (dword)((sdword)pCVar9 == 0);
    if (local_114 == 0) {
      $$outlined_init_with_copy_of_(extension_in_UIKit):__C.UIButton.Configuration?
                (local_70,local_88);
      (extension_UIKit)::__C::UIButton::$set_configuration(pUVar7);
      $$outlined_destroy_of_(extension_in_UIKit):__C.UIButton.Configuration?(local_70);
    }
    else {
      pcVar5 = (code *)auStack_50;
      Configuration::$modify_attributedTitle(local_70);
      local_128 = pcVar5;
      local_120 = pAVar12;
      AVar10 = Foundation::AttributedString::typeMetadataAccessor();
      pAVar12 = local_120;
      (**(code **)(*(int *)(AVar10.unknown + -8) + 0x30))(local_120,1);
      pUVar7 = local_98;
      local_118 = (dword)((sdword)pAVar12 == 0);
      if (local_118 == 0) {
        (*local_128)(auStack_50,0);
        $$outlined_init_with_copy_of_(extension_in_UIKit):__C.UIButton.Configuration?
                  (local_70,local_88);
        (extension_UIKit)::__C::UIButton::$set_configuration(pUVar7);
        $$outlined_destroy_of_(extension_in_UIKit):__C.UIButton.Configuration?(local_70);
      }
      else {
        local_60 = Swift::String::init("Arrr, find yerr hidden flag here!",0x21,1);
        local_130.unknown = (undefined *)&local_60;
        Foundation::AttributedString::CharacterView::$lazy_protocol_witness_table_accessor();
        (extension_Swift)::Swift::RangeReplaceableCollection::$init((char)local_130.unknown);
        Foundation::AttributedString::set_characters(local_120,local_a0);
        pUVar7 = local_98;
        (*local_128)(auStack_50,0);
        (extension_UIKit)::__C::UIButton::$set_configuration(pUVar7);
      }
    }
  }
  return;
}
```

There are a **lot of functions**.
In fact, in my case, as I use a **rootless device**, Idk if some checks like *ports, gdb, etc* affect to me.
Anyways, I try bypass all the mechanism as a possible.
First, we need **understand the flow**, what *check* is first **triggered**, what is called, from where, etc.

With **`frida-trace`** tool we can inspect what functions is called if we press the *blue button*
```bash
frida-trace -U -f "com.mobilehackinglab.Captain-Nohook.YX4C7J2RLK" -i "*hook*"
```

Output:
```bash
1. $s14Captain_Nohook14ViewControllerC11whereIsflagyySo8UIButtonCF()
2. $s14Captain_Nohook14ViewControllerC4flagSo7UILabelCSgvg()
3. $s14Captain_Nohook14ViewControllerC7getFlagSSyF()
4. $s14Captain_Nohook22is_noncompliant_deviceSbyF()
5. $s14Captain_Nohook30ReverseEngineeringToolsCheckerCMa()
6. $s14Captain_Nohook30ReverseEngineeringToolsCheckerC20amIReverseEngineeredSbyFZ()
7. $s14Captain_Nohook11FailedCheckOMa()
8. $s14Captain_Nohook11FailedCheckO8allCasesSayACGvgZ()
9. $s14Captain_Nohook11FailedCheckOMa()
10. $s14Captain_Nohook11FailedCheckOMa()
11. $s14Captain_Nohook11FailedCheckOMa()
12. $s14Captain_Nohook30ReverseEngineeringToolsCheckerC0cdE6StatusV6passed12failedChecksAESb_SayAA11FailedCheckO5check_SS11failMessagetGtcfC()
13. $s14Captain_Nohook14ViewControllerC4flagSo7UILabelCSgvg()
```

But anyway, here's more function that are called at the start
```bash
$s14Captain_Nohook22is_noncompliant_deviceSbyF
$s14Captain_Nohook30ReverseEngineeringToolsCheckerC20amIReverseEngineeredSbyFZ
$s14Captain_Nohook30ReverseEngineeringToolsCheckerC16checkOpenedPortsSSyF
$s14Captain_Nohook30ReverseEngineeringToolsCheckerC6checkDYLDSSyF
$s14Captain_Nohook30ReverseEngineeringToolsCheckerC32checkExistenceOfSuspiciousFilesSSyF
```

These functions **check if the device is jailbroken**, if there are *suspicious processes running and if there are files or libraries related to Frida or other debugger tools*.
How we can bypass it?
We **hook all these functions and force their return to `false` or `0`**, so that they always pass the checks.

**Flag 'ere!** button interaction
When the user presses the button to get the flag, the function is called:
```bash
$s14Captain_Nohook14ViewControllerC11whereIsflagyySo8UIButtonCF
```
This function *probably* evaluates whether **all checks were successful before displaying the flag**.

Let's make some bypasses.

## Initial Analysis

1. Anti-debugging protection (`_disable_gdb`)
2. Detection of reversing tools (`amIReverseEngineered`)
3. Check for suspicious files (`checkExistenceOfSuspiciousFiles`)
4. Open ports check (`checkOpenedPorts`)
5. DYLD Injection Detection (`checkDYLD`)
6. App integrity validation (`is_noncompliant_device`)
7. Checking process permissions (`PSelect Flag`) (`checkPSelectFlag`)
8. Running `getFlag()`: It had to be intercepted to get the actual flag.

After obtaining the list of functions using Frida (`frida-trace`) and `Radare2` (`r2frida`), we proceeded to exploit each check.

For example, with **`r2frida`** we can *bypass* the first button.
```bash
r2 'frida://spawn/usb//com.mobilehackinglab.Captain-Nohook.YX4C7J2RLK'
```

```bash
[0x100fc7e24]> :di0 `:iE~+is_noncompliant_device[0]`
[0x100fc7e24]> :di1 `:iE~+amIReverseEngineered[0]`
[0x100fc7e24]> :dc

Click in Flag 'ere! button

INFO: resumed spawned process
[0x100fc7e24]> Intercept return for 0x100fc9180 with 0
```

Also, we can enumerate the *real name function* of `getFlag`
`:iE~+getFlag`
Output:
```bash
0x1044d8ac0 f $s14Captain_Nohook14ViewControllerC7getFlagSSyF
0x1046303c0 v $s14Captain_Nohook14ViewControllerC7getFlagSSyFTq
```

## Bypass
The app uses `_disable_gdb` to detect debuggers.
We patch it in Frida to prevent it from terminating the process:
```javascript
Interceptor.replace(Module.findExportByName(null, "ptrace"),
  new NativeCallback(() => 0, 'int', ['int', 'int', 'pointer', 'pointer']));
```

`is_noncompliant_device()`
The` is_noncompliant_device()` function checked *if the app was running* in a “*modified*” environment (*jailbreak*, *Frida*, etc.).
We replaced it with:
```javascript
var isNoncompliant = Module.findExportByName(null, "$s14Captain_Nohook22is_noncompliant_deviceSbyF");
if (isNoncompliant) {
    Interceptor.replace(isNoncompliant, new NativeCallback(() => {
        console.log("[+] Bypass is_noncompliant_device executed!");
        return 0;
    }, 'int', []));
}
```

`amIReverseEngineered()`
The `amIReverseEngineered()` function *attempted to detect reversing tools*.
It was overwritten to **always return false**:
```javascript
var reverseEngineered = Module.findExportByName(null, "$s14Captain_Nohook30ReverseEngineeringToolsCheckerC20amIReverseEngineeredSbyFZ");
if (reverseEngineered) {
    Interceptor.replace(reverseEngineered, new NativeCallback(() => {
        console.log("[+] Bypass amIReverseEngineered executed!");
        return 0;
    }, 'int', []));
}
```

`checkExistenceOfSuspiciousFiles()`
This function **checked files on the system related to tools like Frida**.
We hooked `fopen()` to always return `/dev/null` when *looking for “suspicious” files*:
```javascript
var fopen = Module.findExportByName(null, "fopen");
Interceptor.attach(fopen, {
    onEnter(args) {
        var path = args[0].readCString();
        if (path.includes("frida") || path.includes("gadget")) {
            this.fake = Memory.allocUtf8String("/dev/null");
            args[0] = this.fake;
        }
    }
});
```

`checkOpenedPorts()`
`checkOpenedPorts()` was trying to **detect suspicious connections on specific ports**.
We replaced it *with a function that always returns a “safe” value*:
```javascript
var checkOpenedPorts = Module.findExportByName(null, "$s14Captain_Nohook30ReverseEngineeringToolsCheckerC16checkOpenedPortsSSyF");
if (checkOpenedPorts) {
    Interceptor.replace(checkOpenedPorts, new NativeCallback(() => {
        console.log("[+] Bypass checkOpenedPorts executed!");
        return 0;
    }, 'int', []));
}
```

`checkDYLD()`
`checkDYLD()` checked if the **app had been manipulated** with `DYLD_INSERT_LIBRARIES`.
It was replaced to *always return false*:
```javascript
var checkDYLD = Module.findExportByName(null, "$s14Captain_Nohook30ReverseEngineeringToolsCheckerC6checkDYLDSSyF");
if (checkDYLD) {
    Interceptor.replace(checkDYLD, new NativeCallback(() => {
        console.log("[+] Bypass checkDYLD executed!");
        return 0;
    }, 'int', []));
}
```

`checkPSelectFlag()`
`checkPSelectFlag()` checked **process permissions**.
It was *forced to return false* to **avoid detections**:
```javascript
var checkPSelectFlag = Module.findExportByName(null, "$s14Captain_Nohook30ReverseEngineeringToolsCheckerC32checkExistenceOfSuspiciousFilesSSyF");
if (checkPSelectFlag) {
    Interceptor.replace(checkPSelectFlag, new NativeCallback(() => {
        console.log("[+] Bypass checkPSelectFlag executed!");
        return 0;
    }, 'int', []));
}
```

## Intercepting `getFlag()` and Extracting the Flag
Initially, `getFlag()` returned `nil` (https://stackoverflow.com/questions/24043589/null-nil-in-swift), indicating **that the flag was stored in the UI instead of being returned directly**.
Instead of **just hooking the function**, we **captured the `UILabel` that displayed it**.

Intercepting `whereIsflag()` and **capturing the flag in the UI**:
```javascript
var whereIsFlag = Module.findExportByName(null, "$s14Captain_Nohook14ViewControllerC11whereIsflagyySo8UIButtonCF");
if (whereIsFlag) {
    Interceptor.attach(whereIsFlag, {
        onEnter(args) {
            console.log("[+] whereIsflag() called... Getting context.");
            try {
                var rootVC = ObjC.classes.UIApplication.sharedApplication().keyWindow().rootViewController();
                var subviews = rootVC.view().subviews();
                for (var i = 0; i < subviews.count(); i++) {
                    var view = subviews.objectAtIndex_(i);
                    if (view.$className === "UILabel") {
                        var flag = view.text().toString();
                        console.log(`[++] UILabel Found: ${flag}`);
                    }
                }
            } catch (e) {
                console.log(`[X] Error capturing UILabel: ${e.message}`);
            }
        }
    });
}
```

After > 20 scripts
![[noHook2.png]]
And dealing with `nil`

The full script
```javascript
console.log("[+] Starting definitive bypass...");

// 1 **Bypass main protections**
const bypassMainChecks = () => {
    const symbols = [
        "$s14Captain_Nohook22is_noncompliant_deviceSbyF",
        "$s14Captain_Nohook30ReverseEngineeringToolsCheckerC20amIReverseEngineeredSbyFZ",
        "$s14Captain_Nohook30ReverseEngineeringToolsCheckerC16checkOpenedPortsSSyF",
        "$s14Captain_Nohook30ReverseEngineeringToolsCheckerC6checkDYLDSSyF",
        "$s14Captain_Nohook30ReverseEngineeringToolsCheckerC32checkExistenceOfSuspiciousFilesSSyF"
    ];

    symbols.forEach(symbol => {
        const address = Module.findExportByName(null, symbol);
        if (address) {
            Interceptor.replace(address, new NativeCallback(() => {
                console.log(`[+] Bypassed: ${symbol}`);
                return 0;
            }, 'int', []));
        }
    });
};

// 2 **Intercept `whereIsflag()` to see what it is doing with the flag**
const hookWhereIsFlag = () => {
    const whereIsflag = Module.findExportByName(null, "$s14Captain_Nohook14ViewControllerC11whereIsflagyySo8UIButtonCF");

    if (whereIsflag) {
        Interceptor.attach(whereIsflag, {
            onEnter(args) {
                console.log("[+] whereIsflag() called... Capturing context.");

                // Look for the label where the flag should be
                try {
                    let vc = ObjC.classes.UIApplication.sharedApplication()
                        .keyWindow()
                        .rootViewController();

                    let views = vc.view().subviews();
                    for (let i = 0; i < views.count(); i++) {
                        let view = views.objectAtIndex_(i);
                        if (view.isKindOfClass_(ObjC.classes.UILabel)) {
                            console.log(`[Label found: ${view.text().toString()}`);
                        }
                    }
                } catch (e) {
                    console.log("[X] Could not read the flag in UI: " + e.message);
                }
            }
        });
    }
};

// 3 **Hook `getFlag()` to manually modify its return**
const hookGetFlag = () => {
    const getFlag = Module.findExportByName(null, "$s14Captain_Nohook14ViewControllerC7getFlagSSyF");

    if (getFlag) {
        Interceptor.attach(getFlag, {
            onEnter(args) {
                console.log("[+] Intercepting getFlag()...");
            },
            onLeave(retval) {
                try {
                    if (retval.isNull()) {
                        console.log("[X] The returned flag is `nil`. Exploring UI...");

                        // Look for the flag in the UI labels
                        let vc = ObjC.classes.UIApplication.sharedApplication()
                            .keyWindow()
                            .rootViewController();

                        let views = vc.view().subviews();
                        for (let i = 0; i < views.count(); i++) {
                            let view = views.objectAtIndex_(i);
                            if (view.isKindOfClass_(ObjC.classes.UILabel)) {
                                let labelText = view.text().toString();
                                console.log(`[Label found: ${labelText}`);

                                if (labelText.includes("FLAG{")) {
                                    console.log(`[FLAG CAPTURED: ${labelText}`);
                                    retval.replace(ObjC.classes.NSString.stringWithString_(labelText));
                                    return;
                                }
                            }
                        }
                    } else {
                        const flagString = new ObjC.Object(retval).toString();
                        console.log(`[Flag decrypted: ${flagString}`);

                        // Modify the return for debugging
                        retval.replace(ObjC.classes.NSString.stringWithString_("FLAG{HACKED_SUCCESSFULLY}"));
                    }
                } catch (e) {
                    console.log(`[X] Error obtaining the flag: ${e.message}`);
                }
            }
        });
    }
};

// 4 **Additional bypasses**
const additionalHooks = () => {
    Interceptor.replace(Module.findExportByName(null, "ptrace"),
        new NativeCallback(() => 0, 'int', ['int', 'int', 'pointer', 'pointer']));

    const fopen = Module.findExportByName(null, "fopen");
    Interceptor.attach(fopen, {
        onEnter(args) {
            const path = args[0].readCString();
            if (path.includes("frida") || path.includes("gadget")) {
                this.fake = Memory.allocUtf8String("/dev/null");
                args[0] = this.fake;
            }
        }
    });
};

// Execute all hooks
bypassMainChecks();
hookWhereIsFlag();
hookGetFlag();
additionalHooks();


console.log("[✔] All hooks installed. Press two times the button for get the flag!");
```

I can get the flag:
```bash
frida -U "Captain Nohook" -l yesHook.js
```

```bash
Attaching...
[+] Starting definitive bypass...
[✔] All hooks installed. Press two times the button for get the flag!
[iPhone::Captain Nohook ]-> [+] whereIsflag() called... Capturing context.
[Label found:
[+] Intercepting getFlag()...
[+] Bypassed: $s14Captain_Nohook22is_noncompliant_deviceSbyF
[Flag decrypted: nil
[+] whereIsflag() called... Capturing context.
[Label found: MHL{H00k_1n_Y0ur_D3bUgg3r}

[+] Intercepting getFlag()...
[+] Bypassed: $s14Captain_Nohook22is_noncompliant_deviceSbyF
[Flag decrypted: nil
```

Flag: **`MHL{H00k_1n_Y0ur_D3bUgg3r}`**

I hope you found it useful (: