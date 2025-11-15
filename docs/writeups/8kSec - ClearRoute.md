---
title: 8kSec - ClearRoute
description: "ClearRoute is an iOS app designed to test your ability to intercept sensitive data without getting caught."
tags:
  - obj-c
  - network
  - proxy
  - frida
  - rev-binaries
  - 8ksec
  - ios
keywords:
  - ios hacking
  - ctf writeup
  - 8ksec
  - mobile writeups
  - ios reversing
  - ios exploitation
  - mobile security research
canonical: https://lautarovculic.github.io/writeups/8kSec%20-%20ClearRoute/
---

**Description**: ClearRoute is an iOS app designed to test your ability to intercept sensitive data without getting caught.

**Link**: https://academy.8ksec.io/course/ios-application-exploitation-challenges

![[8ksec-clearRoute1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Recon
We can see that we have a *button* that **Send Secure Data** and, in green, the **status text**.

And the challenge is clear with the objective, we need **intercept the information that is transmitted**.

Inside of `Payload/ClearRoute.app` we have the **`ClearRoute.debug.dylib`** file library.

Also, the binary **`ClearRoute`**. But first, let's check the *debug library*.

Let's *import* into **Ghidra** and start **analyze the source code** looking for *interesting functions*.

The first that we need to check is **`isProxyEnabled()`**.

This Swift function returns a **boolean value**:
```C
  local_30 = (undefined *)0x0;
  local_70 = (char *)0x0;
  local_68 = (void *)0x0;
  _CFNetworkCopySystemProxySettings();
  if (param_1.unknown == (undefined *)0x0) {
    local_a0 = (undefined *)0x0;
  }
  else {
    (*(code *)PTR__objc_retain_00010090)();
    (*(code *)PTR__objc_retain_00010090)(param_1.unknown);
    (*(code *)PTR__objc_release_00010088)(param_1.unknown);
    (*(code *)PTR__objc_release_00010088)(param_1.unknown);
    local_a0 = param_1.unknown;
  }
  if (local_a0 == (undefined *)0x0) {
    local_d8.unknown = (undefined *)0x0;
  }
  else {
    ___swift_instantiateConcreteTypeFromMangledName();
    (*(code *)PTR__objc_retain_00010090)(local_a0);
    Swift::Dictionary<>::$lazy_protocol_witness_table_accessor();
    Swift::$_conditionallyBridgeFromObjectiveC_bridgeable();
    (*(code *)PTR__objc_release_00010088)(local_a0);
    (*(code *)PTR__objc_release_00010088)(local_a0);
    if (local_88 == (undefined *)0x0) {
      local_d0 = (undefined *)0x0;
    }
    else {
      local_d0 = local_88;
    }
    local_d8.unknown = local_d0;
  }
  if (local_d8.unknown != (undefined *)0x0) {
    local_30 = local_d8.unknown;
    local_60 = Swift::String::init("HTTPProxy",9,1);
    Swift::Dictionary::$get_subscript((char)&local_60,local_d8);
    $$outlined_destroy_of_Swift.String(&local_60);
    if (local_38 == 0) {
      $$outlined_destroy_of_Any?(auStack_50);
      local_118 = (char *)0x0;
      local_110 = (void *)0x0;
    }
    else {
      ppcVar3 = &local_80;
      _swift_dynamicCast(ppcVar3,auStack_50,PTR_$$type_metadata_for_Any_00010550 + 8,
                         PTR_$$type_metadata_for_Swift.String_000103f8,6);
      if (((uint)ppcVar3 & 1) == 0) {
        local_108 = (char *)0x0;
        local_100 = (void *)0x0;
      }
      else {
        local_108 = local_80;
        local_100 = local_78;
      }
      local_118 = local_108;
      local_110 = local_100;
    }
    if (local_110 != (void *)0x0) {
      SVar1.bridgeObject = local_110;
      SVar1.str = local_118;
      local_70 = local_118;
      local_68 = local_110;
      bVar2 = Swift::String::get_isEmpty(SVar1);
      _swift_bridgeObjectRelease(local_110);
      _swift_bridgeObjectRelease(local_d8.unknown);
      return !bVar2;
    }
    _swift_bridgeObjectRelease(local_d8.unknown);
  }
  return false;
```

We will not work with proxies like burpsuite or mitmproxy. So, *we never will set up a manual proxy in the Wi-Fi settings*. A great bypass sometimes is just go with the wind.

In Swift, it **bridge `CFNetworkCopySystemProxySettings()`** then looks up the key "*HTTPProxy*" in the dictionary and returns `true` if it is not empty (`Sdtring::get_isEmpty`).

Another *important function* is **`checkForProxyAndSend()`**.

This function If `isProxyEnabled()==true`, set the *status/UI* to “Some Error Occurred, Please Try again” and **don’t send**. If `false`, set “Request Successful.” and call **`sendSensitiveRequest()`**.

But the **most important is `sendSensitiveRequest()`**:
```C
  iVar12 = *(int *)PTR____stack_chk_guard_000100c8;
  local_78 = (String)ZEXT816(0);
  local_88 = (String)ZEXT816(0);
  local_98 = (String)ZEXT816(0);
  local_a8 = (String)ZEXT816(0);
  local_b8 = (String)ZEXT816(0);
  local_d0 = (char *)0x0;
  local_c8 = (void *)0x0;
  local_d8 = (undefined *)0x0;
  UVar4 = Foundation::URLRequest::typeMetadataAccessor();
  iVar13 = *(int *)(UVar4.unknown + -8);
  iVar14 = *(int *)(iVar13 + 0x40);
  (*(code *)PTR____chkstk_darwin_000100b8)();
  pUVar1 = local_360 + -(iVar14 + 0xfU & 0xfffffffffffffff0);
  (*(code *)PTR____chkstk_darwin_000100b8)();
  this = pUVar1 + -(extraout_x8 + 0xfU & 0xfffffffffffffff0);
  puVar8 = &$$demangling_cache_variable_for_type_metadata_for_Foundation.URL?;
  ___swift_instantiateConcreteTypeFromMangledName();
  iVar14 = *(int *)(*(int *)(puVar8 + -8) + 0x40);
  (*(code *)PTR____chkstk_darwin_000100b8)(0);
  iVar14 = (int)this - (iVar14 + 0xfU & 0xfffffffffffffff0);
  UVar5 = Foundation::URL::typeMetadataAccessor();
  iVar15 = *(int *)(UVar5.unknown + -8);
  iVar16 = *(int *)(iVar15 + 0x40);
  (*(code *)PTR____chkstk_darwin_000100b8)();
  url.unknown = (undefined *)(iVar14 - (iVar16 + 0xfU & 0xfffffffffffffff0));
  (*(code *)PTR____chkstk_darwin_000100b8)();
  iVar16 = (int)url.unknown - (extraout_x8_00 + 0xfU & 0xfffffffffffffff0);
  SVar17 = Swift::String::init("https://8ksec.io/blog",0x15,1);
  Foundation::URL::$init();
  _swift_bridgeObjectRelease(SVar17.bridgeObject);
  iVar6 = iVar14;
  (**(code **)(iVar15 + 0x30))(iVar14,1,UVar5.unknown);
  if ((sdword)iVar6 == 1) {
    *(undefined *)(iVar16 + -0x20) = 2;
    *(undefined8 *)(iVar16 + -0x18) = 0x3e;
    *(undefined4 *)(iVar16 + -0x10) = 0;
    Swift::_assertionFailure((StaticString)0xefda,(StaticString)0xb,(StaticString)0x2,0xefa0,0x39);
                    /* WARNING: Does not return */
    pcVar2 = (code *)SoftwareBreakpoint(1,0x6b78);
    (*pcVar2)();
  }
  (**(code **)(iVar15 + 0x20))(iVar16,iVar14,UVar5.unknown);
  UVar7.unknown = url.unknown;
  (**(code **)(iVar15 + 0x10))(url.unknown,iVar16,UVar5.unknown);
  $$default_argument_1_of_Foundation.URLRequest.init(url:_Foundation.URL,cachePolicy:___C.NSURLReque stCachePolicy,timeoutInterval:_Swift.Double)_->_Foundation.URLRequest
            ();
  local_2d8.unknown = UVar7.unknown;
  $$default_argument_2_of_Foundation.URLRequest.init(url:_Foundation.URL,cachePolicy:___C.NSURLReque stCachePolicy,timeoutInterval:_Swift.Double)_->_Foundation.URLRequest
            ();
  Foundation::URLRequest::init(url,local_2d8,in_d0);
  local_248 = 4;
  local_22c = 1;
  Swift::String::init("POST",4,1);
  Foundation::URLRequest::$set_httpMethod(this);
  local_250 = 2;
  local_2d0 = Swift::String::init("8k",2,(byte)local_22c & 1);
  local_78 = local_2d0;
  local_2c0 = Swift::String::init("sec",3,(byte)local_22c & 1);
  local_88 = local_2c0;
  local_2b0 = Swift::String::init("_int",(__int16)local_248,(byte)local_22c & 1);
  local_98 = local_2b0;
  local_2a0 = Swift::String::init("er",(__int16)local_250,(byte)local_22c & 1);
  local_a8 = local_2a0;
  local_288 = Swift::String::init("cepted",6,(byte)local_22c & 1);
  local_210 = PTR_$$type_metadata_for_Swift.String_000103f8;
  local_b8 = local_288;
  tVar18 = Swift::$_allocateUninitializedArray(5);
  local_278 = (undefined8 *)tVar18.1;
  local_290 = tVar18._0_8_;
  _swift_bridgeObjectRetain(local_2d0.bridgeObject);
  *local_278 = local_2d0.str;
  local_278[1] = local_2d0.bridgeObject;
  _swift_bridgeObjectRetain(local_2c0.bridgeObject);
  local_278[2] = local_2c0.str;
  local_278[3] = local_2c0.bridgeObject;
  _swift_bridgeObjectRetain(local_2b0.bridgeObject);
  local_278[4] = local_2b0.str;
  local_278[5] = local_2b0.bridgeObject;
  _swift_bridgeObjectRetain(local_2a0.bridgeObject);
  local_278[6] = local_2a0.str;
  local_278[7] = local_2a0.bridgeObject;
  _swift_bridgeObjectRetain(local_288.bridgeObject);
  local_278[8] = local_288.str;
  local_278[9] = local_288.bridgeObject;
  AVar3 = Swift::$_finalizeUninitializedArray((Array<undefined>)local_290);
  local_c0 = CONCAT44(extraout_var,AVar3);
  local_258 = &local_c0;
  pcVar11 = &$$demangling_cache_variable_for_type_metadata_for_[Swift.String];
  ___swift_instantiateConcreteTypeFromMangledName();
  local_270 = pcVar11;
  Swift::Array<String>::$lazy_protocol_witness_table_accessor();
  SVar17.bridgeObject = pcVar11;
  SVar17.str = local_270;
  local_268 = pcVar11;
  SVar17 = (extension_Swift)::Swift::BidirectionalCollection::$joined(SVar17);
  local_260 = SVar17.bridgeObject;
  local_240 = (extension_Swift)::Swift::BidirectionalCollection::$joined(SVar17);
  _swift_bridgeObjectRelease(local_260);
  $$outlined_destroy_of_[Swift.String](local_258);
  local_d0 = local_240.str;
  local_c8 = local_240.bridgeObject;
  puVar8 = &$$demangling_cache_variable_for_type_metadata_for_(Swift.String,Any);
  ___swift_instantiateConcreteTypeFromMangledName();
  local_218 = puVar8;
  tVar18 = Swift::$_allocateUninitializedArray((__int16)local_250);
  local_228 = (String *)tVar18.1;
  local_220 = tVar18._0_8_;
  SVar17 = Swift::String::init("user",(__int16)local_248,(byte)local_22c & 1);
  *local_228 = SVar17;
  SVar17 = Swift::String::init("john_doe",8,(byte)local_22c & 1);
  local_228[2].bridgeObject = local_210;
  local_228[1] = SVar17;
  _swift_bridgeObjectRetain(local_240.bridgeObject);
  local_228[3].str = local_240.str;
  local_228[3].bridgeObject = local_240.bridgeObject;
  SVar17 = Swift::String::init("CTF{no_proxies_allowed}",0x17,(byte)local_22c & 1);
  local_228[5].bridgeObject = local_210;
  local_228[4] = SVar17;
  Swift::$_finalizeUninitializedArray((Array<undefined>)local_220);
  local_208 = PTR_$$type_metadata_for_Any_00010550 + 8;
  local_200 = PTR_$$protocol_witness_table_for_Swift.String_:_Swift.Hashable_in_Swift_00010400;
  local_1f8 = (undefined *)Swift::Dictionary::$init();
  local_1f0 = 0;
  puVar8 = &_OBJC_CLASS_$_NSJSONSerialization;
  local_d8 = local_1f8;
  _objc_opt_self();
  local_1e0 = puVar8;
  _swift_bridgeObjectRetain(local_1f8);
  local_1d0 = (extension_Foundation)::Swift::Dictionary::_bridgeToObjectiveC();
  _swift_bridgeObjectRelease(local_1f8);
  __C::NSJSONWritingOptions::typeMetadataAccessor();
  tVar18 = Swift::$_allocateUninitializedArray((__int16)local_1f0);
  local_1e8 = tVar18._0_8_;
  __C::NSJSONWritingOptions::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::SetAlgebra::$init();
  local_e8 = 0;
  pcVar11 = "dataWithJSONObject:options:error:";
  puVar8 = local_1e0;
  _objc_msgSend(local_1e0,"dataWithJSONObject:options:error:",local_1d0,local_e0,&local_e8);
  _objc_retainAutoreleasedReturnValue();
  local_1d8 = local_e8;
  local_1c8.unknown = puVar8;
  (*(code *)PTR__objc_retain_00010090)();
  uVar10 = local_1d8;
  (*(code *)PTR__objc_release_00010088)(0);
  _swift_unknownObjectRelease(local_1d0);
  if (local_1c8.unknown != (undefined *)0x0) {
    local_2e0 = local_1c8.unknown;
    local_348 = local_1c8.unknown;
    local_2f8 = (undefined *)Foundation::Data::$_unconditionallyBridgeFromObjectiveC(local_1c8);
    local_2f0 = pcVar11;
    (*(code *)PTR__objc_release_00010088)(local_348);
    local_33c = 1;
    SVar17 = Swift::String::init("application/json",0x10,1);
    local_328 = SVar17.bridgeObject;
    local_338 = SVar17.str;
    SVar17 = Swift::String::init("Content-Type",0xc,(byte)local_33c & 1);
    local_330 = SVar17.bridgeObject;
    SVar19.bridgeObject = local_328;
    SVar19.str = local_338;
    Foundation::URLRequest::$setValue(SVar19,(URLRequest.conflict)SVar17.str);
    _swift_bridgeObjectRelease(local_330);
    _swift_bridgeObjectRelease(local_328);
    outlined_copy((_Representation)(__int8)local_2f8);
    Foundation::URLRequest::$set_httpBody(this);
    puVar8 = &_OBJC_CLASS_$_NSURLSession;
    _objc_opt_self();
    _objc_msgSend();
    _objc_retainAutoreleasedReturnValue();
    UVar9.unknown = pUVar1;
    local_308 = puVar8;
    (**(code **)(iVar13 + 0x10))(pUVar1,this,UVar4.unknown);
    local_310 = Foundation::URLRequest::_bridgeToObjectiveC(UVar9);
    local_2e8 = *(code **)(iVar13 + 8);
    (*local_2e8)(pUVar1,UVar4.unknown);
    $$outlined_retain_of_ClearRoute.ContentView(unaff_x20);
    puVar8 = &DAT_00010668;
    _swift_allocObject(&DAT_00010668,0x38,7);
    local_320 = puVar8;
    _memcpy(puVar8 + 0x10,unaff_x20,0x28);
    local_f8 = 
    $$partial_apply_forwarder_for_closure_#1_@Sendable_(Foundation.Data?,__C.NSURLResponse?,Swift.Er ror?)_->_()_in_ClearRoute.ContentView.sendSensitiveRequest()_->_()
    ;
    local_f0 = local_320;
    local_118 = PTR___NSConcreteStackBlock_000100b0;
    local_110 = 0x42000000;
    local_10c = 0;
    local_108 = 
    $$reabstraction_thunk_helper_from_@escaping_@callee_guaranteed_@Sendable_(@guaranteed_Foundation .Data?,@guaranteed___C.NSURLResponse?,@guaranteed_Swift.Error?)_->_()_to_@escaping_@callee_unown ed_@convention(block)_@Sendable_(@unowned___C.NSData?,@unowned___C.NSURLResponse?,@unowned___C.N SError?)_->_()
    ;
    local_100 = &_block_descriptor;
    local_318 = __Block_copy(&local_118);
    _swift_release(local_f0);
    puVar8 = local_308;
    _objc_msgSend(local_308,"dataTaskWithRequest:completionHandler:",local_310,local_318);
    _objc_retainAutoreleasedReturnValue();
    local_300 = puVar8;
    __Block_release(local_318);
    (*(code *)PTR__objc_release_00010088)(local_310);
    (*(code *)PTR__objc_release_00010088)(local_308);
    _objc_msgSend(local_300,"resume");
    (*(code *)PTR__objc_release_00010088)(local_300);
    outlined_consume((_Representation)(__int8)local_2f8);
    _swift_bridgeObjectRelease(local_1f8);
    _swift_bridgeObjectRelease(local_240.bridgeObject);
    _swift_bridgeObjectRelease(local_288.bridgeObject);
    _swift_bridgeObjectRelease(local_2a0.bridgeObject);
    _swift_bridgeObjectRelease(local_2b0.bridgeObject);
    _swift_bridgeObjectRelease(local_2c0.bridgeObject);
    _swift_bridgeObjectRelease(local_2d0.bridgeObject);
    (*local_2e8)(this,UVar4.unknown);
    (**(code **)(iVar15 + 8))(iVar16,UVar5.unknown);
    if (*(int *)PTR____stack_chk_guard_000100c8 - iVar12 != 0) {
                    /* WARNING: Subroutine does not return */
      ___stack_chk_fail(*(int *)PTR____stack_chk_guard_000100c8 - iVar12);
    }
    return;
  }
  local_358 = uVar10;
  Foundation::$_convertNSErrorToError();
  local_350 = uVar10;
  (*(code *)PTR__objc_release_00010088)(local_358);
  _swift_willThrow();
  _swift_unexpectedError(local_350,"ClearRoute/ContentView.swift",0x1c,1,0x50);
                    /* WARNING: Does not return */
  pcVar2 = (code *)SoftwareBreakpoint(1,0x75ec);
  (*pcVar2)();
```

Here's the request *is crafted*:

- URL: https://8ksec.io/blog

- Method: **POST**, header *`Content-Type: application/json`*

- Key: *concatenate* "**`8k`**"+"**`sec`**"+" **`_int`**"+"**`er`**"+"**`cepted`**" → "`8ksec_intercepted`"

- JSON: `{ "user": "john_doe", "8ksec_intercepted": "CTF{no_proxies_allowed}" }`

- **Serializes** with `+[NSJSONSerialization dataWithJSONObject:options:error:]`, does **`setHTTPBody`**, creates `-[NSURLSession dataTaskWithRequest:completionHandler:]` and *resume*.

And there are a **closure**:

- `void $$closure_#1_@Sendable_(Foundation.Data?,__C.NSURLResponse?,Swift.Error?)_->_()_in_ClearRoute.C ontentView.sendSensitiveRequest()_->_()`

This It's the **handler for `dataTaskWithRequest`**. It *dispatches to the main queue* using `DispatchQueue.main.async` to *update state/UI*.

Basically, the *chain we can reconstruct is the following*:

`isProxyEnabled()` (Swift) → if *no proxy*, call `sendSensitiveRequest()` → assemble *JSON* with `NSJSONSerialization` → `setHTTPBody` → `NSURLSession dataTask... resume`.
### Solution
So, we can **hook** this function:

`+[NSJSONSerialization dataWithJSONObject:options:error:]` → See the *dictionary before serializing*.

We can use this **Frida script**:
```javascript
(function () {
  if (!ObjC.available) { console.log('ObjC no available'); return; }

  const NSJSON = ObjC.classes.NSJSONSerialization;
  Interceptor.attach(NSJSON['+ dataWithJSONObject:options:error:'].implementation, {
    onEnter(args) {
      try {
	// NSDictionary
        const dict = new ObjC.Object(args[2]);
	// set the string into the object
        const flag = dict.objectForKey_('8ksec_intercepted');
        if (flag && flag.toString && flag.toString() !== '0x0') {
          console.log('[FLAG] ' + flag.toString());
        }
      } catch (e) { console.log('NSJSON err: ' + e); }
    }
  });
})();
```

Then, run the frida command:
```bash
frida -U -n ClearRoute -l NSJSONSerialization-hook.js
```
Output:
```bash
     ____
    / _  |   Frida 17.2.17 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iPhone (id=666eb5ebad136366b2085d7ef60c978ce95eec2d)

[iPhone::ClearRoute ]-> [FLAG] CTF{no_proxies_allowed}
```

For the **full capture**, we can *hook the most important functions for complete the challenge*:
```javascript
// iOS / Frida 17.x
// Hook NSURLSession to read the HTTPBody when creating the task.
// + fallback: setHTTPBody and NSJSONSerialization

(function () {
  function log(m){ try{ console.log(m); }catch(_){} }

  if (!ObjC.available) { log('ObjC no available'); return; }

  // Dump at the exact moment of creating the task
  try {
    const NSURLSession = ObjC.classes.NSURLSession;
    // instance: - dataTaskWithRequest:completionHandler:
    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
      onEnter(args) {
        try {
          const req = new ObjC.Object(args[2]);        // NSURLRequest*
          const body = req.HTTPBody();                 // NSData*
          if (body && body.toString() !== '0x0') {
            const s = ObjC.classes.NSString
              .alloc()
              .initWithData_encoding_(body, 4)        // UTF-8
              .toString();
            log('HTTPBody @ dataTaskWithRequest:\n' + s);
          } else {
            log('HTTPBody empty or nil');
          }
        } catch (e) { log('NSURLSession hook err: ' + e); }
      }
    });
    log('---hooked--- -[NSURLSession dataTaskWithRequest:completionHandler:]');
  } catch (e) { log('cant hook' + e); }

  // fallback: when setting the body in the request (Mutable)
  try {
    const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    Interceptor.attach(NSMutableURLRequest['- setHTTPBody:'].implementation, {
      onEnter(args) {
        try {
          const data = new ObjC.Object(args[2]); // NSData*
          const s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4).toString();
          log('setHTTPBody captured:\n' + s);
        } catch (e) { log('setHTTPBody err: ' + e); }
      }
    });
    log('---hooked--- -[NSMutableURLRequest setHTTPBody:]');
  } catch (e) { log('cant hook setHTTPBody: ' + e); }

  // extra fallback: before serializing the JSON (look keys and flags)
  try {
    const NSJSONSerialization = ObjC.classes.NSJSONSerialization;
    Interceptor.attach(NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
      onEnter(args) {
        try {
          const dict = new ObjC.Object(args[2]); // NSDictionary*
          log('NSJSON input:\n' + dict.toString());
        } catch (e) { log('NSJSON err: ' + e); }
      }
    });
    log('---hooked--- +[NSJSONSerialization dataWithJSONObject:options:error:]');
  } catch (e) { log('cant hook NSJSONSerialization: ' + e); }
})();
```

Then run the command:
```bash
frida -U -n ClearRoute -l NSURLSession--NSMutableURLRequest--NSJSONSerialization-hook.js
```
Output:
```bash
     ____
    / _  |   Frida 17.2.17 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iPhone (id=666eb5ebad136366b2085d7ef60c978ce95eec2d)
Attaching...
---hooked--- -[NSURLSession dataTaskWithRequest:completionHandler:]
---hooked--- -[NSMutableURLRequest setHTTPBody:]
---hooked--- +[NSJSONSerialization dataWithJSONObject:options:error:]
[iPhone::ClearRoute ]-> NSJSON input:
{
    "8ksec_intercepted" = "CTF{no_proxies_allowed}";
    user = "john_doe";
}
setHTTPBody captured:
{"user":"john_doe","8ksec_intercepted":"CTF{no_proxies_allowed}"}
HTTPBody @ dataTaskWithRequest:
{"user":"john_doe","8ksec_intercepted":"CTF{no_proxies_allowed}"}
setHTTPBody captured:
```

- `+[NSJSONSerialization dataWithJSONObject:options:error:]` -> (JSON assembly)

- `-[NSMutableURLRequest setHTTPBody:]` -> (injection of the body to the request)

- `-[NSURLSession dataTaskWithRequest:completionHandler:]` -> (creation of the task with the final request).

**Flag**: **`CTF{no_proxies_allowed}`**

I hope you found it useful (:
