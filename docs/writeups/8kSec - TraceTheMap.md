**Description**: TraceTheMap is an iOS location-based challenge where you must collect 5 hidden map markers scattered within a 1 km radius. Each collectible is worth 100 points and you need all 500 to win. Get within 50 meters of each collectible to score.

**Link**: https://academy.8ksec.io/course/ios-application-exploitation-challenges

![[8ksec-traceTheMap1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Recon
Inside the directory `Payload/TraceTheMap.app/` we have the `TraceTheMap.debug.dylib` file.

Let's import into **Ghidra** for know how the app work.

Inside, we can see some functions. First, the function:

- **`Array<Collectible> TraceTheMap::generateCollectibles(CLLocation *around,int count,double radius)`**

```C
[...]
[...]
[...]

  local_1a8.unknown = "Fatal error";
  local_1a0 = "Range requires lowerBound <= upperBound";
  local_198 = "Swift/arm64-apple-ios.swiftinterface";
  local_38 = 0;
  local_40 = (CLLocation *)0x0;
  local_48 = 0;
  local_50 = 0.0;
  local_58 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_a0 = 0;
  local_c0 = 0.0;
  local_e0 = 0.0;
  local_e8 = 0.0;
  local_100 = 0.0;
  local_130 = 0.0;
  local_128 = 0.0;
  local_188 = 0;
  local_190 = radius;
  local_160 = around;
  local_150 = count;
  CVar17 = Collectible::typeMetadataAccessor();
  local_178 = *(int *)(*(int *)(CVar17.title + -8) + 0x40);
  local_180 = local_178 + 0xfU & 0xfffffffffffffff0;
  uVar9 = local_188;
  dVar12 = local_190;
  (*(code *)PTR____chkstk_darwin_000180a0)(local_150,local_188,CVar17.title,CVar17._16_8_);
  _Var4 = (__int16)uVar9;
  iVar1 = -local_180;
  local_168 = local_178 + 0xfU & 0xfffffffffffffff0;
  local_170 = auStack_290 + iVar1;
  (*(code *)PTR____chkstk_darwin_000180a0)();
  iVar1 = (int)(auStack_290 + iVar1) - local_168;
  local_40 = local_160;
  local_158 = iVar1;
  local_50 = dVar12;
  local_38 = iVar1;
  tVar15 = Swift::$_allocateUninitializedArray(_Var4);
  pcVar8 = local_1a0;
  SVar2.unknown = local_1a8.unknown;
  local_58 = tVar15._0_8_;
  if (local_150 < 1) {
    *(undefined *)(iVar1 + -0x20) = 2;
    *(undefined **)(iVar1 + -0x18) = &DAT_000017ad;
    *(undefined4 *)(iVar1 + -0x10) = 0;
    Swift::_assertionFailure(SVar2,(StaticString)0xb,(StaticString)0x2,(uint)pcVar8,0x27);
                    /* WARNING: Does not return */
    pcVar3 = (code *)SoftwareBreakpoint(1,0xb5f8);
    (*pcVar3)();
  }
  local_88 = 1;
  local_80 = local_150;
  puVar6 = &$$demangling_cache_variable_for_type_metadata_for_Swift.ClosedRange<Swift.Int>;
  ___swift_instantiateConcreteTypeFromMangledName();
  local_1b0 = puVar6;
  Swift::ClosedRange<int>::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::Collection::$makeIterator();
  while( true ) {
    IVar7.unknown =
         &
         $$demangling_cache_variable_for_type_metadata_for_Swift.IndexingIterator<Swift.ClosedRange< Swift.Int>>
    ;
    ___swift_instantiateConcreteTypeFromMangledName();
    Swift::IndexingIterator::$next(IVar7);
    local_1b8 = local_98;
    if ((local_90 & 1) != 0) {
      local_288 = &local_58;
      local_280 = local_58;
      _swift_bridgeObjectRetain();
      $$outlined_destroy_of_[TraceTheMap.Collectible](local_288);
      return (Array<Collectible>)local_280;
    }
    local_1c0 = local_98;
    local_1e8 = local_98;
    local_a0 = local_98;
    local_1d8.unknown = (undefined *)&local_b8;
    local_b8 = 0;
    local_b0 = 0x4076800000000000;
    double::$lazy_protocol_witness_table_accessor();
    local_1e0 = IVar7.unknown;
    __int64::$lazy_protocol_witness_table_accessor();
    local_1d0 = IVar7.unknown;
    (extension_Swift)::Swift::BinaryFloatingPoint::$random(local_1d8);
    pcVar8 = local_1a0;
    SVar2.unknown = local_1a8.unknown;
    local_1c8 = local_a8;
    local_c0 = local_a8;
    if (local_190 < 100.0) break;
    local_d8 = 0x4059000000000000;
    local_d0 = local_190;
    puVar6 = local_1d0;
    (extension_Swift)::Swift::BinaryFloatingPoint::$random((ClosedRange<undefined>)&local_d8);
    local_278 = local_c8;
    local_e0 = local_c8;
    dVar12 = local_1c8;
    _cos();
    local_268 = 111000.0;
    local_250 = (local_278 * dVar12) / 111000.0;
    dVar12 = local_1c8;
    local_e8 = local_250;
    _sin();
    dVar11 = local_278 * dVar12;
    local_258 = 0x1c000;
    local_260 = dVar11;
    _objc_msgSend(local_160,"coordinate");
    local_270 = dVar11;
    local_f8 = dVar11;
    local_f0 = dVar12;
    dVar12 = double::get_pi(dVar11);
    dVar11 = (local_270 * dVar12) / 180.0;
    _cos();
    dVar11 = local_268 * dVar11;
    dVar13 = local_260 / dVar11;
    local_248 = dVar13;
    local_100 = dVar13;
    _objc_msgSend(local_160,*(undefined8 *)(local_258 + 0x570));
    dVar14 = dVar13 + local_250;
    dVar12 = local_250;
    local_200 = dVar14;
    local_110 = dVar13;
    local_108 = dVar11;
    _objc_msgSend(local_160,*(undefined8 *)(local_258 + 0x570));
    local_1f8 = dVar12 + local_248;
    local_130 = local_200;
    local_240 = 0xc;
    uVar9 = 1;
    local_128 = local_1f8;
    local_120 = dVar14;
    local_118 = dVar12;
    local_140 = (undefined *)Swift::DefaultStringInterpolation::init(0xc,1);
    local_220 = &local_140;
    local_22c = 1;
    DVar10.unknown = (undefined *)((int)&mach_header_00000000.magic + 1);
    local_138 = uVar9;
    SVar16 = Swift::String::init("Collectible ",(__int16)local_240,1);
    local_238 = SVar16.bridgeObject;
    Swift::DefaultStringInterpolation::appendLiteral(SVar16,DVar10);
    _swift_bridgeObjectRelease(local_238);
    local_148 = local_1e8;
    Swift::DefaultStringInterpolation::$appendInterpolation
              ((char)&local_148,
               (DefaultStringInterpolation)PTR_$$type_metadata_for_Swift.Int_000185b0);
    DVar10.unknown = (undefined *)(uint)(local_22c & 1);
    SVar16 = Swift::String::init("",0,(__int8)(local_22c & 1));
    local_228 = SVar16.bridgeObject;
    Swift::DefaultStringInterpolation::appendLiteral(SVar16,DVar10);
    _swift_bridgeObjectRelease(local_228);
    local_210.unknown = local_140;
    local_218 = local_138;
    _swift_bridgeObjectRetain();
    $$outlined_destroy_of_Swift.DefaultStringInterpolation(local_220);
    SVar16 = Swift::String::init(local_210);
    local_208 = SVar16.bridgeObject;
    pcVar8 = SVar16.str;
    local_1f0 = pcVar8;
    $$default_argument_2_of_TraceTheMap.Collectible.init(title:_Swift.String,coordinate:___C.CLLocat ionCoordinate2D,collected:_Swift.Bool)_->_TraceTheMap.Collectible
              ();
    coordinate.latitude = (double)(uint)((dword)pcVar8 & 1);
    SVar16.bridgeObject = local_208;
    SVar16.str = local_1f0;
    coordinate.longitude = (double)puVar6;
    CVar17 = Collectible::init(SVar16,coordinate,SUB81(in_x4,0));
    $$outlined_init_with_copy_of_TraceTheMap.Collectible(local_158,local_170,CVar17._16_8_);
    AVar5 = 0x1c728;
    ___swift_instantiateConcreteTypeFromMangledName();
    Swift::Array<undefined>::append((char)local_170,AVar5);
    $$outlined_destroy_of_TraceTheMap.Collectible(local_158);
  }
  *(undefined *)(iVar1 + -0x20) = 2;
  *(undefined **)(iVar1 + -0x18) = &DAT_000017ad;
  *(undefined4 *)(iVar1 + -0x10) = 0;
  Swift::_assertionFailure(SVar2,(StaticString)0xb,(StaticString)0x2,(uint)pcVar8,0x27);
                    /* WARNING: Does not return */
  pcVar3 = (code *)SoftwareBreakpoint(1,0xb740);
  (*pcVar3)();
```

The most important thing of this functions is:

- Use **`BinaryFloatingPoint.random(in:)`** twice:

- Angle in `[0, 360]`.

- Distance in `[100, radius]` (if **radius < 100**, `assert → crash`).

- Apply `trig(cos, sin)` and the approximation `111,000 m/degree` for **latitude**; adjust **longitude** by `cos(lat)` (factor with `π`, visible calls to `_sin/_cos` and the `deg↔rad` conversion).

- **Calculate coordinates from `around.coordinate`** and add annotations (via **`MKMapView.addAnnotation/setCoordinate:`**).

Conclusion: It is not feasible to "**lower**" the distance to 0 by editing the range without touching invariants; the range `[100, R]` is protected by a valid **`ClosedRange`**.

Anyway, this function doesn't important for complete the challenge, but is good to know.

One of the most **important** function is:

- **`void TraceTheMap::ContentView::checkProximity(CLLocation *to,ContentView param_2)`**

```C
  local_b8 = 0;
  local_b0 = 0;
  local_a8 = 0;
  local_110 = 0;
  local_178 = 0.0;
  CVar11 = Collectible::typeMetadataAccessor();
  pcVar3 = CVar11.title;
  iVar8 = *(int *)(*(int *)(pcVar3 + -8) + 0x40);
  (*(code *)PTR____chkstk_darwin_000180a0)(&local_170,to,CVar11.title.bridgeObject,CVar11._16_8_);
  iVar1 = -0x380 - (iVar8 + 0xfU & 0xfffffffffffffff0);
  (*(code *)PTR____chkstk_darwin_000180a0)();
  iVar8 = iVar1 - (iVar8 + 0xfU & 0xfffffffffffffff0);
  uVar9 = *(undefined8 *)(unaff_x20 + 0x18);
  *(undefined8 *)(extraout_x8 + 0x138) = *(undefined8 *)(unaff_x20 + 0x20);
  *(undefined8 *)(extraout_x8 + 0x130) = uVar9;
  $$outlined_retain_of_SwiftUI.State<>();
  $$outlined_retain_of_SwiftUI.State<>(&local_40);
  uStack_c8 = uStack_38;
  local_d0 = local_40;
  SVar4.unknown =
       &$$demangling_cache_variable_for_type_metadata_for_SwiftUI.State<[TraceTheMap.Collectible]>;
  ___swift_instantiateConcreteTypeFromMangledName();
  SwiftUI::State::get_wrappedValue(SVar4);
  $$outlined_destroy_of_SwiftUI.State<>(&local_d0);
  $$outlined_release_of_SwiftUI.State<>(&local_40);
  _swift_bridgeObjectRetain(local_c0);
  local_e8 = local_c0;
  ___swift_instantiateConcreteTypeFromMangledName();
  Swift::Array<>::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::RandomAccessCollection::$get_indices();
  $$outlined_destroy_of_[TraceTheMap.Collectible](&local_e8);
  _swift_bridgeObjectRelease(local_c0);
  local_f8 = local_e0;
  local_f0 = local_d8;
  ___swift_instantiateConcreteTypeFromMangledName();
  Swift::Range<int>::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::Collection::$makeIterator();
  while( true ) {
    do {
      do {
        IVar5.unknown =
             &
             $$demangling_cache_variable_for_type_metadata_for_Swift.IndexingIterator<Swift.Range<Sw ift.Int>>
        ;
        ___swift_instantiateConcreteTypeFromMangledName();
        Swift::IndexingIterator::$next(IVar5);
        local_298 = local_108;
        if ((local_100 & 1) != 0) {
          return;
        }
        local_2a0 = local_108;
        local_2b8 = local_108;
        local_110 = local_108;
        uStack_48 = *(undefined8 *)(unaff_x20 + 0x20);
        local_50 = *(undefined8 *)(unaff_x20 + 0x18);
        local_2c0 = &local_50;
        $$outlined_retain_of_SwiftUI.State<>();
        $$outlined_retain_of_SwiftUI.State<>(local_2c0);
        local_2c8 = &local_130;
        uStack_128 = uStack_48;
        local_130 = local_50;
        SwiftUI::State::get_wrappedValue(SVar4);
        $$outlined_destroy_of_SwiftUI.State<>(local_2c8);
        local_2b0 = local_118;
        $$outlined_release_of_SwiftUI.State<>(local_2c0);
        Swift::Array<undefined>::get_subscript(local_2b8,(Array<undefined>)local_2b0);
        local_2a4 = (dword)*(byte *)((int)&local_380 + *(sdword *)(pcVar3 + 0x1c) + iVar8 + 0x380);
        $$outlined_destroy_of_TraceTheMap.Collectible();
        _swift_bridgeObjectRelease(local_2b0);
      } while ((local_2a4 & 1) != 0);
      local_310 = __C::CLLocation::typeMetadataAccessor();
      uStack_58 = *(undefined8 *)(unaff_x20 + 0x20);
      local_60 = *(undefined8 *)(unaff_x20 + 0x18);
      local_318 = &local_60;
      $$outlined_retain_of_SwiftUI.State<>();
      $$outlined_retain_of_SwiftUI.State<>(local_318);
      local_320 = &local_150;
      uStack_148 = uStack_58;
      local_150 = local_60;
      SwiftUI::State::get_wrappedValue(SVar4);
      $$outlined_destroy_of_SwiftUI.State<>(local_320);
      local_2e0 = local_138;
      $$outlined_release_of_SwiftUI.State<>(local_318);
      Swift::Array<undefined>::get_subscript(local_2b8,(Array<undefined>)local_2e0);
      local_2f8 = *(double *)((int)&local_380 + *(sdword *)(pcVar3 + 0x18) + iVar8 + 0x380);
      $$outlined_destroy_of_TraceTheMap.Collectible();
      uStack_68 = *(undefined8 *)(unaff_x20 + 0x20);
      local_70 = *(undefined8 *)(unaff_x20 + 0x18);
      local_300 = &local_70;
      $$outlined_retain_of_SwiftUI.State<>();
      $$outlined_retain_of_SwiftUI.State<>(local_300);
      local_308 = &local_170;
      uStack_168 = uStack_68;
      local_170 = local_70;
      SwiftUI::State::get_wrappedValue(SVar4);
      this_00 = local_310;
      $$outlined_destroy_of_SwiftUI.State<>(local_308);
      local_2e8 = local_158;
      $$outlined_release_of_SwiftUI.State<>(local_300);
      Swift::Array<undefined>::get_subscript(local_2b8,(Array<undefined>)local_2e8);
      local_2f0 = *(double *)((int)&local_378 + *(sdword *)(pcVar3 + 0x18) + iVar1 + 0x380);
      $$outlined_destroy_of_TraceTheMap.Collectible();
      dVar10 = local_2f8;
      local_2d8 = __C::CLLocation::__allocating_init(this_00,local_2f8,local_2f0);
      _swift_bridgeObjectRelease(local_2e8);
      _swift_bridgeObjectRelease(local_2e0);
      _objc_msgSend(to,"distanceFromLocation:",local_2d8);
      local_2d0 = dVar10;
      (*(code *)PTR__objc_release_00018070)(local_2d8);
      local_178 = local_2d0;
    } while (50.0 <= local_2d0);
    uStack_78 = *(undefined8 *)(unaff_x20 + 0x20);
    local_80 = *(undefined **)(unaff_x20 + 0x18);
    local_348 = &local_80;
    $$outlined_retain_of_SwiftUI.State<>();
    $$outlined_retain_of_SwiftUI.State<>(local_348);
    uStack_188 = uStack_78;
    local_190 = local_80;
    local_368 = &local_190;
    local_370 = (Array<undefined> *)&local_180;
    SwiftUI::State::get_wrappedValue(SVar4);
    this = local_370;
    $$outlined_destroy_of_SwiftUI.State<>(local_368);
    pcVar2 = (code *)auStack_1b0;
    iVar7 = local_2b8;
    local_360 = pcVar2;
    Swift::Array<undefined>::modify_subscript(this,(int)pcVar2);
    *(undefined *)(iVar7 + *(sdword *)(pcVar3 + 0x1c)) = 1;
    (*pcVar2)(local_360,0);
    local_358 = local_180;
    $$outlined_retain_of_SwiftUI.State<>(local_348);
    uStack_1b8 = uStack_78;
    local_1c0.unknown = local_80;
    local_350 = &local_1c0;
    local_1c8 = local_358;
    SwiftUI::State::set_wrappedValue(local_350,(char)&local_1c8);
    $$outlined_destroy_of_SwiftUI.State<>(local_350);
    $$outlined_release_of_SwiftUI.State<>(local_348);
    uStack_88 = *(undefined8 *)(unaff_x20 + 0x30);
    local_90 = *(undefined **)(unaff_x20 + 0x28);
    local_340 = &local_90;
    $$outlined_retain_of_SwiftUI.State<Swift.Int>();
    $$outlined_retain_of_SwiftUI.State<Swift.Int>(local_340);
    uStack_1d8 = uStack_88;
    local_1e0 = local_90;
    local_330 = &local_1e0;
    SVar6.unknown = &$$demangling_cache_variable_for_type_metadata_for_SwiftUI.State<Swift.Int>;
    ___swift_instantiateConcreteTypeFromMangledName();
    local_338 = SVar6.unknown;
    SwiftUI::State::get_wrappedValue(SVar6);
    $$outlined_destroy_of_SwiftUI.State<Swift.Int>(local_330);
    local_328 = local_1d0 + 100;
    if (SCARRY8(local_1d0,100) != false) break;
    local_378 = &local_90;
    local_1d0 = local_328;
    $$outlined_retain_of_SwiftUI.State<Swift.Int>();
    uStack_1e8 = uStack_88;
    local_1f0.unknown = local_90;
    local_380 = &local_1f0;
    local_1f8 = local_328;
    SwiftUI::State::set_wrappedValue(local_380,(char)&local_1f8);
    $$outlined_destroy_of_SwiftUI.State<Swift.Int>(local_380);
    $$outlined_release_of_SwiftUI.State<Swift.Int>(local_378);
  }
                    /* WARNING: Does not return */
  pcVar2 = (code *)SoftwareBreakpoint(1,0x77d8);
  (*pcVar2)();
```

This function:

- Retrieves the `State<[Collectible]>` array.

- Iterates over indices (`Range<Int>`, `IndexingIterator`).

- For each uncollected Collectible:

	- **Constructs** **`CLLocation`** with the `lat/lon` of the collectible.

	- **Calculates** `to.distanceFromLocation(collectibleLoc)`.

	- If < 50.0:

		- `set_collected(true)` (setter of `Collectible.collected`).

		- Increment state score by +100 (`SwiftUI State<Int>`).

- When `score == 500` then show the Win UI.

Conclusion: The **`decision depends 100% on distanceFromLocation:`**. It's the perfect hook point.

So, let's explore the `locationManager` that `didUpdateLocations`:

- `void __thiscall TraceTheMap::LocationManager::locationManager(LocationManager *this,CLLocationManager *param_1,Array<CLLocation> didUpdateLocations)`

```C
  local_a0 = (uint)didUpdateLocations;
  local_28 = 0;
  local_30 = 0;
  local_38 = (LocationManager *)0x0;
  local_50 = 0;
  local_f0 = 0;
  local_f8 = this;
  local_c8 = param_1;
  local_20 = this;
  local_e8 = (undefined *)Dispatch::DispatchWorkItemFlags::typeMetadataAccessor();
  local_e0 = *(int *)(local_e8 + -8);
  local_d8 = *(int *)(local_e0 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_000180a0)(local_f0);
  iVar1 = (int)&local_120 - local_d8;
  local_d0 = iVar1;
  local_c0 = (undefined *)Dispatch::DispatchQoS::typeMetadataAccessor();
  local_b8 = *(int *)(local_c0 + -8);
  local_b0 = *(int *)(local_b8 + 0x40) + 0xfU & 0xfffffffffffffff0;
  uVar2 = local_a0;
  (*(code *)PTR____chkstk_darwin_000180a0)(local_c8);
  local_a8.unknown = (undefined *)(iVar1 - local_b0);
  local_38 = this;
  local_30 = uVar2;
  _swift_bridgeObjectRetain();
  local_90 = &local_48;
  local_48 = local_a0;
  puVar3 = &$$demangling_cache_variable_for_type_metadata_for_[__C.CLLocation];
  ___swift_instantiateConcreteTypeFromMangledName();
  local_98 = puVar3;
  Swift::Array<CLLocation>::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::BidirectionalCollection::$get_last();
  $$outlined_destroy_of_[__C.CLLocation](local_90);
  local_88 = local_40;
  if (local_40 != 0) {
    local_100 = local_40;
    local_108 = local_40;
    local_50 = local_40;
    local_120.unknown = (undefined *)0x0;
    pOVar4 = __C::OS_dispatch_queue::typeMetadataAccessor();
    local_110 = (extension_Dispatch)::__C::OS_dispatch_queue::get_main((OS_dispatch_queue *)pOVar4);
    (*(code *)PTR__objc_retain_00018078)(local_f8);
    (*(code *)PTR__objc_retain_00018078)(local_108);
    puVar3 = &DAT_00018b50;
    qos = &segment_command_00000020;
    _swift_allocObject(&DAT_00018b50,0x20,7);
    *(LocationManager **)(puVar3 + 0x10) = local_f8;
    *(int *)(puVar3 + 0x18) = local_108;
    local_60 = 
    $$partial_apply_forwarder_for_closure_#1_@Swift.MainActor_()_->_()_in_TraceTheMap.LocationManage r.locationManager(_:___C.CLLocationManager,didUpdateLocations:_[__C.CLLocation])_->_()
    ;
    local_80 = PTR___NSConcreteStackBlock_00018098;
    local_78 = 0x42000000;
    local_74 = 0;
    local_70 = 
    $$reabstraction_thunk_helper_from_@escaping_@callee_guaranteed_()_->_()_to_@escaping_@callee_uno wned_@convention(block)_()_->_()
    ;
    local_68 = &_block_descriptor;
    local_58 = puVar3;
    local_118 = __Block_copy(&local_80);
    group.unknown = local_58;
    _swift_release();
    (extension_Dispatch)::__C::OS_dispatch_queue::$async(group,(DispatchWorkItemFlags)qos);
    (extension_Dispatch)::__C::OS_dispatch_queue::$async(group,(DispatchWorkItemFlags)qos);
    (extension_Dispatch)::__C::OS_dispatch_queue::$async(local_120,local_a8);
    (**(code **)(local_e0 + 8))(local_d0,local_e8);
    (**(code **)(local_b8 + 8))(local_a8.unknown,local_c0);
    __Block_release(local_118);
    (*(code *)PTR__objc_release_00018070)(local_110);
    (*(code *)PTR__objc_release_00018070)(local_108);
  }
  return;
```

It takes the last **`CLLocation`** from the array (`BidirectionalCollection.get_last()`) and then It `'requeues'` it in main with `dispatch_async`.

From there, it updates the `Published<CLLocation?>` (`$userLocation.setter`), which triggers the **`checkProximity(to:)`** in the UI.
### Getting the Flags
So, let's hook **`-[CLLocation distanceFromLocation:]`**!!

I decide hook more "normal", because it's possible get all collectibles in one second.

So we limit the "**cheat**" to one **measurement per time window** and the **rest use the actual distance**.

Thus, a collectible falls for ~1.2s (or not, just **wait until got all the collectibles**):
```javascript
'use strict';
if (!ObjC.available) throw new Error('ObjC no disponible');

ObjC.schedule(ObjC.mainQueue, function () {
  const CLLocation = ObjC.classes.CLLocation;
  if (!CLLocation || !CLLocation['- distanceFromLocation:']) {
    console.log('CLLocation.distanceFromLocation not found');
    return;
  }

  const orig = new NativeFunction(
    CLLocation['- distanceFromLocation:'].implementation,
    'double', ['pointer','pointer','pointer']
  );

  // settings
  const PERIOD_MS = 1200;       // windows: 1 "grant" for ~1.2s
  const MIN_METERS = 6.0;       // min fake distance
  const MAX_METERS = 18.0;      // max fake distance

  let token = 1;                // 1 grant when init
  setInterval(() => { token = 1; }, PERIOD_MS);

  Interceptor.replace(
    CLLocation['- distanceFromLocation:'].implementation,
    new NativeCallback(function (self, _cmd, other) {
      if (token > 0) {
        token = 0;
        const val = MIN_METERS + Math.random() * (MAX_METERS - MIN_METERS);
        console.log(`grant ~${val.toFixed(1)}m`);
        return val;             // <50m
      }
      return orig(self, _cmd, other);
    }, 'double', ['pointer','pointer','pointer'])
  );

  console.log('farming flags');
});
```

So, run the Frida command:
```bash
frida -U -f com.8ksec.TraceTheMap -l getFlags.js
```

![[8ksec-traceTheMap2.png]]

I hope you found it useful (:
