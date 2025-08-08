Download **IPA**: https://lautarovculic.com/my_files/fbfe8ecef4b5f97c40687fd02f74ae009277538490fba314e61830d75b3b4ac5
**Password**: infected

![[laby2016_lastchance1.png]]

When you extract the file, we'll have the **.ipa** file, and the `LastChance_Simulator.app` folder.
Inside of this folder we have the `LastChance` executable.
```bash
file LastChance

LastChance: Mach-O 64-bit x86_64 executable, flags <NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

We can use **ghidra** for inspect this binary.
After load, we have the **entry point**.

But, we can search for some **functions or hardcoded strings**.
I found some interesting **strings**.
![[laby2016_lastchance2.png]]

Let's found where is used.
Taking a look at the **right** of the string, we can see **one reference**
![[laby2016_lastchance3.png]]

Click on the **XREF** and we can see this function that is calling to the **flag**
![[laby2016_lastchance4.png]]
And here is the code of **our interest**
```C
void __TFC10LastChance14ViewController9WinWindowfSiT_(undefined8 param_1,undefined8 param_2)
[...]
[...]
[...]
__TTSg5Vs5UInt8___TFs27_allocateUninitializedArrayurFBwTGSax_Bp_(0x1b);
  puVar13 = auVar15._8_8_;
  *puVar13 = 0x50;
  puVar13[1] = 0x41;
  puVar13[2] = 0x4e;
  puVar13[3] = 0x7b;
  puVar13[4] = 0x45;
  puVar13[5] = 0x5a;
  puVar13[6] = 0x45;
  puVar13[7] = 0x5f;
  puVar13[8] = 0x53;
  puVar13[9] = 0x34;
  puVar13[10] = 0x31;
  puVar13[0xb] = 100;
  puVar13[0xc] = 0x5f;
  puVar13[0xd] = 0x54;
  puVar13[0xe] = 0x68;
  puVar13[0xf] = 0x31;
  puVar13[0x10] = 0x35;
  puVar13[0x11] = 0x5f;
  puVar13[0x12] = 0x77;
  puVar13[0x13] = 0x34;
  puVar13[0x14] = 0x73;
  puVar13[0x15] = 0x5f;
  puVar13[0x16] = 0x45;
  puVar13[0x17] = 0x61;
  puVar13[0x18] = 0x35;
  puVar13[0x19] = 0x79;
  puVar13[0x1a] = 0x7d;
  
[...]
[...]
[...]
```

There are some **hexadecimal** values.
`0x500x410x4e0x7b0x450x5a0x450x5f0x530x340x310x640x5f0x540x680x310x350x5f0x770x340x730x5f0x450x610x350x790x7d`

If we **convert** this, we get the **flag**
```bash
echo -n '0x500x410x4e0x7b0x450x5a0x450x5f0x530x340x310x640x5f0x540x680x310x350x5f0x770x340x730x5f0x450x610x350x790x7d' | sed 's/0x//g' | xxd -r -p
```

**`PAN{EZE_S41d_Th15_w4s_Ea5y}`**

I hope you found it useful (: