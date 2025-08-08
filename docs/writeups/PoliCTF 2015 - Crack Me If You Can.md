**Description**: John bets nobody can find the passphrase to login!
**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/crack-me-if-you-can.apk

![[crackMeIfYouCan1.png]]

Install the **apk** with **adb**
```bash
adb install -r crack-me-if-you-can.apk
```

Then, decompile it with **apktool**
```bash
apktool d crack-me-if-you-can.apk
```

We can see the source code with **jadx** (GUI version).
There are some activities so curious..
In fact, in the **MainActivity** (LoginActivity) we have an "**flag**" hardcoded.
`flagging{It_cannot_be_easier_than_this}`
But this is a **fake flag**.
So, let's keep reading the code.
Here we have an **a** method
```java
private boolean a(String str) {  
        if (!str.equals(c.a(b.a(b.b(b.c(b.d(b.g(b.h(b.e(b.f(b.i(c.c(c.b(c.d(getString(R.string.jadx_deobf_0x00000257)))))))))))))))) {  
            return false;  
        }  
        Toast.makeText(getApplicationContext(), getString(R.string.jadx_deobf_0x0000025b), 1).show();  
        return true;  
    }
```

Where, after some instructions, the string is `jadx_deobf_0x00000257` and `jadx_deobf_0x0000025b`

If we inspect the `res/values/strings.xml`, these strings in the method are:
```XML
<string name="jadx_deobf_0x00000257" formatted="false">[[c%l][c{g}[%{%Mc%spdgj=]T%aat%=O%bRu%sc]c%ti[o%n=Wcs%=No[t=T][hct%=buga[d=As%=W]e=T%ho[u%[%g]h%t[%}%</string>

<string name="jadx_deobf_0x0000025b">Good to go! =)</string>
```

So, we need the message **Good to go!**, then we need **input** the `[[c%l][c{g}[%{%Mc%spdgj=]T%aat%=O%bRu%sc]c%ti[o%n=Wcs%=No[t=T][hct%=buga[d=As%=W]e=T%ho[u%[%g]h%t[%}%` string in the **TextEdit**.

But, the string is **obfuscated**. So, looking more in the code, we can found classes like
`b`
```java
public class b {  
    public static String a(String str) {  
        return str.replace("c", "a");  
    }  
  
    public static String b(String str) {  
        return str.replace("%", "");  
    }  
  
    public static String c(String str) {  
        return str.replace("[", "");  
    }  
  
    public static String d(String str) {  
        return str.replace("]", "");  
    }  
  
    public static String e(String str) {  
        return str.replaceFirst("\\{", "");  
    }  
  
    public static String f(String str) {  
        return str.replaceFirst("\\}", "");  
    }  
  
    public static String g(String str) {  
        return str.replaceFirst("c", "f");  
    }  
  
    public static String h(String str) {  
        return str.replaceFirst("R", "f");  
    }  
  
    public static String i(String str) {  
        return str.replace("=", "_");  
    }  
}
```

And `c`
```java
package it.polictf2015;  
  
/* loaded from: classes.dex */  
public class c {  
    public static String a(String str) {  
        return str.replace("aa", "ca");  
    }  
  
    public static String b(String str) {  
        return str.replace("aat", "his");  
    }  
  
    public static String c(String str) {  
        return str.replace("buga", "Goo");  
    }  
  
    public static String d(String str) {  
        return str.replace("spdgj", "yb%e");  
    }  
}
```

So, we can use this information for craft an **python** script for make it more easy.
```python
def apply_transformations(text, transformations):
    for old, new, count in transformations:
        if count is None:
            text = text.replace(old, new)
        else:
            text = text.replace(old, new, count)
    return text

def transform_string(input_string):
    # Define transformations in order
    transformations = [
        # Transformations from class c
        ("spdgj", "yb%e", None),  # Replace "spdgj" with "yb%e"
        ("aat", "his", None),     # Replace "aat" with "his"
        ("buga", "Goo", None),    # Replace "buga" with "Goo"
        
        # Transformations from class b
        ("=", "_", None),         # Replace "=" with "_"
        ("}", "", 1),             # Remove the first "}"
        ("{", "", 1),             # Remove the first "{"
        ("R", "f", 1),            # Replace the first "R" with "f"
        ("c", "f", 1),            # Replace the first "c" with "f"
        ("]", "", None),          # Remove all "]"
        ("[", "", None),          # Remove all "["
        ("%", "", None),          # Remove all "%"
        ("c", "a", None),         # Replace all remaining "c" with "a"
        
        # Final transformation from class c
        ("aa", "ca", None),       # Replace "aa" with "ca"
    ]
    
    # Apply all transformations
    result = apply_transformations(input_string, transformations)
    
    return result

# Input string
input_string = '[[c%l][c{g}[%{%Mc%spdgj=]T%aat%=O%bRu%sc]c%ti[o%n=Wcs%=No[t=T][hct%=buga[d=As%=W]e=T%ho[u%[%g]h%t[%}%'

# Apply transformations and print the result
print(transform_string(input_string))
```

And then, the flag is `flag{Maybe_This_Obfuscation_Was_Not_That_Good_As_We_Thought}`
Put into the **TextEdit** and get the **Good to go! =)** message.


I hope you found it useful (: