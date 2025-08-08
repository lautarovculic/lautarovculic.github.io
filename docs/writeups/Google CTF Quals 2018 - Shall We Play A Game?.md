**Description**: Win the game 1,000,000 times to get the flag.

Download **APK**: https://lautarovculic.com/my_files/shallweplayagame.apk

![[shallweplayagame1.png]]

Install the **apk** with **adb**
```bash
adb install -r shallweplayagame.apk
```

It seems to be the game of **tic-tac-toe,** and we need `1,000,000` games **won** to **get the flag**.
If we lose, t*he application closes and the counter will return to 0*.

*Our intention will not be to win 1,000,000 games in a row*. But it will be winning `1,000,000` times in one play.
So let's read the source code to understand how the app works using **jadx** (GUI version)
But before, let's decompile the source code with **APKTool**
```bash
apktool d shallweplayagame.apk
```

The **package name** is `com.google.ctf.shallweplayagame` and there are just **one activity**, which is `com.google.ctf.shallweplayagame.GameActivity`.
But, there are **three classes** in the app, which is: `a()`, `b()` and `N()`.

Anyways, the most **valuable code** is here
```bash
void m() {
    Object _ = N._(0, N.a, 0);
    N._(0, N.c, _, 2, N._(1, N.b, this.q, 1));
    ((TextView) findViewById(R.id.score)).setText(new String((byte[]) N._(0, N.d, _, this.r)));
    o();
}

void n() {
    for (int i = 0; i < 3; i++) {
        for (int i2 = 0; i2 < 3; i2++) {
            this.l[i2][i].a(a.EnumC0032a.EMPTY, 25);
        }
    }
    k();
    this.o++;
    Object _ = N._(2, N.e, 2);
    N._(2, N.f, _, this.q);
    this.q = (byte[]) N._(2, N.g, _);
    
    if (this.o == 1000000) {
        m();
    } else {
        ((TextView) findViewById(R.id.score)).setText(String.format("%d / %d", Integer.valueOf(this.o), 1000000));
    }
}
```

Where **`m()`** show the **flag**.
**`this.o++;`** increase the *win counter*.
**`if (this.o == 1000000)`** checks if the *counter is 1,000,000*.

I have tried several ways, for example, *that the counter starts directly at 1,000,000* and I also tried to patch the code by modifying that *if we win, we jump to the `m()` function*.

But there was no success because *it makes a series of extra validations*.
And that's because **there is some sort of loop that must be executed 1,000,000 times**.

Then, we will need to **create a loop that tells the application that we have already won 1,000,000 times**.

We need **modify** the **`.smali`** file of **GameActivity**.
We can found that in
`shallweplayagame/smali/com/google/ctf/shallweplayagame`

And the code that we'll introduce/modify is in the `n()` method.
Which start in the **line code** number `666`.

Looking this value `0xf4240` in hex, which mean `1,000,000`.
Here's the **win counter**
![[shallweplayagame2.png]]

And here the **win check**
![[shallweplayagame3.png]]

In these section, we need add **a loop** which runs `1,000,000` times.

Go to the `.locals 10` line in the *top of the method* and change `10` by `11`. This is for add a *new local variable* unit.
Under `const/4 v6, 0x2` we need *initialize* the new variable (`v10`) to 0 (`0x0`).

After `add-int/lit8 v0, v0, 0x1` which is in `:cond_1`, add this instruction `move v0, v9`. This will move `1,000,000` in **win counter**.

Under the `iput` that is follow from the new code write, add
```smali
:goto_3 # New loop

if-ge v10, v9, :cond_3 # break condition, if v10 is 1,000,000

add-int/lit8 v10, v10, 0x1 # Increase counter of our new variable by 1
```

Must looks like
![[shallweplayagame4.png]]

Finally, let's go further down in the code, search for `iput-object v0, p0, Lcom/google/ctf/shallweplayagame/GameActivity;->q:[B`.

We'll add this two code lines
```smali
goto :goto_3

:cond_3
```

Look like
![[shallweplayagame5.png]]

The **entire `n()` methods is here**
```smali
.method n()V
    .locals 11 # Add new local variable

    const v9, 0xf4240

    const/4 v8, 0x1

    const/4 v7, 0x3

    const/4 v1, 0x0

    const/4 v6, 0x2

    const v10, 0x0 # Add new variable initialize to 0

    move v2, v1

    :goto_0
    if-ge v2, v7, :cond_1

    move v0, v1

    :goto_1
    if-ge v0, v7, :cond_0

    iget-object v3, p0, Lcom/google/ctf/shallweplayagame/GameActivity;->l:[[Lcom/google/ctf/shallweplayagame/a;

    aget-object v3, v3, v0

    aget-object v3, v3, v2

    sget-object v4, Lcom/google/ctf/shallweplayagame/a$a;->a:Lcom/google/ctf/shallweplayagame/a$a;

    const/16 v5, 0x19

    invoke-virtual {v3, v4, v5}, Lcom/google/ctf/shallweplayagame/a;->a(Lcom/google/ctf/shallweplayagame/a$a;I)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_0
    add-int/lit8 v0, v2, 0x1

    move v2, v0

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Lcom/google/ctf/shallweplayagame/GameActivity;->k()V

    iget v0, p0, Lcom/google/ctf/shallweplayagame/GameActivity;->o:I

    add-int/lit8 v0, v0, 0x1

    move v0, v9 # Move 1,000,000 in win counter

    iput v0, p0, Lcom/google/ctf/shallweplayagame/GameActivity;->o:I

    :goto_3 # New loop

    if-ge v10, v9, :cond_3 # break condition, if v10 is 1,000,000

    add-int/lit8 v10, v10, 0x1 # Increase counter of our new variable by 1

    new-array v0, v7, [Ljava/lang/Object;

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    aput-object v2, v0, v1

    sget-object v2, Lcom/google/ctf/shallweplayagame/N;->e:[I

    aput-object v2, v0, v8

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    aput-object v2, v0, v6

    invoke-static {v0}, Lcom/google/ctf/shallweplayagame/N;->_([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    const/4 v2, 0x4

    new-array v2, v2, [Ljava/lang/Object;

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    aput-object v3, v2, v1

    sget-object v3, Lcom/google/ctf/shallweplayagame/N;->f:[I

    aput-object v3, v2, v8

    aput-object v0, v2, v6

    iget-object v3, p0, Lcom/google/ctf/shallweplayagame/GameActivity;->q:[B

    aput-object v3, v2, v7

    invoke-static {v2}, Lcom/google/ctf/shallweplayagame/N;->_([Ljava/lang/Object;)Ljava/lang/Object;

    new-array v2, v7, [Ljava/lang/Object;

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    aput-object v3, v2, v1

    sget-object v3, Lcom/google/ctf/shallweplayagame/N;->g:[I

    aput-object v3, v2, v8

    aput-object v0, v2, v6

    invoke-static {v2}, Lcom/google/ctf/shallweplayagame/N;->_([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [B

    check-cast v0, [B

    iput-object v0, p0, Lcom/google/ctf/shallweplayagame/GameActivity;->q:[B

    goto :goto_3 # End of the loop, then, come back to goto_3 until v10 is 1,000,000

    :cond_3 # Break, come here if v10 is 1,000,000

    iget v0, p0, Lcom/google/ctf/shallweplayagame/GameActivity;->o:I

    if-ne v0, v9, :cond_2

    invoke-virtual {p0}, Lcom/google/ctf/shallweplayagame/GameActivity;->m()V

    :goto_2
    return-void

    :cond_2
    const v0, 0x7f070055

    invoke-virtual {p0, v0}, Lcom/google/ctf/shallweplayagame/GameActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/TextView;

    const-string v2, "%d / %d"

    new-array v3, v6, [Ljava/lang/Object;

    iget v4, p0, Lcom/google/ctf/shallweplayagame/GameActivity;->o:I

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    aput-object v4, v3, v1

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    aput-object v1, v3, v8

    invoke-static {v2, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    goto :goto_2
.end method
```

Now it's **rebuild time**!
With **APKTool**, build
```bash
apktool b shallweplayagame
```

Generate a *new key*
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

**Align** with *zipalign*
```bash
zipalign -v -p 4 shallweplayagame/dist/shallweplayagame.apk shallweplayagame-aligned.apk
```

Then, **sign** the apk
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore shallweplayagame-aligned.apk alias
```

Uninstall the *original apk* and then, install the new
```bash
adb install -r shallweplayagame-aligned.apk
```

When we run the application, and win the *first game*, it will *appear that the application has crashed*.
But **don't worry**, remember that it *must be run 1,000,000 times to win*.

*If Android tells us that the application is not responding, we will tell it to wait*.

We wait a few moments and **we will get the flag**.
![[shallweplayagame6.png]]

This flag is encoded with a technique that *removes secondary vowels from words*. Interpreting the content, it looks something like this:
“`CTF{TheLossOfInnocenceIsThePriceOfApplause}`”
That is:
“**The Loss Of Innocence Is The Price Of Applause**”.

I hope you found it useful (: