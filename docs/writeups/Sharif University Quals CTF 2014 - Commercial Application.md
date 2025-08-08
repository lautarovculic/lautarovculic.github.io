**Category**: Crypto
**Description**: Flag is a serial number.

**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/suCTF.apk

![[commercialApplication1.png]]

Install the **apk** with **adb**
```bash
adb install -r suCTF.apk
```

Decompile this with **apktool**
```bash
apktool d suCTF.apk
```
And now we can inspect the **source code** with **jadx**
But, first at all, let's take a look to the app.

We have a list of **3 pictures**.
The first **picture** is "free".
But, the **picture 2** and **3**, we need insert a **Product Key**
![[commercialApplication2.png]]
Okey, now let's get in action with the **source code**

The **package name** is `edu.sharif.ctf`
And the launcher activity is **MainActivity**.
This is the code (**reduced**)
```java
public class MainActivity extends SherlockFragmentActivity implements ListFragment.OnPictureSelectedListener {
    public static final String NOK_LICENCE_MSG = "Your licence key is incorrect...! Please try again with another.";
    public static final String OK_LICENCE_MSG = "Thank you, Your application has full licence. Enjoy it...!";
    public static boolean isRegisterd = false;
    private ActionBar actionBar;
    private CTFApplication app;
    private ViewPager viewPager;
    FragmentTransaction fragTransactMgr = null;
    private final String CAPTION1 = "ListView";
    private final String CAPTION2 = "GridView";
    private final String CAPTION3 = "ImageView";
    private ViewPager.SimpleOnPageChangeListener onPageChangeListener = new ViewPager.SimpleOnPageChangeListener() {
        @Override
        public void onPageSelected(int position) {
            super.onPageSelected(position);
            MainActivity.this.actionBar.setSelectedNavigationItem(position);
        }
    };
    private ActionBar.TabListener tabListener = new ActionBar.TabListener() {
        @Override
        public void onTabSelected(ActionBar.Tab tab, FragmentTransaction ft) {
            MainActivity.this.viewPager.setCurrentItem(tab.getPosition());
        }

        @Override
        public void onTabUnselected(ActionBar.Tab tab, FragmentTransaction ft) {
        }

        @Override
        public void onTabReselected(ActionBar.Tab tab, FragmentTransaction ft) {
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0084R.layout.activity_main);
        this.viewPager = (ViewPager) findViewById(C0084R.id.pager);
        this.viewPager.setOnPageChangeListener(this.onPageChangeListener);
        this.viewPager.setAdapter(new ViewPagerAdapter(getSupportFragmentManager()));
        this.fragTransactMgr = getSupportFragmentManager().beginTransaction();
        addActionBarTabs();
        this.app = (CTFApplication) getApplication();
    }

    private void addActionBarTabs() {
        this.actionBar = getSupportActionBar();
        this.actionBar.addTab(this.actionBar.newTab().setIcon(C0084R.drawable.ic_4_collections_view_as_list).setTabListener(this.tabListener));
        this.actionBar.addTab(this.actionBar.newTab().setIcon(C0084R.drawable.ic_5_content_picture).setTabListener(this.tabListener));
        this.actionBar.setNavigationMode(2);
    }

    public void executeFragment(SherlockFragment fragment) {
        try {
            this.viewPager.removeAllViews();
            this.fragTransactMgr.addToBackStack(null);
            this.fragTransactMgr = getSupportFragmentManager().beginTransaction();
            this.fragTransactMgr.add(this.viewPager.getId(), fragment);
            this.fragTransactMgr.commit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getSupportMenuInflater();
        inflater.inflate(C0084R.menu.main, menu);
        ShareActionProvider sap = (ShareActionProvider) menu.findItem(C0084R.id.share).getActionProvider();
        Intent intent = new Intent("android.intent.action.SEND");
        intent.setType("text/plain");
        sap.setShareIntent(intent);
        MenuItem menuItem = menu.findItem(C0084R.id.setting);
        menuItem.setOnActionExpandListener(new MenuItem.OnActionExpandListener() {
            @Override
            public boolean onMenuItemActionCollapse(MenuItem item) {
                return true;
            }

            @Override
            public boolean onMenuItemActionExpand(MenuItem item) {
                return true;
            }
        });
        return true;
    }

    @Override
    public void onPictureSelected(Integer selectedRow) {
        this.app.setSelectedItem(selectedRow.intValue());
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() != C0084R.id.setting) {
            return super.onOptionsItemSelected(item);
        }
        checkLicenceKey(this);
        return true;
    }

    private void checkLicenceKey(final Context context) {
        if (this.app.getDataHelper().getConfig().hasLicence()) {
            showAlertDialog(context, OK_LICENCE_MSG);
            return;
        }
        LayoutInflater li = LayoutInflater.from(context);
        View promptsView = li.inflate(C0084R.layout.propmt, (ViewGroup) null);
        AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(context);
        alertDialogBuilder.setView(promptsView);
        final EditText userInput = (EditText) promptsView.findViewById(C0084R.id.editTextDialogUserInput);
        alertDialogBuilder.setCancelable(false).setPositiveButton("Continue", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int id) {
                String userEnteredValue = userInput.getText().toString();
                String storedKey = MainActivity.this.app.getDataHelper().getConfig().getSecurityKey();
                String iv = MainActivity.this.app.getDataHelper().getConfig().getSecurityIv();
                boolean licenceKeyIsValid = KeyVerifier.isValidLicenceKey(userEnteredValue, storedKey, iv);
                if (licenceKeyIsValid) {
                    MainActivity.this.app.getDataHelper().updateLicence(2014);
                    MainActivity.isRegisterd = true;
                    MainActivity.this.showAlertDialog(context, MainActivity.OK_LICENCE_MSG);
                    return;
                }
                MainActivity.this.showAlertDialog(context, MainActivity.NOK_LICENCE_MSG);
            }
        }).setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int id) {
                dialog.cancel();
            }
        });
        AlertDialog inputLicenceDialog = alertDialogBuilder.create();
        inputLicenceDialog.show();
    }

    private void showAlertDialog(Context context, CharSequence msg) {
        final Dialog dialog = new Dialog(context);
        dialog.setContentView(C0084R.layout.dialog);
        dialog.setTitle("CTF 2014");
        TextView txt = (TextView) dialog.findViewById(C0084R.id.txt);
        txt.setText(msg);
        Button dialogButton = (Button) dialog.findViewById(C0084R.id.dialogButton);
        dialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dialog.dismiss();
            }
        });
        dialog.show();
    }
}
```

Let's **explain this code**
In the **License Management** topic
- When the user selects the setting menu item (`R.id.setting`), the `checkLicenceKey()` method is called.
- If there is no valid license, an `AlertDialog` is displayed prompting the user to enter a license key.
- The validity of the key is verified by `KeyVerifier.isValidLicenceKey()` using values such as `storedKey` and `iv` retrieved from `DataHelper`.

**Messages**
- The `showAlertDialog()` method is used to display status messages about the validity of the license key.

**License Key Validation** could be a point of interest to exploit, as it may involve reverse engineering techniques or data manipulation.

Looking inside of the **extracted** apk folder, we can see in **assets** an **database**.
That is called **db.db**.
Let's open and see information inside
```bash
sqlite3 db.db
```
```bash
sqlite> .tables
config
sqlite> select * FROM config;
1|2|2014|0|a5efdbd57b84ca36|37eaae0141f1a3adf8a1dee655853714|1000|ctf.sharif.edu|9
sqlite>
```

Then, we have another **two** java classes that we need.
**KeyVerifier** (simplified)
```java
public class KeyVerifier {
    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String VALID_LICENCE = "29a002d9340fc4bd54492f327269f3e051619b889dc8da723e135ce486965d84";

    public static boolean isValidLicenceKey(String userInput, String secretKey, String iv) {
        String encryptedUserInput = encrypt(userInput, secretKey, iv);
        return encryptedUserInput.equals(VALID_LICENCE);
    }

    public static String encrypt(String userInput, String secretKey, String iv) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(hexStringToBytes(secretKey), "AES");
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(hexStringToBytes(iv));
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(userInput.getBytes());
            return bytesToHexString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private static String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexStringToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
```

**DBHelper** (simplified)
```java
public class DBHelper extends SQLiteOpenHelper {
    private static final String DB_PATH = "/data/data/edu.sharif.ctf/databases/";
    private static final String DB_NAME = "db.db";
    private static final String TABLE_NAME = "config";
    private static final String SELECT_QUERY = "SELECT * FROM " + TABLE_NAME + " WHERE a=1";

    public DBHelper(Context context) {
        super(context, DB_NAME, null, 1);
    }

    public AppConfig getConfig() {
        AppConfig agency = new AppConfig();
        Cursor cursor = this.getReadableDatabase().rawQuery(SELECT_QUERY, null);
        if (cursor.moveToFirst()) {
            agency.setSecurityKey(cursor.getString(5));
            agency.setSecurityIv(cursor.getString(4));
        }
        return agency;
    }
}
```

We can conclude that the **key** is former with an **AES** encryption.
That is need for decrypt an **iv** and **secret key**.
We can found this parameters in the **db**.

Which, for standard of **AES**, the
**IV**: `a5efdbd57b84ca36`
**Secret Key**: `37eaae0141f1a3adf8a1dee655853714`

And, in the **KeyVerifier** class, we have the **encrypted** license:
`29a002d9340fc4bd54492f327269f3e051619b889dc8da723e135ce486965d84`

Then, in cyberchef we can **decrypt** the **AES**
![[commercialApplication3.png]]

**License Key**: fl-ag-IS-se-ri-al-NU-MB-ER
![[commercialApplication4.png]]

I hope you found it useful (: