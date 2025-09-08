**Description**: Crossing international borders as a highly targeted individual? BorderDroid provides the ultimate protection against unauthorized device seizures and searches.

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-BorderDroid_1.png]]

Install the `.apk` file using **ADB**.
```bash
adb install -r BorderDroid.apk
```

Then, give **all the needed permissions** to the applications. *An input text for 6 digits must be appear*.

I set a *6 digits* as `111111`. Then, a *new activity* will be launched with *three buttons*.

- Start Security

- Stop Security

- Change PIN

After set the PIN, and press *start security* button, we can see a **countdown**. And then, *kiosk mode is activated*.

![[8ksec-BorderDroid_2.png]]

I'm trying to put *my code*, **but isn't work**.

The kiosk mode, *is working*.

Let's analyze the **source code** using **JADX**.
The *package name* is `com.eightksec.borderdroid`.

And in the `AndroidManifest.xml` file we can see this **receiver** exported as `true`.
```XML
<receiver
    android:name="com.eightksec.borderdroid.receiver.RemoteTriggerReceiver"
    android:enabled="true"
    android:exported="true">
    <intent-filter>
        <action android:name="com.eightksec.borderdroid.ACTION_PERFORM_REMOTE_TRIGGER"/>
    </intent-filter>
</receiver>
```

And, we can see a *lot of classes* in the *java code*.

I'll show some interesting functions.
### Using Volume Buttons
Starting in **`YouAreSecureActivity`** class, I found that **never will work** if we insert the *correct* pin, because **always will call to** `showWrongPinError()` function:
```java
private void onNumpadClick(String str) {
    this.wrongPinText.setVisibility(4);
    if (this.enteredPin.length() < 6) {
        this.enteredPin.append(str);
        updatePinDots();
        if (this.enteredPin.length() == 6) {
            showWrongPinError();
        }
    }
}
```

So.. we can see **another** great function in this class, which is `checkVolumeSequence()`
```java
private void checkVolumeSequence() {
    while (this.volumeSequence.size() > this.targetSequence.size()) {
        Log.d(TAG, "Trimming volume sequence (unexpectedly long). Old: " + this.volumeSequence.toString());
        this.volumeSequence.remove(0);
    }
    if (this.volumeSequence.equals(this.targetSequence)) {
        Log.i(TAG, "Target volume sequence DETECTED! Unlocking.");
        this.volumeSequence.clear();
        Runnable runnable = this.volumeSequenceTimeout;
        if (runnable != null) {
            this.volumeSequenceHandler.removeCallbacks(runnable);
        }
        unlockAndReturnToDashboard();
        return;
    }
    if (this.volumeSequence.size() == this.targetSequence.size()) {
        Log.d(TAG, "Volume sequence full but incorrect. Pruning first element. Seq: " + this.volumeSequence.toString());
        this.volumeSequence.remove(0);
    }
}
```

Which is used in `onKeyDown()` function:
```java
public boolean onKeyDown(int i, KeyEvent keyEvent) {
    if (i == 24 || i == 25) {
        Log.d(TAG, "Volume key pressed: ".concat(i == 24 ? "UP" : "DOWN"));
        resetSequenceTimeout();
        this.volumeSequence.add(Integer.valueOf(i));
        checkVolumeSequence();
        return true;
    }
    return super.onKeyDown(i, keyEvent);
}
```

And finally, the `unlockAndReturnToDashboard()` function:
```java
private void unlockAndReturnToDashboard() {
    try {
        Log.i(TAG, "Stopping lock task due to volume sequence.");
        stopLockTask();
    } catch (Exception e) {
        Log.e(TAG, "Failed to stop lock task during unlock", e);
    }
    Log.i(TAG, "Disabling kiosk state and stopping HTTP service.");
    setKioskState(false);
    Log.i(TAG, "Navigating back to DashboardActivity.");
    Intent intent = new Intent(this, (Class<?>) DashboardActivity.class);
    intent.addFlags(603979776);
    startActivity(intent);
    finish();
}
```
We can see this sequence:
- `unlockAndReturnToDashboard()` → `stopLockTask()`, **`setKioskState(false)`**, **stop** `HttpUnlockService` **and open** `DashboardActivity`.

But, what is the sequence?
Well, it's easy. In `YouAreSecureActivity` class, we can see the following list:
```java
private final List<Integer> targetSequence;
```
Looking some lines below, we can see this function:
```java
public YouAreSecureActivity() {
    List<Integer> m65m;
    m65m = YouAreSecureActivity$ExternalSyntheticBackport0.m65m(new Object[]{24, 25, 24, 25});
    this.targetSequence = m65m;
    this.volumeSequenceHandler = new Handler(Looper.getMainLooper());
}
```

The *sequence*: `24, 25, 24, 25`.
Remember the `onKeyDown()` function?
Pay attention in these lines:
```java
if (i == 24 || i == 25) {
    Log.d(TAG, "Volume key pressed: ".concat(i == 24 ? "UP" : "DOWN"));
```
So:
- `UP` -> `24`
- `DOWN` -> `25`
**Sequence: `UP`, `DOWN`, `UP`, `DOWN`**
In kiosk mode, **just follow the sequence** and the *kiosk mode must be turned off*!
### HTTP Remote using PIN via Wi-Fi
We can see that the app set up a **Nano HTTP Server** locally.
Check it with:
```bash
sudo arp-scan -I wlan0 --localnet
```
Output:
```bash
192.168.0.6	**:**:**:**:**:**	Xiaomi Communications Co Ltd
```

Let's check some classes, but the **most important class** is **`HttpUnlockService`**.
Ill put the *entire class code*:
```java
public class HttpUnlockService extends Service {  
    public static final String ACTION_STOP_KIOSK = "com.eightksec.borderdroid.ACTION_STOP_KIOSK_ENFORCEMENT";  
    private static final String NOTIFICATION_CHANNEL_ID = "HttpUnlockServiceChannel";  
    private static final int NOTIFICATION_ID = 1;  
    private static final int SERVER_PORT = 8080;  
    private static final String TAG = "HttpUnlockService";  
    private WebServer server;  
  
    @Override // android.app.Service  
    public IBinder onBind(Intent intent) {  
        return null;  
    }  
  
    @Override // android.app.Service  
    public void onCreate() {  
        super.onCreate();  
        createNotificationChannel();  
        this.server = new WebServer(this);  
    }  
  
    @Override // android.app.Service  
    public int onStartCommand(Intent intent, int i, int i2) {  
        startForeground(1, new NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID).setContentTitle("BorderDroid Kiosk Control").setContentText("Remote Unlock Listener Active").setSmallIcon(C0479R.drawable.ic_launcher_foreground).setContentIntent(PendingIntent.getActivity(this, 0, new Intent(this, (Class<?>) DashboardActivity.class), AccessibilityEventCompat.TYPE_VIEW_TARGETED_BY_SCROLL)).setOngoing(true).build());  
        try {  
            if (!this.server.isAlive()) {  
                this.server.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);  
            }  
        } catch (IOException unused) {  
            stopSelf();  
        }  
        return 1;  
    }  
  
    @Override // android.app.Service  
    public void onDestroy() {  
        super.onDestroy();  
        WebServer webServer = this.server;  
        if (webServer != null) {  
            webServer.stop();  
        }  
        stopForeground(true);  
    }  
  
    private void createNotificationChannel() {  
        if (Build.VERSION.SDK_INT >= 26) {  
            NotificationChannel notificationChannel = new NotificationChannel(NOTIFICATION_CHANNEL_ID, "HTTP Unlock Service Channel", 2);  
            NotificationManager notificationManager = (NotificationManager) getSystemService(NotificationManager.class);  
            if (notificationManager != null) {  
                notificationManager.createNotificationChannel(notificationChannel);  
            }  
        }  
    }  
  
    private static class WebServer extends NanoHTTPD {  
        private Context context;  
        private PinStorage pinStorage;  
  
        public WebServer(Context context) {  
            super(HttpUnlockService.SERVER_PORT);  
            this.context = context.getApplicationContext();  
            this.pinStorage = new PinStorage();  
        }  
  
        @Override // fi.iki.elonen.NanoHTTPD  
        public NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession iHTTPSession) {  
            String str;  
            NanoHTTPD.Response.Status status = NanoHTTPD.Response.Status.OK;  
            if (NanoHTTPD.Method.POST.equals(iHTTPSession.getMethod()) && "/unlock".equalsIgnoreCase(iHTTPSession.getUri())) {  
                try {  
                    try {  
                        HashMap hashMap = new HashMap();  
                        iHTTPSession.parseBody(hashMap);  
                        String str2 = hashMap.get("postData");  
                        if (str2 == null || str2.isEmpty()) {  
                            str = "Error: Empty or unparseable request body. Send JSON with 'pin'.";  
                            status = NanoHTTPD.Response.Status.BAD_REQUEST;  
                        } else {  
                            str = "";  
                        }  
                        if (status == NanoHTTPD.Response.Status.OK && str2 != null) {  
                            String optString = new JSONObject(str2).optString("pin", null);  
                            if (optString != null) {  
                                broadcastVulnerableUnlockIntentWithPin(optString);  
                                str = "Unlock attempt initiated (vulnerable pathway).";  
                                status = NanoHTTPD.Response.Status.OK;  
                            } else {  
                                str = "Error: Missing 'pin' in JSON body.";  
                                status = NanoHTTPD.Response.Status.BAD_REQUEST;  
                            }  
                        }  
                    } catch (JSONException unused) {  
                        status = NanoHTTPD.Response.Status.BAD_REQUEST;  
                        str = "Error: Invalid JSON format.";  
                    } catch (Exception e) {  
                        Log.e(HttpUnlockService.TAG, "Unexpected error serving request", e);  
                        status = NanoHTTPD.Response.Status.INTERNAL_ERROR;  
                        str = "Error: Internal server error.";  
                    }  
                } catch (NanoHTTPD.ResponseException | IOException unused2) {  
                    status = NanoHTTPD.Response.Status.INTERNAL_ERROR;  
                    str = "Error: Failed to read request body or socket error.";  
                }  
            } else {  
                Log.w(HttpUnlockService.TAG, "Received request for unsupported method/URI: " + iHTTPSession.getMethod() + " " + iHTTPSession.getUri());  
                status = NanoHTTPD.Response.Status.NOT_FOUND;  
                str = "Error: Unsupported request. Use POST to /unlock.";  
            }  
            return newFixedLengthResponse(status, NanoHTTPD.MIME_PLAINTEXT, str);  
        }  
  
        private void broadcastVulnerableUnlockIntentWithPin(String str) {  
            Intent intent = new Intent(RemoteTriggerReceiver.ACTION_PERFORM_REMOTE_TRIGGER);  
            intent.putExtra(RemoteTriggerReceiver.EXTRA_TRIGGER_PIN, str);  
            intent.setClassName(this.context, RemoteTriggerReceiver.class.getName());  
            this.context.sendBroadcast(intent);  
            Log.i(HttpUnlockService.TAG, "Broadcast sent for remote trigger: " + intent.getAction());  
        }  
    }  
}
```

Notice the *port number*:
```java
private static final int SERVER_PORT = 8080;
```

And the *endpoint*:
```java
public NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession iHTTPSession) {
    String str;
    NanoHTTPD.Response.Status status = NanoHTTPD.Response.Status.OK;
    if (NanoHTTPD.Method.POST.equals(iHTTPSession.getMethod()) && "/unlock".equalsIgnoreCase(iHTTPSession.getUri())) {
```

So, we have:
- `POST http://192.168.0.124:8080/unlock`
And *finally*, we have the **body content**!
```java
if (status == NanoHTTPD.Response.Status.OK && str2 != null) {
    String optString = new JSONObject(str2).optString("pin", null);
    if (optString != null) {
        broadcastVulnerableUnlockIntentWithPin(optString);
        str = "Unlock attempt initiated (vulnerable pathway).";
        status = NanoHTTPD.Response.Status.OK;
    } else {
        str = "Error: Missing 'pin' in JSON body.";
        status = NanoHTTPD.Response.Status.BAD_REQUEST;
    }
```
Is **`pin`**!

If we *send the correct PIN*, this function will be triggered:
`broadcastVulnerableUnlockIntentWithPin()`, passed the PIN as *extra*:
```java
private void broadcastVulnerableUnlockIntentWithPin(String str) {
    Intent intent = new Intent(RemoteTriggerReceiver.ACTION_PERFORM_REMOTE_TRIGGER);
    intent.putExtra(RemoteTriggerReceiver.EXTRA_TRIGGER_PIN, str);
    intent.setClassName(this.context, RemoteTriggerReceiver.class.getName());
    this.context.sendBroadcast(intent);
    Log.i(HttpUnlockService.TAG, "Broadcast sent for remote trigger: " + intent.getAction());
}
```
And the `RemoteTriggerReceiver` will be called with *intents*!
When it's receive the intent, will execute this code:
```java
public void onReceive(Context context, Intent intent) {
    String stringExtra;
    if (!ACTION_PERFORM_REMOTE_TRIGGER.equals(intent.getAction()) || (stringExtra = intent.getStringExtra(EXTRA_TRIGGER_PIN)) == null || stringExtra.isEmpty()) {
        return;
    }
    try {
        if (new PinStorage().verifyPin(context, stringExtra)) {
            performUnlockActions(context);
            return;
        }
        Bundle extras = intent.getExtras();
        if (extras != null) {
            for (String str : extras.keySet()) {
            }
        }
    } catch (Exception unused) {
    }
}
```

Look at:
```java
PinStorage().verifyPin(context, stringExtra)
```
Will *verify the PIN* with the *extra string*.
And then, call `performUnlockActions()` function:
```java
private void performUnlockActions(final Context context) {
    Log.i(TAG, "Executing performUnlockActions...");
    new Handler(context.getMainLooper()).post(new Runnable() { // from class: com.eightksec.borderdroid.receiver.RemoteTriggerReceiver$ExternalSyntheticLambda0
        @Override // java.lang.Runnable
        public final void run() {
            RemoteTriggerReceiver.lambda$performUnlockActions$0(context);
        }
    });
}

static /* synthetic */ void lambda$performUnlockActions$0(Context context) {
    Toast.makeText(context, "Remote Action Triggered (PIN OK)", Toast.LENGTH_SHORT).show();
    context.getSharedPreferences("kiosk_state", 0).edit().putBoolean("is_kiosk_active", false).apply();
    LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent(HttpUnlockService.ACTION_STOP_KIOSK));
    Log.d(TAG, "Sent local broadcast to stop kiosk enforcement: com.eightksec.borderdroid.ACTION_STOP_KIOSK_ENFORCEMENT");
    Log.i(TAG, "Requesting stop of HttpUnlockService from RemoteTriggerReceiver.");
    context.stopService(new Intent(context, (Class<?>) HttpUnlockService.class));
    Intent intent = new Intent(context, (Class<?>) DashboardActivity.class);
    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    context.startActivity(intent);
    Log.i(TAG, "Finished executing unlock actions within Handler.");
}
```

How we can abuse of this vulnerability?
Simple, just **brute forcing** the PIN **via Request**.
But just for be a little concise, Ill show you the *curl* command.
```bash
curl -i -X POST http://192.168.0.6:8080/unlock \
  -H 'Content-Type: application/json' \
  -d '{"pin":"111111"}'
```
Remember change the *pin* value with the initial that you set when the app was installed.

I hope you found it useful (:
