package online.feian.mixia;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.service.autofill.Dataset;
import android.util.Base64;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillManager;
import android.view.autofill.AutofillValue;
import android.widget.RemoteViews;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResult;
import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/**
 * 原生能力：Keystore 硬件密钥、受控网络、剪贴板、文件、生物识别解锁、自动填充收尾。
 * WebView 的 CSP 禁止联网，这里是唯一的出口。
 */
@CapacitorPlugin(name = "MixiaNative")
public class MixiaNativePlugin extends Plugin {
    private static final String KS = "AndroidKeyStore";
    private static final int B64 = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;
    private static final long BACKGROUND_LOCK_MS = 60_000;

    private final ExecutorService pool = Executors.newFixedThreadPool(3);
    private final Handler main = new Handler(Looper.getMainLooper());
    private BroadcastReceiver screenOff;
    private long backgroundAt = 0;
    private byte[] pendingSave;

    private static byte[] dec(String s) {
        return Base64.decode(s, B64);
    }

    private static String enc(byte[] b) {
        return Base64.encodeToString(b, B64);
    }

    private SharedPreferences prefs() {
        return getContext().getSharedPreferences("mixia", Context.MODE_PRIVATE);
    }

    // ———— 生命周期：锁屏立刻锁，切后台超时锁 ————

    @Override
    public void load() {
        screenOff = new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent i) {
                notifyListeners("systemLock", new JSObject(), true);
            }
        };
        ContextCompat.registerReceiver(
            getContext(),
            screenOff,
            new IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED
        );
        getActivity().getOnBackPressedDispatcher().addCallback(getActivity(), new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                notifyListeners("backButton", new JSObject(), false);
            }
        });
    }

    @PluginMethod
    public void exitApp(PluginCall call) {
        call.resolve();
        getActivity().moveTaskToBack(true);
    }

    @Override
    protected void handleOnDestroy() {
        if (screenOff != null) getContext().unregisterReceiver(screenOff);
        pool.shutdown();
    }

    @Override
    protected void handleOnPause() {
        backgroundAt = System.currentTimeMillis();
    }

    @Override
    protected void handleOnResume() {
        if (backgroundAt > 0 && System.currentTimeMillis() - backgroundAt > BACKGROUND_LOCK_MS) {
            notifyListeners("systemLock", new JSObject(), true);
        }
        backgroundAt = 0;
    }

    // ———— 硬件密钥 ————

    private static String authAlias(String n) {
        return "mx-auth-" + n;
    }

    private static String sealAlias(String n) {
        return "mx-seal-" + n;
    }

    private static String quickAlias(String n) {
        return "mx-quick-" + n;
    }

    private KeyStore keystore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KS);
        ks.load(null);
        return ks;
    }

    private boolean hasStrongBox() {
        return getContext().getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    /** 实际生成一把探测密钥，按系统报告的安全等级判断，不凭机型猜。 */
    private String probeLevel() throws Exception {
        String alias = "mx-probe";
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KS);
        g.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build());
        g.generateKeyPair();
        KeyStore ks = keystore();
        PrivateKey k = (PrivateKey) ks.getKey(alias, null);
        KeyInfo info = KeyFactory.getInstance(k.getAlgorithm(), KS).getKeySpec(k, KeyInfo.class);
        boolean hw;
        if (Build.VERSION.SDK_INT >= 31) {
            int lv = info.getSecurityLevel();
            hw = lv == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT || lv == KeyProperties.SECURITY_LEVEL_STRONGBOX;
        } else {
            hw = info.isInsideSecureHardware();
        }
        ks.deleteEntry(alias);
        return hw ? "hardware" : "os";
    }

    @PluginMethod
    public void hwLevel(PluginCall call) {
        pool.execute(() -> {
            try {
                JSObject r = new JSObject();
                r.put("level", probeLevel());
                r.put("strongbox", hasStrongBox());
                call.resolve(r);
            } catch (Exception e) {
                call.reject("keystore_failed");
            }
        });
    }

    private void generateAuth(String alias, boolean strongBox) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KS);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256);
        if (strongBox) b.setIsStrongBoxBacked(true);
        // 设备锁屏时这把钥匙不可用：被 root 的已锁定设备也签不了名
        if (Build.VERSION.SDK_INT >= 28 && secureLockScreen()) b.setUnlockedDeviceRequired(true);
        g.initialize(b.build());
        g.generateKeyPair();
    }

    private boolean secureLockScreen() {
        android.app.KeyguardManager km = (android.app.KeyguardManager) getContext().getSystemService(Context.KEYGUARD_SERVICE);
        return km != null && km.isDeviceSecure();
    }

    private void generateSeal(String alias) throws Exception {
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KS);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256);
        if (Build.VERSION.SDK_INT >= 28 && secureLockScreen()) b.setUnlockedDeviceRequired(true);
        g.init(b.build());
        g.generateKey();
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }

    @PluginMethod
    public void hwCreate(PluginCall call) {
        String name = call.getString("name");
        pool.execute(() -> {
            try {
                String alias = authAlias(name);
                boolean done = false;
                if (hasStrongBox()) {
                    try {
                        generateAuth(alias, true);
                        done = true;
                    } catch (StrongBoxUnavailableException ignored) {
                        // 退到 TEE
                    }
                }
                if (!done) generateAuth(alias, false);
                generateSeal(sealAlias(name));
                ECPublicKey pub = (ECPublicKey) keystore().getCertificate(alias).getPublicKey();
                byte[] point = new byte[65];
                point[0] = 4;
                System.arraycopy(fixed32(pub.getW().getAffineX()), 0, point, 1, 32);
                System.arraycopy(fixed32(pub.getW().getAffineY()), 0, point, 33, 32);
                JSObject r = new JSObject();
                r.put("authPub", enc(point));
                call.resolve(r);
            } catch (Exception e) {
                call.reject("keystore_failed");
            }
        });
    }

    /** ASN.1 DER 的 ECDSA 签名转成 r||s。 */
    private static byte[] derToRaw(byte[] der) {
        int i = 2;
        if ((der[1] & 0xff) > 0x80) i += (der[1] & 0x7f);
        int rl = der[i + 1] & 0xff;
        byte[] r = new byte[rl];
        System.arraycopy(der, i + 2, r, 0, rl);
        i += 2 + rl;
        int sl = der[i + 1] & 0xff;
        byte[] s = new byte[sl];
        System.arraycopy(der, i + 2, s, 0, sl);
        byte[] out = new byte[64];
        System.arraycopy(fixed32(new BigInteger(1, r)), 0, out, 0, 32);
        System.arraycopy(fixed32(new BigInteger(1, s)), 0, out, 32, 32);
        return out;
    }

    @PluginMethod
    public void hwSign(PluginCall call) {
        String name = call.getString("name");
        byte[] data = dec(call.getString("data"));
        pool.execute(() -> {
            try {
                PrivateKey k = (PrivateKey) keystore().getKey(authAlias(name), null);
                if (k == null) {
                    call.reject("no_key");
                    return;
                }
                Signature s = Signature.getInstance("SHA256withECDSA");
                s.initSign(k);
                s.update(data);
                JSObject r = new JSObject();
                r.put("sig", enc(derToRaw(s.sign())));
                call.resolve(r);
            } catch (Exception e) {
                call.reject("keystore_failed");
            }
        });
    }

    @PluginMethod
    public void hwSeal(PluginCall call) {
        String name = call.getString("name");
        byte[] data = dec(call.getString("data"));
        pool.execute(() -> {
            try {
                SecretKey k = (SecretKey) keystore().getKey(sealAlias(name), null);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, k);
                byte[] iv = c.getIV();
                byte[] ct = c.doFinal(data);
                byte[] out = new byte[1 + iv.length + ct.length];
                out[0] = (byte) iv.length;
                System.arraycopy(iv, 0, out, 1, iv.length);
                System.arraycopy(ct, 0, out, 1 + iv.length, ct.length);
                JSObject r = new JSObject();
                r.put("blob", enc(out));
                call.resolve(r);
            } catch (Exception e) {
                call.reject("keystore_failed");
            }
        });
    }

    @PluginMethod
    public void hwUnseal(PluginCall call) {
        String name = call.getString("name");
        byte[] blob = dec(call.getString("blob"));
        pool.execute(() -> {
            try {
                SecretKey k = (SecretKey) keystore().getKey(sealAlias(name), null);
                if (k == null) {
                    call.reject("no_key");
                    return;
                }
                int n = blob[0] & 0xff;
                byte[] iv = new byte[n];
                System.arraycopy(blob, 1, iv, 0, n);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, iv));
                JSObject r = new JSObject();
                r.put("data", enc(c.doFinal(blob, 1 + n, blob.length - 1 - n)));
                call.resolve(r);
            } catch (Exception e) {
                call.reject("keystore_failed");
            }
        });
    }

    @PluginMethod
    public void hwDestroy(PluginCall call) {
        String name = call.getString("name");
        pool.execute(() -> {
            try {
                KeyStore ks = keystore();
                ks.deleteEntry(authAlias(name));
                ks.deleteEntry(sealAlias(name));
                ks.deleteEntry(quickAlias(name));
                prefs().edit().remove("quick-" + name).apply();
                call.resolve();
            } catch (Exception e) {
                call.reject("keystore_failed");
            }
        });
    }

    // ———— 生物识别快捷解锁：密钥只有在系统生物识别通过后才能使用 ————

    @PluginMethod
    public void quickAvailable(PluginCall call) {
        int r = BiometricManager.from(getContext()).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        JSObject o = new JSObject();
        o.put("value", r == BiometricManager.BIOMETRIC_SUCCESS);
        call.resolve(o);
    }

    private SecretKey quickKey(String name, boolean create) throws Exception {
        KeyStore ks = keystore();
        String alias = quickAlias(name);
        if (create) {
            if (ks.containsAlias(alias)) ks.deleteEntry(alias);
            KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KS);
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true);
            if (Build.VERSION.SDK_INT >= 30) {
                b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
            }
            g.init(b.build());
            g.generateKey();
        }
        return (SecretKey) ks.getKey(alias, null);
    }

    private void prompt(PluginCall call, Cipher cipher, java.util.function.Consumer<Cipher> done) {
        main.post(() -> {
            BiometricPrompt p = new BiometricPrompt(
                (FragmentActivity) getActivity(),
                ContextCompat.getMainExecutor(getContext()),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int code, @NonNull CharSequence msg) {
                        call.reject("biometric_cancelled");
                    }

                    @Override
                    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult r) {
                        done.accept(r.getCryptoObject().getCipher());
                    }
                }
            );
            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("解锁密匣")
                .setNegativeButtonText("用口令")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();
            p.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
        });
    }

    @PluginMethod
    public void quickEnroll(PluginCall call) {
        String name = call.getString("name");
        byte[] secret = dec(call.getString("data"));
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, quickKey(name, true));
            prompt(call, c, (ok) -> {
                try {
                    byte[] ct = ok.doFinal(secret);
                    byte[] iv = ok.getIV();
                    prefs().edit().putString("quick-" + name, enc(iv) + "." + enc(ct)).apply();
                    call.resolve();
                } catch (Exception e) {
                    call.reject("biometric_failed");
                }
            });
        } catch (Exception e) {
            call.reject("biometric_failed");
        }
    }

    @PluginMethod
    public void quickRetrieve(PluginCall call) {
        String name = call.getString("name");
        String stored = prefs().getString("quick-" + name, null);
        if (stored == null) {
            call.reject("quick_not_enrolled");
            return;
        }
        String[] parts = stored.split("\\.");
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, quickKey(name, false), new GCMParameterSpec(128, dec(parts[0])));
            prompt(call, c, (ok) -> {
                try {
                    JSObject r = new JSObject();
                    r.put("data", enc(ok.doFinal(dec(parts[1]))));
                    call.resolve(r);
                } catch (Exception e) {
                    call.reject("biometric_failed");
                }
            });
        } catch (KeyPermanentlyInvalidatedException e) {
            // 新录入了指纹：这把钥匙按设计失效，必须回到口令
            prefs().edit().remove("quick-" + name).apply();
            call.reject("quick_invalidated");
        } catch (Exception e) {
            call.reject("biometric_failed");
        }
    }

    @PluginMethod
    public void quickClear(PluginCall call) {
        String name = call.getString("name");
        try {
            keystore().deleteEntry(quickAlias(name));
            prefs().edit().remove("quick-" + name).apply();
            call.resolve();
        } catch (Exception e) {
            call.reject("keystore_failed");
        }
    }

    // ———— 受控网络 ————

    private void assertAllowed(URL u) throws Exception {
        String pin = prefs().getString("server-origin", null);
        String origin = u.getProtocol() + "://" + u.getAuthority();
        if (pin != null) {
            if (!pin.equals(origin)) throw new SecurityException("server_not_pinned");
            return;
        }
        if (!"https".equals(u.getProtocol()) && !debugLoopback(u)) throw new SecurityException("https_required");
    }

    /** 只有可调试的安装包（调试版）才允许经 adb reverse 连电脑上的本地测试服务端。正式版不可调试，这里永远是 false。 */
    private boolean debugLoopback(URL u) {
        boolean debuggable = (getContext().getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        String h = u.getHost();
        return debuggable && "http".equals(u.getProtocol()) && ("127.0.0.1".equals(h) || "localhost".equals(h));
    }

    @PluginMethod
    public void pinServer(PluginCall call) {
        try {
            URL u = new URL(call.getString("url"));
            prefs().edit().putString("server-origin", u.getProtocol() + "://" + u.getAuthority()).apply();
            call.resolve();
        } catch (Exception e) {
            call.reject("bad_url");
        }
    }

    @PluginMethod
    public void unpinServer(PluginCall call) {
        prefs().edit().remove("server-origin").apply();
        call.resolve();
    }

    private static byte[] readAll(InputStream in) throws Exception {
        if (in == null) return new byte[0];
        try (InputStream s = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] b = new byte[16384];
            int n;
            while ((n = s.read(b)) > 0) out.write(b, 0, n);
            return out.toByteArray();
        }
    }

    @PluginMethod
    public void http(PluginCall call) {
        String method = call.getString("method");
        String url = call.getString("url");
        JSObject headers = call.getObject("headers", new JSObject());
        String body = call.getString("body");
        pool.execute(() -> {
            HttpURLConnection c = null;
            try {
                URL u = new URL(url);
                assertAllowed(u);
                c = (HttpURLConnection) u.openConnection();
                c.setRequestMethod(method);
                c.setInstanceFollowRedirects(false);
                c.setUseCaches(false);
                c.setConnectTimeout(15000);
                c.setReadTimeout(60000);
                Iterator<String> keys = headers.keys();
                while (keys.hasNext()) {
                    String k = keys.next();
                    c.setRequestProperty(k, headers.getString(k));
                }
                if (body != null) {
                    byte[] bytes = dec(body);
                    c.setDoOutput(true);
                    c.setFixedLengthStreamingMode(bytes.length);
                    try (OutputStream o = c.getOutputStream()) {
                        o.write(bytes);
                    }
                }
                int status = c.getResponseCode();
                byte[] data = readAll(status >= 400 ? c.getErrorStream() : c.getInputStream());
                JSObject r = new JSObject();
                r.put("status", status);
                r.put("body", enc(data));
                call.resolve(r);
            } catch (SecurityException e) {
                call.reject(e.getMessage());
            } catch (Exception e) {
                call.reject("network");
            } finally {
                if (c != null) c.disconnect();
            }
        });
    }

    // ———— 剪贴板 ————

    @PluginMethod
    public void copy(PluginCall call) {
        String text = call.getString("text");
        int seconds = call.getInt("seconds", 30);
        ClipboardManager cm = (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("密匣", text);
        if (Build.VERSION.SDK_INT >= 33) {
            PersistableBundle extras = new PersistableBundle();
            // 系统不再在剪贴板预览里显示内容
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        cm.setPrimaryClip(clip);
        // Android 10 起后台读不到剪贴板，复制后切走正是主要用法，所以到时直接清除，不先比对。
        // 定时放在前台服务里：普通定时器在进程被系统冻结后不触发。
        Intent clear = new Intent(getContext(), ClipboardClearService.class);
        clear.putExtra(ClipboardClearService.EXTRA_SECONDS, seconds);
        try {
            ContextCompat.startForegroundService(getContext(), clear);
        } catch (RuntimeException e) {
            main.postDelayed(() -> ClipboardClearService.clearNow(getContext()), Math.max(5, seconds) * 1000L);
        }
        call.resolve();
    }

    // ———— 文件 ————

    @PluginMethod
    public void saveFile(PluginCall call) {
        pendingSave = dec(call.getString("data"));
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/octet-stream");
        i.putExtra(Intent.EXTRA_TITLE, call.getString("name"));
        startActivityForResult(call, i, "onSaved");
    }

    @ActivityCallback
    private void onSaved(PluginCall call, ActivityResult result) {
        JSObject r = new JSObject();
        if (result.getResultCode() != Activity.RESULT_OK || result.getData() == null) {
            pendingSave = null;
            r.put("saved", false);
            call.resolve(r);
            return;
        }
        Uri uri = result.getData().getData();
        byte[] data = pendingSave;
        pendingSave = null;
        pool.execute(() -> {
            try (OutputStream o = getContext().getContentResolver().openOutputStream(uri, "wt")) {
                o.write(data);
                r.put("saved", true);
                call.resolve(r);
            } catch (Exception e) {
                call.reject("file_failed");
            }
        });
    }

    @PluginMethod
    public void openFile(PluginCall call) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(call, i, "onOpened");
    }

    @ActivityCallback
    private void onOpened(PluginCall call, ActivityResult result) {
        JSObject r = new JSObject();
        if (result.getResultCode() != Activity.RESULT_OK || result.getData() == null) {
            call.resolve(r);
            return;
        }
        Uri uri = result.getData().getData();
        pool.execute(() -> {
            try {
                byte[] data = readAll(getContext().getContentResolver().openInputStream(uri));
                String name = "file";
                try (android.database.Cursor cur = getContext().getContentResolver().query(uri, null, null, null, null)) {
                    if (cur != null && cur.moveToFirst()) {
                        int idx = cur.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                        if (idx >= 0) name = cur.getString(idx);
                    }
                }
                r.put("name", name);
                r.put("data", enc(data));
                call.resolve(r);
            } catch (Exception e) {
                call.reject("file_failed");
            }
        });
    }

    @PluginMethod
    public void openExternal(PluginCall call) {
        String url = call.getString("url", "");
        if (!url.startsWith("https://") && !url.startsWith("http://")) {
            call.reject("bad_url");
            return;
        }
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getContext().startActivity(i);
        call.resolve();
    }

    @PluginMethod
    public void deviceInfo(PluginCall call) {
        JSObject r = new JSObject();
        r.put("model", Build.MANUFACTURER + " " + Build.MODEL);
        r.put("sdk", Build.VERSION.SDK_INT);
        call.resolve(r);
    }

    // ———— 自动填充收尾 ————

    private boolean autofillMode() {
        return getActivity() instanceof AutofillActivity;
    }

    @PluginMethod
    public void autofillPending(PluginCall call) {
        JSObject r = new JSObject();
        if (autofillMode()) {
            Intent i = getActivity().getIntent();
            r.put("target", i.getStringExtra(MixiaAutofillService.EXTRA_TARGET));
            r.put("kind", i.getStringExtra(MixiaAutofillService.EXTRA_KIND));
        }
        call.resolve(r);
    }

    @PluginMethod
    public void autofillFinish(PluginCall call) {
        if (!autofillMode()) {
            call.reject("not_autofill");
            return;
        }
        Activity a = getActivity();
        Intent src = a.getIntent();
        AutofillId user = src.getParcelableExtra(MixiaAutofillService.EXTRA_USER_ID);
        AutofillId pass = src.getParcelableExtra(MixiaAutofillService.EXTRA_PASS_ID);
        RemoteViews view = new RemoteViews(a.getPackageName(), R.layout.autofill_item);
        view.setTextViewText(R.id.autofill_text, "密匣");
        Dataset.Builder b = new Dataset.Builder();
        if (user != null) b.setValue(user, AutofillValue.forText(call.getString("username", "")), view);
        if (pass != null) b.setValue(pass, AutofillValue.forText(call.getString("password", "")), view);
        Intent reply = new Intent();
        reply.putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, b.build());
        a.setResult(Activity.RESULT_OK, reply);
        call.resolve();
        a.finish();
    }

    @PluginMethod
    public void autofillCancel(PluginCall call) {
        call.resolve();
        if (autofillMode()) {
            getActivity().setResult(Activity.RESULT_CANCELED);
            getActivity().finish();
        }
    }

    @PluginMethod
    public void autofillEnabled(PluginCall call) {
        AutofillManager m = getContext().getSystemService(AutofillManager.class);
        JSObject r = new JSObject();
        r.put("value", m != null && m.hasEnabledAutofillServices());
        call.resolve(r);
    }

    @PluginMethod
    public void autofillSettings(PluginCall call) {
        Intent i = new Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE);
        i.setData(Uri.parse("package:" + getContext().getPackageName()));
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getContext().startActivity(i);
        call.resolve();
    }
}
