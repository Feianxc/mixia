package online.feian.mixia;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Intent;
import android.content.IntentSender;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.Dataset;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;
import android.text.InputType;
import android.view.View;
import android.view.autofill.AutofillId;
import android.widget.RemoteViews;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 系统自动填充入口。这里不接触任何密码：只找出登录框，然后要求用户进入密匣确认。
 * 没有明文索引，也不预先暴露账号提示；重要库的内容不会出现在系统建议里。
 */
public class MixiaAutofillService extends AutofillService {
    static final String EXTRA_USER_ID = "mixia.userId";
    static final String EXTRA_PASS_ID = "mixia.passId";
    static final String EXTRA_TARGET = "mixia.target";
    static final String EXTRA_KIND = "mixia.kind";

    /**
     * 只有这些浏览器报告的网站域名才可信。任何 App 都能在自己的控件里调用
     * setWebDomain 声称自己是 accounts.google.com，所以其他来源一律按真实包名处理。
     */
    private static final Set<String> TRUSTED_BROWSERS = new HashSet<>(Arrays.asList(
        "com.android.chrome",
        "com.chrome.beta",
        "org.mozilla.firefox",
        "com.microsoft.emmx",
        "com.sec.android.app.sbrowser",
        "com.brave.browser",
        "com.opera.browser",
        "com.mmbox.xbrowser",
        "com.huawei.browser",
        "com.heytap.browser",
        "com.vivo.browser",
        "com.android.browser"
    ));

    private static final class Parsed {
        AutofillId user;
        AutofillId pass;
        String webDomain;
        String webScheme;
    }

    @Override
    public void onFillRequest(FillRequest request, CancellationSignal signal, FillCallback callback) {
        List<FillContext> contexts = request.getFillContexts();
        AssistStructure structure = contexts.get(contexts.size() - 1).getStructure();
        Parsed p = new Parsed();
        for (int i = 0; i < structure.getWindowNodeCount(); i++) {
            walk(structure.getWindowNodeAt(i).getRootViewNode(), p);
        }
        if (p.pass == null && p.user == null) {
            callback.onSuccess(null);
            return;
        }
        String pkg = structure.getActivityComponent().getPackageName();
        // 密匣自己的输入框不接受自动填充
        if (getPackageName().equals(pkg)) {
            callback.onSuccess(null);
            return;
        }
        boolean web = p.webDomain != null
            && TRUSTED_BROWSERS.contains(pkg)
            && (p.webScheme == null || "https".equalsIgnoreCase(p.webScheme));
        String target = web ? p.webDomain : pkg;
        Intent intent = new Intent(this, AutofillActivity.class);
        intent.putExtra(EXTRA_TARGET, target);
        intent.putExtra(EXTRA_KIND, web ? "web" : "app");
        if (p.user != null) intent.putExtra(EXTRA_USER_ID, p.user);
        if (p.pass != null) intent.putExtra(EXTRA_PASS_ID, p.pass);
        int flags = PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_MUTABLE;
        IntentSender sender = PendingIntent.getActivity(this, (int) System.nanoTime(), intent, flags).getIntentSender();

        RemoteViews view = new RemoteViews(getPackageName(), R.layout.autofill_item);
        view.setTextViewText(R.id.autofill_text, "用密匣填充");
        // 数据集级认证：用户在密匣里选定后，系统直接填入这一条，不再二次选择
        Dataset.Builder ds = new Dataset.Builder(view);
        if (p.user != null) ds.setValue(p.user, null, view);
        if (p.pass != null) ds.setValue(p.pass, null, view);
        ds.setAuthentication(sender);
        FillResponse response = new FillResponse.Builder().addDataset(ds.build()).build();
        callback.onSuccess(response);
    }

    @Override
    public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        // 保存由用户在密匣里主动完成，不接收系统转来的明文
        callback.onSuccess();
    }

    private void walk(AssistStructure.ViewNode node, Parsed p) {
        if (node.getWebDomain() != null && p.webDomain == null) {
            p.webDomain = node.getWebDomain();
            if (android.os.Build.VERSION.SDK_INT >= 28) p.webScheme = node.getWebScheme();
        }
        classify(node, p);
        for (int i = 0; i < node.getChildCount(); i++) walk(node.getChildAt(i), p);
    }

    private void classify(AssistStructure.ViewNode node, Parsed p) {
        AutofillId id = node.getAutofillId();
        if (id == null || node.getAutofillType() != View.AUTOFILL_TYPE_TEXT) return;
        String[] hints = node.getAutofillHints();
        if (hints != null) {
            for (String h : hints) {
                String v = h.toLowerCase(Locale.ROOT);
                if (v.contains("password") && p.pass == null) {
                    p.pass = id;
                    return;
                }
                if ((v.contains("username") || v.contains("email") || v.contains("phone")) && p.user == null) {
                    p.user = id;
                    return;
                }
            }
        }
        int type = node.getInputType();
        int variation = type & InputType.TYPE_MASK_VARIATION;
        boolean pwd = (type & InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT
            && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD
                || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
                || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        String idEntry = node.getIdEntry() == null ? "" : node.getIdEntry().toLowerCase(Locale.ROOT);
        String html = htmlType(node);
        if (pwd || "password".equals(html) || idEntry.contains("password") || idEntry.contains("passwd")) {
            if (p.pass == null) p.pass = id;
            return;
        }
        boolean userish = variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
            || "email".equals(html)
            || idEntry.contains("user")
            || idEntry.contains("account")
            || idEntry.contains("login")
            || idEntry.contains("email")
            || idEntry.contains("phone");
        if (userish && p.user == null) p.user = id;
        else if (p.user == null && p.pass == null && "text".equals(html)) p.user = id;
    }

    private String htmlType(AssistStructure.ViewNode node) {
        android.view.ViewStructure.HtmlInfo info = node.getHtmlInfo();
        if (info == null || info.getAttributes() == null) return "";
        for (android.util.Pair<String, String> a : info.getAttributes()) {
            if ("type".equals(a.first) && a.second != null) return a.second.toLowerCase(Locale.ROOT);
        }
        return "";
    }
}
