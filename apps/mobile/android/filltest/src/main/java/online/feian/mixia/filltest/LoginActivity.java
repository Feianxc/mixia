package online.feian.mixia.filltest;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;

/** 验收用的最小登录页：记录被填入的内容；获得焦点时记录剪贴板，用来验证自动清除。 */
public class LoginActivity extends Activity {
    private EditText field(String hint, int type, String autofill) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setInputType(type);
        e.setAutofillHints(autofill);
        e.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_YES);
        e.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(Editable s) {
                Log.i("FillTest", hint + "=" + s);
            }
        });
        return e;
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(40, 300, 40, 40);
        l.addView(field("user", InputType.TYPE_CLASS_TEXT, View.AUTOFILL_HINT_USERNAME));
        l.addView(field("pass", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD, View.AUTOFILL_HINT_PASSWORD));
        setContentView(l);
    }

    @Override
    public void onWindowFocusChanged(boolean focus) {
        super.onWindowFocusChanged(focus);
        if (!focus) return;
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        ClipData c = cm.getPrimaryClip();
        String text = c == null || c.getItemCount() == 0 ? "<empty>" : String.valueOf(c.getItemAt(0).coerceToText(this));
        Log.i("FillTest", "clip=" + text);
    }
}
