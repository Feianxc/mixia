package online.feian.mixia;

import android.os.Bundle;
import android.view.WindowManager;
import com.getcapacitor.BridgeActivity;

/**
 * 自动填充时由系统拉起，必须是普通 launchMode 才能把结果交回系统。
 * 加载同一个界面，用户解锁后选一条，只把这一条返回。
 */
public class AutofillActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(MixiaNativePlugin.class);
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
    }
}
