package online.feian.mixia;

import android.os.Bundle;
import android.view.WindowManager;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(MixiaNativePlugin.class);
        super.onCreate(savedInstanceState);
        // 禁止截屏、录屏和最近任务缩略图。只有可调试的调试版放开，方便在真机上录屏验收动效；正式版不可调试，始终禁止
        boolean debuggable = (getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        if (!debuggable) {
            getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }
    }
}
