package online.feian.mixia;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

/**
 * 到时清除剪贴板。复制后切到别的 App 是主要用法，而系统（实测 HyperOS）会冻结后台进程，
 * 普通定时器在切走后不触发，密码就一直留在剪贴板。短时前台服务让进程在这几十秒里保持运行。
 * 不需要通知权限：没有权限时通知不显示，服务照常工作。
 */
public class ClipboardClearService extends Service {
    static final String EXTRA_SECONDS = "seconds";
    private static final String CHANNEL = "clipboard";
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable finish = () -> {
        clearNow(this);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    };

    static void clearNow(Context c) {
        ClipboardManager cm = (ClipboardManager) c.getSystemService(Context.CLIPBOARD_SERVICE);
        try {
            if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip();
            else cm.setPrimaryClip(ClipData.newPlainText("", ""));
        } catch (RuntimeException ignored) {
            // 没有更多可做的
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, "剪贴板清除", NotificationManager.IMPORTANCE_MIN));
        Notification n = new Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("密匣")
            .setContentText("复制的内容稍后自动清除")
            .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE);
        } else {
            startForeground(1, n);
        }
        int seconds = intent == null ? 30 : intent.getIntExtra(EXTRA_SECONDS, 30);
        // 再次复制时重新计时
        handler.removeCallbacks(finish);
        handler.postDelayed(finish, Math.max(5, seconds) * 1000L);
        return START_NOT_STICKY;
    }

    /** 短时服务最多三分钟，超时前必须结束。 */
    @Override
    public void onTimeout(int startId, int fgsType) {
        handler.removeCallbacks(finish);
        finish.run();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
