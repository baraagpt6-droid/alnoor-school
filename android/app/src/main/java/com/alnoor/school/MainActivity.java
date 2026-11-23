package com.alnoor.school;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.animation.AlphaAnimation;

public class MainActivity extends Activity {
    private WebView webView;
    private View splash;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(Color.rgb(28,25,20));
        getWindow().setNavigationBarColor(Color.rgb(28,25,20));
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.rgb(28,25,20));
        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setLoadsImagesAutomatically(true);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setMediaPlaybackRequiresUserGesture(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        CookieManager.getInstance().setAcceptCookie(true);
        webView.setWebChromeClient(new WebChromeClient());
        webView.setWebViewClient(new WebViewClient() {
            @Override public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                // Remove the HTML splash behind the native overlay to avoid a second loading screen.
                view.evaluateJavascript("document.getElementById('instant-splash')?.remove();", null);
                hideSplashWhenReady(view);
            }
        });
        root.addView(webView, new FrameLayout.LayoutParams(-1, -1));
        splash = buildSplash();
        root.addView(splash, new FrameLayout.LayoutParams(-1, -1));
        setContentView(root);
        if (savedInstanceState == null) webView.loadUrl("file:///android_asset/www/index.html");
        else webView.restoreState(savedInstanceState);
    }

    private void hideSplashWhenReady(WebView view) {
        final long started = SystemClock.elapsedRealtime();
        final Handler handler = new Handler(getMainLooper());
        final Runnable[] check = new Runnable[1];
        check[0] = () -> {
            if (splash == null) return;
            view.evaluateJavascript("document.getElementById('root') && document.getElementById('root').children.length > 0 ? 'ready' : 'waiting'", value -> {
                boolean ready = value != null && value.contains("ready") && !value.contains("waiting");
                boolean timeout = SystemClock.elapsedRealtime() - started > 10000;
                if (ready || timeout) {
                    AlphaAnimation fade = new AlphaAnimation(1f, 0f);
                    fade.setDuration(260);
                    splash.startAnimation(fade);
                    splash.setVisibility(View.GONE);
                    splash = null;
                } else {
                    handler.postDelayed(check[0], 100);
                }
            });
        };
        handler.post(check[0]);
    }

    private View buildSplash() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER_HORIZONTAL | Gravity.CENTER_VERTICAL);
        layout.setPadding(dp(24), dp(24), dp(24), dp(24));
        layout.setBaselineAligned(false);
        GradientDrawable bg = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.rgb(74,55,27), Color.rgb(28,25,20)});
        layout.setBackground(bg);
        ImageView logo = new ImageView(this);
        logo.setImageResource(com.alnoor.school.R.drawable.ic_launcher);
        logo.setScaleType(ImageView.ScaleType.FIT_CENTER);
        LinearLayout.LayoutParams imageParams = new LinearLayout.LayoutParams(dp(116), dp(116));
        imageParams.bottomMargin = dp(14);
        imageParams.gravity = Gravity.CENTER_HORIZONTAL;
        layout.addView(logo, imageParams);
        TextView title = new TextView(this);
        title.setText("مدرسة النور");
        title.setTextColor(Color.rgb(240,210,94));
        title.setTextSize(28);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setGravity(Gravity.CENTER);
        title.setTextAlignment(View.TEXT_ALIGNMENT_CENTER);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(-1, -2);
        titleParams.gravity = Gravity.CENTER_HORIZONTAL;
        layout.addView(title, titleParams);
        TextView subtitle = new TextView(this);
        subtitle.setText("المنصة التعليمية الذكية");
        subtitle.setTextColor(Color.rgb(229,212,168));
        subtitle.setTextSize(13);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setTextAlignment(View.TEXT_ALIGNMENT_CENTER);
        LinearLayout.LayoutParams textParams = new LinearLayout.LayoutParams(-1, -2);
        textParams.gravity = Gravity.CENTER_HORIZONTAL;
        textParams.topMargin = dp(6);
        layout.addView(subtitle, textParams);
        return layout;
    }

    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    @Override protected void onSaveInstanceState(Bundle out) { if (webView != null) webView.saveState(out); super.onSaveInstanceState(out); }
    @Override public void onBackPressed() { if (webView != null && webView.canGoBack()) webView.goBack(); else super.onBackPressed(); }
    @Override protected void onDestroy() { if (webView != null) { webView.stopLoading(); webView.setWebChromeClient(null); webView.setWebViewClient(null); webView.destroy(); webView = null; } super.onDestroy(); }
}
