package com.reactnativecommunity.webview;

// import android.webkit.WebView;
import com.tencent.smtt.sdk.WebView;

/**
 * Implement this interface in order to config your {@link WebView}. An instance of that
 * implementation will have to be given as a constructor argument to {@link RNCWebViewManager}.
 */
public interface WebViewConfig {

  void configWebView(WebView webView);
}
