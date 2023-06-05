package com.reactnativecommunity.webview;

import android.annotation.TargetApi;
import android.graphics.Bitmap;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;
import com.tencent.smtt.export.external.interfaces.HttpAuthHandler;

import com.tencent.smtt.export.external.interfaces.SslError;
import com.tencent.smtt.export.external.interfaces.SslErrorHandler;
import com.tencent.smtt.export.external.interfaces.WebResourceRequest;
import com.tencent.smtt.export.external.interfaces.WebResourceResponse;
import com.tencent.smtt.sdk.WebView;
import com.tencent.smtt.sdk.WebViewClient;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.core.util.Pair;

import com.facebook.common.logging.FLog;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.ThemedReactContext;
import com.facebook.react.uimanager.UIManagerHelper;
import com.reactnativecommunity.webview.events.TopHttpErrorEvent;
import com.reactnativecommunity.webview.events.TopLoadingErrorEvent;
import com.reactnativecommunity.webview.events.TopLoadingFinishEvent;
import com.reactnativecommunity.webview.events.TopLoadingStartEvent;
import com.reactnativecommunity.webview.events.TopRenderProcessGoneEvent;
import com.reactnativecommunity.webview.events.TopShouldStartLoadWithRequestEvent;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.atomic.AtomicReference;

public class RNCWebViewClient extends WebViewClient {
    private static String TAG = "RNCWebViewClient";
    protected static final int SHOULD_OVERRIDE_URL_LOADING_TIMEOUT = 250;

    protected boolean mLastLoadFailed = false;
    protected RNCWebView.ProgressChangedFilter progressChangedFilter = null;
    protected @Nullable String ignoreErrFailedForThisURL = null;
    protected @Nullable RNCBasicAuthCredential basicAuthCredential = null;

    public void setIgnoreErrFailedForThisURL(@Nullable String url) {
        ignoreErrFailedForThisURL = url;
    }

    public void setBasicAuthCredential(@Nullable RNCBasicAuthCredential credential) {
        basicAuthCredential = credential;
    }


  private WebResourceResponse proxyResource(String key, WebView view, WebResourceRequest request) {
    InputStream inputStream = null;

    String url = request.getUrl().toString();

    if (url.contains(key)) {
      String path = "data/data/com.wyntv/" + url.replace(key, "");
      try {
        String[] tmp = path.split("/");
        File file = new File(path.trim());
        String dirPath = "/";
        for (int i = 0; i < tmp.length -1; i++) {
          dirPath = dirPath + tmp[i] + "/";
        }
        File dir = new File(dirPath);
        if (file.exists()){
          inputStream = new FileInputStream(file);
        } else {
          dir.mkdirs();
          file.createNewFile();
          URL url1 = new URL(url);
          URLConnection connection = url1.openConnection();
          connection.connect();
          inputStream = connection.getInputStream();
          OutputStream outputStream = new FileOutputStream(file);
          byte[] buffer = new byte[8 * 1024];
          int read;
          while ((read = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, read);
          }
          outputStream.flush();
          inputStream = new FileInputStream(file);
        }
        WebResourceResponse response = null;
        if (url.contains(".js")) {
          response = new WebResourceResponse("text/javascript", "UTF-8", inputStream);
        } else if (url.contains(".css")) {
          response = new WebResourceResponse("text/css", "UTF-8", inputStream);
        }

        return response;
      } catch (Exception e) {
        e.printStackTrace();
      } finally {
      }
    }
    return null;
  }

  @Nullable
  @Override
  public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {

    String baseUrl = ((RNCWebView) view).baseUrl;

    WebResourceResponse response;
    response = this.proxyResource(baseUrl + "/api/PluginAssets", view, request);
    if (response != null) {
      return response;
    }
    response = this.proxyResource(baseUrl + "/api/themefiles", view, request);
    if (response != null) {
      return response;
    }
    return super.shouldInterceptRequest(view, request);
  }

    @Override
    public void onPageFinished(WebView webView, String url) {
        super.onPageFinished(webView, url);

        if (!mLastLoadFailed) {
            RNCWebView reactWebView = (RNCWebView) webView;

            reactWebView.callInjectedJavaScript();

            emitFinishEvent(webView, url);
        }
    }

    @Override
    public void doUpdateVisitedHistory (WebView webView, String url, boolean isReload) {
      super.doUpdateVisitedHistory(webView, url, isReload);

      ((RNCWebView) webView).dispatchEvent(
        webView,
        new TopLoadingStartEvent(
          webView.getId(),
          createWebViewEvent(webView, url)));
    }

    @Override
    public void onPageStarted(WebView webView, String url, Bitmap favicon) {
      super.onPageStarted(webView, url, favicon);
      mLastLoadFailed = false;

      RNCWebView reactWebView = (RNCWebView) webView;
      reactWebView.callInjectedJavaScriptBeforeContentLoaded();
    }

    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        final RNCWebView rncWebView = (RNCWebView) view;
        final boolean isJsDebugging = ((ReactContext) view.getContext()).getJavaScriptContextHolder().get() == 0;

        if (!isJsDebugging && rncWebView.mCatalystInstance != null) {
            final Pair<Double, AtomicReference<RNCWebViewModuleImpl.ShouldOverrideUrlLoadingLock.ShouldOverrideCallbackState>> lock = RNCWebViewModuleImpl.shouldOverrideUrlLoadingLock.getNewLock();
            final double lockIdentifier = lock.first;
            final AtomicReference<RNCWebViewModuleImpl.ShouldOverrideUrlLoadingLock.ShouldOverrideCallbackState> lockObject = lock.second;

            final WritableMap event = createWebViewEvent(view, url);
            event.putDouble("lockIdentifier", lockIdentifier);
            rncWebView.sendDirectMessage("onShouldStartLoadWithRequest", event);

            try {
                assert lockObject != null;
                synchronized (lockObject) {
                    final long startTime = SystemClock.elapsedRealtime();
                    while (lockObject.get() == RNCWebViewModuleImpl.ShouldOverrideUrlLoadingLock.ShouldOverrideCallbackState.UNDECIDED) {
                        if (SystemClock.elapsedRealtime() - startTime > SHOULD_OVERRIDE_URL_LOADING_TIMEOUT) {
                            FLog.w(TAG, "Did not receive response to shouldOverrideUrlLoading in time, defaulting to allow loading.");
                            RNCWebViewModuleImpl.shouldOverrideUrlLoadingLock.removeLock(lockIdentifier);
                            return false;
                        }
                        lockObject.wait(SHOULD_OVERRIDE_URL_LOADING_TIMEOUT);
                    }
                }
            } catch (InterruptedException e) {
                FLog.e(TAG, "shouldOverrideUrlLoading was interrupted while waiting for result.", e);
                RNCWebViewModuleImpl.shouldOverrideUrlLoadingLock.removeLock(lockIdentifier);
                return false;
            }

            final boolean shouldOverride = lockObject.get() == RNCWebViewModuleImpl.ShouldOverrideUrlLoadingLock.ShouldOverrideCallbackState.SHOULD_OVERRIDE;
            RNCWebViewModuleImpl.shouldOverrideUrlLoadingLock.removeLock(lockIdentifier);

            return shouldOverride;
        } else {
            FLog.w(TAG, "Couldn't use blocking synchronous call for onShouldStartLoadWithRequest due to debugging or missing Catalyst instance, falling back to old event-and-load.");
            progressChangedFilter.setWaitingForCommandLoadUrl(true);

            int reactTag = view.getId();
            UIManagerHelper.getEventDispatcherForReactTag((ReactContext) view.getContext(), reactTag).dispatchEvent(new TopShouldStartLoadWithRequestEvent(
                    reactTag,
                    createWebViewEvent(view, url)));
            return true;
        }
    }

    @TargetApi(Build.VERSION_CODES.N)
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        final String url = request.getUrl().toString();
        return this.shouldOverrideUrlLoading(view, url);
    }

    @Override
    public void onReceivedHttpAuthRequest(WebView view, HttpAuthHandler handler, String host, String realm) {
        if (basicAuthCredential != null) {
            handler.proceed(basicAuthCredential.username, basicAuthCredential.password);
            return;
        }
        super.onReceivedHttpAuthRequest(view, handler, host, realm);
    }

    @Override
    public void onReceivedSslError(final WebView webView, final SslErrorHandler handler, final SslError error) {
        // onReceivedSslError is called for most requests, per Android docs: https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(com.tencent.smtt.sdk.WebView,%2520android.webkit.SslErrorHandler,%2520android.net.http.SslError)
        // WebView.getUrl() will return the top-level window URL.
        // If a top-level navigation triggers this error handler, the top-level URL will be the failing URL (not the URL of the currently-rendered page).
        // This is desired behavior. We later use these values to determine whether the request is a top-level navigation or a subresource request.
        String topWindowUrl = webView.getUrl();
        String failingUrl = error.getUrl();

        // Cancel request after obtaining top-level URL.
        // If request is cancelled before obtaining top-level URL, undesired behavior may occur.
        // Undesired behavior: Return value of WebView.getUrl() may be the current URL instead of the failing URL.
        handler.cancel();

        if (!topWindowUrl.equalsIgnoreCase(failingUrl)) {
            // If error is not due to top-level navigation, then do not call onReceivedError()
            Log.w(TAG, "Resource blocked from loading due to SSL error. Blocked URL: "+failingUrl);
            return;
        }

        int code = error.getPrimaryError();
        String description = "";
        String descriptionPrefix = "SSL error: ";

        // https://developer.android.com/reference/android/net/http/SslError.html
        switch (code) {
            case android.net.http.SslError.SSL_DATE_INVALID:
                description = "The date of the certificate is invalid";
                break;
            case android.net.http.SslError.SSL_EXPIRED:
                description = "The certificate has expired";
                break;
            case android.net.http.SslError.SSL_IDMISMATCH:
                description = "Hostname mismatch";
                break;
            case android.net.http.SslError.SSL_INVALID:
                description = "A generic error occurred";
                break;
            case android.net.http.SslError.SSL_NOTYETVALID:
                description = "The certificate is not yet valid";
                break;
            case android.net.http.SslError.SSL_UNTRUSTED:
                description = "The certificate authority is not trusted";
                break;
            default:
                description = "Unknown SSL Error";
                break;
        }

        description = descriptionPrefix + description;

        this.onReceivedError(
                webView,
                code,
                description,
                failingUrl
        );
    }

    @Override
    public void onReceivedError(
            WebView webView,
            int errorCode,
            String description,
            String failingUrl) {

        if (ignoreErrFailedForThisURL != null
                && failingUrl.equals(ignoreErrFailedForThisURL)
                && errorCode == -1
                && description.equals("net::ERR_FAILED")) {

            // This is a workaround for a bug in the WebView.
            // See these chromium issues for more context:
            // https://bugs.chromium.org/p/chromium/issues/detail?id=1023678
            // https://bugs.chromium.org/p/chromium/issues/detail?id=1050635
            // This entire commit should be reverted once this bug is resolved in chromium.
            setIgnoreErrFailedForThisURL(null);
            return;
        }

        super.onReceivedError(webView, errorCode, description, failingUrl);
        mLastLoadFailed = true;

        // In case of an error JS side expect to get a finish event first, and then get an error event
        // Android WebView does it in the opposite way, so we need to simulate that behavior
        emitFinishEvent(webView, failingUrl);

        WritableMap eventData = createWebViewEvent(webView, failingUrl);
        eventData.putDouble("code", errorCode);
        eventData.putString("description", description);

        int reactTag = webView.getId();
        UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new TopLoadingErrorEvent(webView.getId(), eventData));
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void onReceivedHttpError(
            WebView webView,
            WebResourceRequest request,
            WebResourceResponse errorResponse) {
        super.onReceivedHttpError(webView, request, errorResponse);

        if (request.isForMainFrame()) {
            WritableMap eventData = createWebViewEvent(webView, request.getUrl().toString());
            eventData.putInt("statusCode", errorResponse.getStatusCode());
            eventData.putString("description", errorResponse.getReasonPhrase());

            int reactTag = webView.getId();
            UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new TopHttpErrorEvent(webView.getId(), eventData));
        }
    }

    @TargetApi(Build.VERSION_CODES.O)
    @Override
    public boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail detail) {
        // WebViewClient.onRenderProcessGone was added in O.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return false;
        }
        super.onRenderProcessGone(webView, detail);

        if(detail.didCrash()){
            Log.e(TAG, "The WebView rendering process crashed.");
        }
        else{
            Log.w(TAG, "The WebView rendering process was killed by the system.");
        }

        // if webView is null, we cannot return any event
        // since the view is already dead/disposed
        // still prevent the app crash by returning true.
        if(webView == null){
            return true;
        }

        WritableMap event = createWebViewEvent(webView, webView.getUrl());
        event.putBoolean("didCrash", detail.didCrash());
        int reactTag = webView.getId();
        UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new TopRenderProcessGoneEvent(webView.getId(), event));

        // returning false would crash the app.
        return true;
    }

    protected void emitFinishEvent(WebView webView, String url) {
        int reactTag = webView.getId();
        UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new TopLoadingFinishEvent(webView.getId(), createWebViewEvent(webView, url)));
    }

    protected WritableMap createWebViewEvent(WebView webView, String url) {
        WritableMap event = Arguments.createMap();
        event.putDouble("target", webView.getId());
        // Don't use webView.getUrl() here, the URL isn't updated to the new value yet in callbacks
        // like onPageFinished
        event.putString("url", url);
        event.putBoolean("loading", !mLastLoadFailed && webView.getProgress() != 100);
        event.putString("title", webView.getTitle());
        event.putBoolean("canGoBack", webView.canGoBack());
        event.putBoolean("canGoForward", webView.canGoForward());
        return event;
    }

    public void setProgressChangedFilter(RNCWebView.ProgressChangedFilter filter) {
        progressChangedFilter = filter;
    }
}