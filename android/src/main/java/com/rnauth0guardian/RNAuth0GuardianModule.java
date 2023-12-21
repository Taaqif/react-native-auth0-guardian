//
//  RNAuth0GuardianModule.java
//  RNAuth0Guardian
//
//  Created by Mukhammad Ali on 2020/01/07.
//  Copyright © 2020. All rights reserved.
//

package com.rnauth0guardian;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import android.content.SharedPreferences;
import android.util.Log;
import android.net.Uri;
import android.util.Base64;

import com.auth0.android.guardian.sdk.CurrentDevice;
import com.auth0.android.guardian.sdk.Enrollment;
import com.auth0.android.guardian.sdk.Notification;
import com.auth0.android.guardian.sdk.ParcelableNotification;
import com.auth0.android.guardian.sdk.networking.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;
import com.auth0.android.guardian.sdk.Guardian;
import com.auth0.android.guardian.sdk.GuardianAPIClient;
import com.facebook.react.bridge.ReadableMap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.NoSuchAlgorithmException;
import java.util.Map;

import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;

import com.auth0.android.guardian.sdk.networking.RequestFactory;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import static android.content.Context.MODE_PRIVATE;


public class RNAuth0GuardianModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;
  private static final String TAG = RNAuth0GuardianModule.class.getName();

  private Guardian guardian;
  SharedPreferences mPrefs;
  private ParcelableEnrollment enrollment;

  private static final String ENROLLMENT = "ENROLLMENT";
  private static final Exception DEVICE_NOT_ENROLLED_EXCEPTION = new IllegalStateException("DEVICE_NOT_ENROLLED");

  public RNAuth0GuardianModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
    mPrefs = this.reactContext.getSharedPreferences("myPrefsKeys", MODE_PRIVATE);
  }

  private ParcelableEnrollment getEnrollment(){
    String json = mPrefs.getString(ENROLLMENT, "");
    Log.e(TAG, json);
    return ParcelableEnrollment.fromJSON(json);
  }

  private void saveEnrollment(Enrollment data){
    SharedPreferences.Editor prefsEditor = mPrefs.edit();
    ParcelableEnrollment parcelableEnrollment = new ParcelableEnrollment(data);
    enrollment = parcelableEnrollment;
    String json = parcelableEnrollment.toJSON();
    prefsEditor.putString(ENROLLMENT, json);
    prefsEditor.commit();
  }

  @ReactMethod
  public void initializeWithUrl(String domain, Promise promise) {
    Log.d(TAG, "Initialized attempted:" + domain);
    Uri url = new Uri.Builder()
      .scheme("https")
      .authority(domain)
      .build();
    Log.d(TAG, "url built" + url.toString());

    try {
      Guardian.Builder builder = new Guardian.Builder();
      Log.d(TAG, "Builder created");
      builder.enableLogging();
      Log.d(TAG, "logging enabled");
      builder.url(url);
      Log.d(TAG, "url assigned");
      guardian = builder.build();
      Log.d(TAG, "Builder complete");

      enrollment = getEnrollment();
      Log.i("SAVED ENROLLMENT", enrollment.toJSON());
      promise.resolve(true);
    } catch (Exception err){
      promise.reject(err);
    }
  }

  private GuardianAPIClient buildGuardianApiClient(String domain) {
    // reflect to make access the constructor
    Class<?> guardianApiClientClass = Class.forName("com.auth0.android.guardian.sdk.Guardian");
    Constructor<?> guardianApiClientConstructor = guardianApiClientClass.getDeclaredConstructor(RequestFactory.class, HttpUrl.class);
    guardianApiClientConstructor.setAccessible(true);

    Uri url = new Uri.Builder()
      .scheme("https")
      .authority(domain)
      .build();

    final OkHttpClient.Builder builder = new OkHttpClient.Builder();

    final String clientInfo = Base64.encodeToString(
        String.format("{\"name\":\"Guardian.Android\",\"version\":\"%s\"}",
          "1.0").getBytes(),
        Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

    builder.addInterceptor(new Interceptor() {
      @Override
      public Response intercept(Chain chain) throws IOException {
        okhttp3.Request originalRequest = chain.request();
        okhttp3.Request requestWithUserAgent = originalRequest.newBuilder()
          .header("Accept-Language",
              "en")
          .header("User-Agent",
              String.format("GuardianSDK/%s Android %s",
                "1.0",
                "21"))
          .header("Auth0-Client", clientInfo)
          .build();
        return chain.proceed(requestWithUserAgent);
      }
    });

    OkHttpClient client = builder.build();

    Gson gson = new GsonBuilder().create();

    RequestFactory requestFactory = new RequestFactory(gson, client);

    GuardianAPIClient guardianAPIClient = (GuardianAPIClient) guardianApiClientConstructor.newInstance(requestFactory, url);
    return guardianAPIClient;
  }

  @ReactMethod
  public void initialize(String domain, Promise promise) {
    Log.d(TAG, "Initialized attempted:" + domain);
    try {
      // reflect to make access the constructor
      Class<?> guardianClass = Class.forName("com.auth0.android.guardian.sdk.Guardian");
      Constructor<?> guardianConstructor = guardianClass.getDeclaredConstructor(GuardianAPIClient.class);
      guardianConstructor.setAccessible(true);

      guardian = (Guardian) guardianConstructor.newInstance(buildGuardianApiClient(domain));
      Log.d(TAG, "Builder complete");

      enrollment = getEnrollment();
      Log.i("SAVED ENROLLMENT", enrollment.toJSON());
      promise.resolve(true);
    } catch (Exception err){
      promise.reject(err);
    }
  }

  private KeyPair generateKeyPair() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048); // at least 2048 bits!
      return keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      Log.e(TAG, "Error generating keys", e);
    }

    return null;
  }

  @Override
  public String getName() {
    return "RNAuth0Guardian";
  }

  @ReactMethod
  public void enroll(String enrollmentURI, String FCMToken, final Promise promise){
    Log.i(TAG, "ENROLL ATTEMPTED");
    String deviceName = android.os.Build.MODEL;
    Log.i(TAG, "DEVICE MODEL: " + deviceName);
    CurrentDevice device = new CurrentDevice(this.reactContext, FCMToken, deviceName);
    Log.i(TAG, "DEVICE CONTEXT ESTABLISHED");
    try {
      KeyPair keyPair = generateKeyPair();
      if(keyPair != null) {
        guardian
          .enroll(enrollmentURI, device, keyPair)
          .start(new Callback<Enrollment>() {
            @Override
            public void onSuccess(Enrollment response) {
              Log.i(TAG, "ENROLLED SUCCESSFULLY!");
              promise.resolve(response.getSecret());
              saveEnrollment(response);
            }

            @Override
            public void onFailure(Throwable exception) {
              Log.i(TAG, "ENROLL FAILED!");
              promise.reject(exception);
            }
          });
      }

    } catch (Exception err){
      promise.reject(err);
      Log.e("AUTH0 GUARDIAN", "ENROLLMENT EXCEPTION", err);
    }

  }

  @ReactMethod
  public void getTOTP(Promise promise){
    try {
      if(enrollment != null){
        String totpCode = Guardian.getOTPCode(enrollment);
        promise.resolve(totpCode);
      } else {
        promise.reject(DEVICE_NOT_ENROLLED_EXCEPTION);
      }
    } catch (Exception err){
      promise.reject(err);
    }
  }


  @ReactMethod
  public void allow(ReadableMap data, final Promise promise) {
    Map parsedData = MapUtil.toMap(data);
    ParcelableNotification notification = Guardian.parseNotification(parsedData);
    try {

      if(enrollment != null) {
        guardian
          .allow(notification, enrollment)
          .start(new Callback<Void>() {
            @Override
            public void onSuccess(Void response) {
              Log.i(TAG, "ALLOWED SUCCESSFULLY");
              promise.resolve(true);
            }

            @Override
            public void onFailure(Throwable exception) {
              Log.e(TAG, "ALLOW FAILED!", exception);
              promise.reject(exception);
            }
          });
      } else {
        promise.reject(DEVICE_NOT_ENROLLED_EXCEPTION);
      }
    } catch (Exception err){
      Log.e(TAG, "ALLOW FAILED!", err);
      promise.reject(err);
    }
  }

  @ReactMethod
  public void reject(ReadableMap data, final Promise promise) {
    try {
      Map parsedData = MapUtil.toMap(data);
      Notification notification = Guardian.parseNotification(parsedData);

      if(enrollment != null) {
        guardian
          .reject(notification, enrollment)
          .start(new Callback<Void>() {
            @Override
            public void onSuccess(Void response) {
              Log.i(TAG, "REJECTED SUCCESSFULLY");
              promise.resolve(true);
            }

            @Override
            public void onFailure(Throwable exception) {
              Log.e(TAG, "REJECT FAILED!", exception);
              promise.reject(exception);
            }
          });
      } else {
        promise.reject(DEVICE_NOT_ENROLLED_EXCEPTION);
      }
    } catch (Exception err){
      Log.e(TAG, "REJECT FAILED!", err);
      promise.reject(err);
    }
  }

  @ReactMethod
  public void unenroll(final Promise promise){
    try {
      if(enrollment != null){
        guardian
          .delete(enrollment)
          .start(new Callback<Void>() {
            @Override
            public void onSuccess(Void response) {
              Log.i(TAG, "UNENROLLED SUCCESSFULLY");
              promise.resolve(true);
            }

            @Override
            public void onFailure(Throwable exception) {
              Log.e(TAG, "UNENROLL FAILED!", exception);
              promise.reject(exception);
            }
          });
      } else {
        promise.reject(DEVICE_NOT_ENROLLED_EXCEPTION);
      }
    } catch (Exception err) {
      Log.e(TAG, "UNENROLL FAILED!", err);
      promise.reject(err);
    }

  }
}
