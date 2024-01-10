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

import android.content.SharedPreferences;
import android.util.Log;
import android.util.Base64;

import com.auth0.android.guardian.sdk.CurrentDevice;
import com.auth0.android.guardian.sdk.Enrollment;
import com.auth0.android.guardian.sdk.Notification;
import com.auth0.android.guardian.sdk.ParcelableNotification;
import com.auth0.android.guardian.sdk.networking.Callback;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.Promise;
import com.auth0.android.guardian.sdk.Guardian;
import com.facebook.react.bridge.ReadableMap;

import java.lang.reflect.Type;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import static android.content.Context.MODE_PRIVATE;

public class RNAuth0GuardianModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;
  private static final String TAG = RNAuth0GuardianModule.class.getName();
  private static final Gson JSON = new GsonBuilder().create();

  private Guardian guardian;
  SharedPreferences mPrefs;
  private ArrayList<ParcelableEnrollment> enrollments;

  private static final String ENROLLMENTS = "ENROLLMENTS";
  private static final Exception DEVICE_NOT_ENROLLED_EXCEPTION = new IllegalStateException("DEVICE_NOT_ENROLLED");

  public RNAuth0GuardianModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
    mPrefs = this.reactContext.getSharedPreferences("RNAuth0GuardianPrefs", MODE_PRIVATE);
  }

  private ArrayList<ParcelableEnrollment> getEnrollments() {
    String json = mPrefs.getString(ENROLLMENTS, "[]");
    Type enrollmentListType = new TypeToken<ArrayList<ParcelableEnrollment>>(){}.getType();
    return JSON.fromJson(json, enrollmentListType);
  }

  private ParcelableEnrollment getEnrollment(final String enrollmentId) {
    ParcelableEnrollment enrollment = null;
    if (enrollmentId != null && !enrollmentId.trim().isEmpty()) {
      enrollment = enrollments.stream().filter(e -> e.getId().equals(enrollmentId)).findFirst().orElse(null);
    }else if (enrollments.size() == 1){
      enrollments.stream().findFirst();
    }
    return enrollment;

  }

  private void saveEnrollment(ParcelableEnrollment data) {
    SharedPreferences.Editor prefsEditor = mPrefs.edit();
    enrollments.add(data);
    String json = JSON.toJson(enrollments);
    prefsEditor.putString(ENROLLMENTS, json);
    prefsEditor.commit();
  }

  @ReactMethod
  public void initialize(String domain, Promise promise) {
    Log.i(TAG, "Initialized attempted:" + domain);
    try {
      guardian = new Guardian.Builder()
              .domain(domain)
              .build();
      Log.i(TAG, "Builder complete");

      enrollments = getEnrollments();
      if (enrollments != null) {
        Log.i(TAG, enrollments.size() + " ENROLLMENTS FOUND");
      } else {
        Log.i(TAG, "ENROLLMENT IS EMPTY");
      }
      promise.resolve(true);
    } catch (Exception err) {
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
  private void getEnrollments(final Promise promise) {

    Log.i(TAG, "GETTING ENROLLMENTS");
    try {

      WritableArray writableArray = Arguments.createArray();

      for (ParcelableEnrollment item : enrollments) {
        // Convert each item to a WritableMap and add it to the array
        WritableMap writableMap = item.toWritableMap();
        writableArray.pushMap(writableMap);
      }
      promise.resolve(writableArray);
    } catch (Exception err) {
      promise.reject(err);
      Log.e(TAG, "COULD NOT GET ENROLLMENTS", err);
    }
  }

  @ReactMethod
  public void enroll(String enrollmentURI, String FCMToken, final Promise promise) {
    Log.i(TAG, "ENROLL ATTEMPTED");
    String deviceName = android.os.Build.MODEL;
    Log.i(TAG, "DEVICE MODEL: " + deviceName);
    CurrentDevice device = new CurrentDevice(this.reactContext, FCMToken, deviceName);
    Log.i(TAG, "DEVICE CONTEXT ESTABLISHED");
    try {
      KeyPair keyPair = generateKeyPair();
      if (keyPair != null) {
        guardian
            .enroll(enrollmentURI, device, keyPair)
            .start(new Callback<Enrollment>() {
              @Override
              public void onSuccess(Enrollment response) {
                Log.i(TAG, "ENROLLED SUCCESSFULLY!");
                ParcelableEnrollment parcelableEnrollment = new ParcelableEnrollment(response);
                saveEnrollment(parcelableEnrollment);
                promise.resolve(parcelableEnrollment.toWritableMap());
              }

              @Override
              public void onFailure(Throwable exception) {
                Log.i(TAG, "ENROLL FAILED!");
                promise.reject(exception);
              }
            });
      }

    } catch (Exception err) {
      promise.reject(err);
      Log.e(TAG, "ENROLLMENT EXCEPTION", err);
    }

  }

  @ReactMethod
  public void getTOTP(String enrollmentId, Promise promise) {
    try {

      ParcelableEnrollment enrollment = getEnrollment(enrollmentId);
      if (enrollment != null) {
        String totpCode = Guardian.getOTPCode(enrollment);
        promise.resolve(totpCode);
      } else {
        promise.reject(DEVICE_NOT_ENROLLED_EXCEPTION);
      }
    } catch (Exception err) {
      promise.reject(err);
    }
  }

  @ReactMethod
  public void allow(ReadableMap data, final Promise promise) {
    Map parsedData = MapUtil.toMap(data);
    ParcelableNotification notification = Guardian.parseNotification(parsedData);
    ParcelableEnrollment enrollment = getEnrollment(notification.getEnrollmentId());
    try {

      if (enrollment != null) {
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
    } catch (Exception err) {
      Log.e(TAG, "ALLOW FAILED!", err);
      promise.reject(err);
    }
  }

  @ReactMethod
  public void reject(ReadableMap data, final Promise promise) {
    try {
      Map parsedData = MapUtil.toMap(data);
      Notification notification = Guardian.parseNotification(parsedData);
      ParcelableEnrollment enrollment = getEnrollment(notification.getEnrollmentId());

      if (enrollment != null) {
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
    } catch (Exception err) {
      Log.e(TAG, "REJECT FAILED!", err);
      promise.reject(err);
    }
  }

  @ReactMethod
  public void getAllEnrollments(final Promise promise) {
    try {
      promise.resolve(JSON);
    } catch (Exception err) {
      Log.e(TAG, "GETTING ALL ENROLLMENTS FAILED!", err);
      promise.reject(err);
    }

  }

  @ReactMethod
  public void unenroll(final String enrollmentId, final Promise promise) {
    try {
      ParcelableEnrollment enrollment = getEnrollment(enrollmentId);
      if (enrollment != null) {
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
