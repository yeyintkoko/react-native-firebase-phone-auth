package com.yeyintkoko.rnfirebasephoneauth;

import android.support.annotation.NonNull;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.FirebaseException;
import com.google.firebase.FirebaseTooManyRequestsException;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthInvalidCredentialsException;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.PhoneAuthCredential;
import com.google.firebase.auth.PhoneAuthProvider;

import java.util.concurrent.TimeUnit;

/**
 * Created by ACEBNK0104 on 09/08/2017.
 */

public class RNFirebasePhoneAuth extends ReactContextBaseJavaModule {

    private static final String TAG = "PhoneAuthActivity";
    private PhoneAuthProvider.ForceResendingToken mResendToken;
    private PhoneAuthProvider.OnVerificationStateChangedCallbacks mCallbacks;
    private Callback onSuccessCodeSend, onFailureCodeSend, onSuccessVerifyCode, onFailureVerifyCode;
    private ReactApplicationContext reactContext;

    public RNFirebasePhoneAuth(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;

        // Check if user is signed in (non-null) and update UI accordingly.
        FirebaseUser currentUser = FirebaseAuth.getInstance().getCurrentUser();
        if(currentUser != null) {
            Log.d(TAG, "User already signed in");
            signOut();
            Log.d(TAG, "User was signed out");
        }

        mCallbacks = new PhoneAuthProvider.OnVerificationStateChangedCallbacks() {

            @Override
            public void onVerificationCompleted(PhoneAuthCredential credential) {
                // This callback will be invoked in two situations:
                // 1 - Instant verification. In some cases the phone number can be instantly
                //     verified without needing to send or enter a verification code.
                // 2 - Auto-retrieval. On some devices Google Play services can automatically
                //     detect the incoming verification SMS and perform verificaiton without
                //     user action.
                Log.d(TAG, "onVerificationCompleted:" + credential);

                signInWithPhoneAuthCredential(credential);
            }

            @Override
            public void onVerificationFailed(FirebaseException e) {
                // This callback is invoked in an invalid request for verification is made,
                // for instance if the the phone number format is not valid.
                Log.w(TAG, "onVerificationFailed", e);
                if (e instanceof FirebaseAuthInvalidCredentialsException) {
                    // Invalid request
                    // ...
                    Log.w(TAG, "Invalid request", e);
                    onFailureCodeSend.invoke("Invalid request");
                } else if (e instanceof FirebaseTooManyRequestsException) {
                    // The SMS quota for the project has been exceeded
                    // ...
                    Log.w(TAG, "The SMS quota for the project has been exceeded", e);
                    onFailureCodeSend.invoke("The SMS quota for the project has been exceeded");
                } else {
                    onFailureCodeSend.invoke(e.getMessage());
                }

                // Show a message and update the UI
                // ...
            }

            @Override
            public void onCodeSent(String verificationId,
                                   PhoneAuthProvider.ForceResendingToken token) {
                // The SMS verification code has been sent to the provided phone number, we
                // now need to ask the user to enter the code and then construct a credential
                // by combining the code with a verification ID.
                Log.d(TAG, "onCodeSent:" + verificationId);

                // Save verification ID and resending token so we can use them later
                mResendToken = token;

                // ...
                onSuccessCodeSend.invoke(verificationId);
            }
        };
    }

    @Override
    public String getName() {
        return "RNFirebasePhoneAuth";
    }

    private void signInWithPhoneAuthCredential(PhoneAuthCredential credential) {
        FirebaseAuth.getInstance().signInWithCredential(credential)
                .addOnCompleteListener(this.reactContext.getCurrentActivity(), new OnCompleteListener<AuthResult>() {
                    @Override
                    public void onComplete(@NonNull Task<AuthResult> task) {
                        Log.w(TAG, "Verification completed");
                        if (task.isSuccessful()) {
                            // Sign in success, update UI with the signed-in user's information
                            Log.d(TAG, "signInWithCredential:success");

                            FirebaseUser user = task.getResult().getUser();
                            // ...
                            onSuccessVerifyCode.invoke("Verification success");
                        } else {
                            // Sign in failed, display a message and update the UI
                            Log.w(TAG, "signInWithCredential:failure", task.getException());
                            if (task.getException() instanceof FirebaseAuthInvalidCredentialsException) {
                                // The verification code entered was invalid
                                onFailureVerifyCode.invoke("The verification code entered was invalid");
                            } else {
                                onFailureVerifyCode.invoke("SignInWithCredential failed");
                            }
                        }
                    }
                });
    }

    @ReactMethod
    public void verifyPhoneNumber(String phoneNumber, final Callback errorCallback, final Callback successCallback) {
        onFailureCodeSend = errorCallback;
        onSuccessCodeSend = successCallback;
        PhoneAuthProvider.getInstance().verifyPhoneNumber(
                phoneNumber,        // Phone number to verify
                60,                 // Timeout duration
                TimeUnit.SECONDS,   // Unit of timeout
                this.reactContext.getCurrentActivity(),    // Activity (for callback binding)
                mCallbacks);        // OnVerificationStateChangedCallbacks
    }

    @ReactMethod
    public void verifyCode(String code, String verificationId, final Callback errorCallback, final Callback successCallback) {
        Log.d(TAG, code);
        onFailureVerifyCode = errorCallback;
        onSuccessVerifyCode = successCallback;
        if(verificationId != null && code != null) {
            Log.d(TAG, verificationId);
            PhoneAuthCredential credential = PhoneAuthProvider.getCredential(verificationId, code);            
            signInWithPhoneAuthCredential(credential);
        } else {
            Log.d(TAG, "verificationId or code is null");
            onFailureVerifyCode.invoke("verificationId or code is null");
        }
    }

    @ReactMethod
    public void signOut() {
        FirebaseAuth.getInstance().signOut();
    }
}
