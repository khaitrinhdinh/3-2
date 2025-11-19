package com.example.securechat;

import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import com.example.securechat.CryptoManager;
import com.example.securechat.crypto.AlgorithmSelector;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes4.dex */
public class LoginActivity extends AppCompatActivity {
    private static final String BASE_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev";
    private static final String HOSTNAME = "crypto-assignment.dangduongminhnhat2003.workers.dev";
    private static final String SPKI_BASE64 = "LLarg8tqQEn0O1lsHVG6pyTY/WtrtilDwKj8ZRwTWeI=";
    private static final String TAG = "LoginActivity";
    private TextView algorithmInfo;
    private OkHttpClient client;
    private CryptoManager cryptoManager;
    private Button loginButton;
    private SharedPreferences prefs;
    private ProgressDialog progressDialog;
    private String sessionToken;
    private String userId;
    private EditText userIdInput;

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (RootDetection.isDeviceRooted(this)) {
            showRootDetectedDialog();
            return;
        }
        setContentView(R.layout.activity_login);
        initViews();
        setupUI();
        this.client = buildClient();
        String savedUserId = this.prefs.getString("userId", HttpUrl.FRAGMENT_ENCODE_SET);
        String savedSessionToken = this.prefs.getString("sessionToken", HttpUrl.FRAGMENT_ENCODE_SET);
        if (!savedUserId.isEmpty() && !savedSessionToken.isEmpty()) {
            attemptSessionRestore(savedUserId, savedSessionToken);
        }
    }

    private void showRootDetectedDialog() {
        new AlertDialog.Builder(this).setTitle("⚠️ Cảnh báo bảo mật").setMessage("Thiết bị của bạn đã bị root/jailbreak.\n\nVì lý do bảo mật, ứng dụng này không thể chạy trên thiết bị đã root.\n\nKhông nên cài đặt ứng dụng này ở thiết bị này.").setIcon(android.R.drawable.ic_dialog_alert).setCancelable(false).setPositiveButton("OK", new DialogInterface.OnClickListener() { // from class: com.example.securechat.LoginActivity$$ExternalSyntheticLambda1
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.m80xec9e85b(dialogInterface, i);
            }
        }).show();
    }

    /* renamed from: lambda$showRootDetectedDialog$0$com-example-securechat-LoginActivity, reason: not valid java name */
    /* synthetic */ void m80xec9e85b(DialogInterface dialog, int which) {
        finish();
        System.exit(0);
    }

    private void initViews() {
        this.userIdInput = (EditText) findViewById(R.id.userIdInput);
        this.loginButton = (Button) findViewById(R.id.loginButton);
        this.algorithmInfo = (TextView) findViewById(R.id.algorithmInfo);
        this.prefs = getSharedPreferences("SecureChat", 0);
    }

    private void setupUI() {
        showAlgorithmMapping();
        this.loginButton.setOnClickListener(new View.OnClickListener() { // from class: com.example.securechat.LoginActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.m79lambda$setupUI$1$comexamplesecurechatLoginActivity(view);
            }
        });
        this.userIdInput.addTextChangedListener(new TextWatcher() { // from class: com.example.securechat.LoginActivity.1
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                LoginActivity.this.updateAlgorithmDisplay(s.toString());
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
    }

    /* renamed from: lambda$setupUI$1$com-example-securechat-LoginActivity, reason: not valid java name */
    /* synthetic */ void m79lambda$setupUI$1$comexamplesecurechatLoginActivity(View v) {
        String userId = this.userIdInput.getText().toString().trim();
        if (userId.isEmpty()) {
            Toast.makeText(this, "Please enter User ID", 0).show();
        } else {
            startLoginProcess(userId);
        }
    }

    private void showAlgorithmMapping() {
        this.algorithmInfo.setText("Welcome to Secure Chat Application");
        this.algorithmInfo.setTextColor(getResources().getColor(android.R.color.black));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateAlgorithmDisplay(String userId) {
        if (userId.isEmpty()) {
            showAlgorithmMapping();
            return;
        }
        String algorithm = AlgorithmSelector.getAlgorithmForUser(userId);
        AlgorithmSelector.getAlgorithmDisplayName(algorithm);
        this.algorithmInfo.setText("Please enter Correct UserId");
        this.algorithmInfo.setTextColor(getResources().getColor(android.R.color.holo_blue_dark));
    }

    private OkHttpClient buildClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder().connectTimeout(15L, TimeUnit.SECONDS).readTimeout(30L, TimeUnit.SECONDS);
        if (0 == 0) {
            Log.d("SSL Pinning", "Have Pinning Here");
            CertificatePinner pinner = new CertificatePinner.Builder().add(HOSTNAME, "sha256/LLarg8tqQEn0O1lsHVG6pyTY/WtrtilDwKj8ZRwTWeI=").build();
            builder.certificatePinner(pinner);
        }
        return builder.build();
    }

    private void startLoginProcess(String userId) {
        this.userId = userId;
        showProgress("Initializing...");
        try {
            this.cryptoManager = new CryptoManager();
            this.cryptoManager.initializeForUser(userId);
            updateProgress("Creating session...");
            createSession();
        } catch (Exception e) {
            hideProgress();
            Log.e(TAG, "Error initializing crypto", e);
            showError("Failed to initialize encryption: " + e.getMessage());
        }
    }

    private boolean isNetworkAvailable() {
        NetworkInfo activeNetworkInfo;
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService("connectivity");
        return (connectivityManager == null || (activeNetworkInfo = connectivityManager.getActiveNetworkInfo()) == null || !activeNetworkInfo.isConnected()) ? false : true;
    }

    private void createSession() throws JSONException {
        try {
            String algorithm = AlgorithmSelector.getAlgorithmForUser(this.userId);
            Log.d(TAG, "Algorithm for user: " + algorithm);
            JSONObject requestBody = new JSONObject();
            requestBody.put("algorithm", algorithm);
            if ("ecdh".equals(algorithm)) {
                JSONObject curveParams = new JSONObject();
                curveParams.put("p", "6277101735386680763835789423207666416083908700390324961279");
                curveParams.put("a", "-3");
                curveParams.put("b", "2455155546008943817740293915197451784769108058161191238065");
                curveParams.put("Gx", "3289624317623424368845348028842487418520868978772050262753");
                curveParams.put("Gy", "5673242899673324591834582889556471730778853907191064256384");
                curveParams.put("order", "6277101735386680763835789423176059013767194773182842284081");
                requestBody.put("curveParameters", curveParams);
                Log.d(TAG, "Added ECDH curve parameters");
            }
            if ("ecdh_2".equals(algorithm)) {
                JSONObject curveParams2 = new JSONObject();
                curveParams2.put("p", "115792089210356248762697446949407573530086143415290314195533631308867097853951");
                curveParams2.put("a", "-3");
                curveParams2.put("b", "41058363725152142129326129780047268409114441015993725554835256314039467401291");
                curveParams2.put("Gx", "48439561293906451759052585252797914202762949526041747995844080717082404635286");
                curveParams2.put("Gy", "36134250956749795798585127919587881956611106672985015071877198253568414405109");
                curveParams2.put("order", "115792089210356248762697446949407573529996955224135760342422259061068512044369");
                requestBody.put("curveParameters", curveParams2);
                Log.d(TAG, "Added ECDH curve parameters");
            }
            RequestBody body = RequestBody.create(requestBody.toString(), MediaType.parse("application/json"));
            Request request = new Request.Builder().url("https://crypto-assignment.dangduongminhnhat2003.workers.dev/session/create?userId=" + this.userId).addHeader("x-user-id", this.userId).addHeader("Content-Type", "application/json").post(body).build();
            if (!isNetworkAvailable()) {
                hideProgress();
                showError("No internet connection!\nPlease check your network settings.");
            } else {
                this.client.newCall(request).enqueue(new AnonymousClass2());
            }
        } catch (Exception e) {
            hideProgress();
            Log.e(TAG, "Error creating session", e);
            showError("Failed to create session: " + e.getMessage());
        }
    }

    /* renamed from: com.example.securechat.LoginActivity$2, reason: invalid class name */
    class AnonymousClass2 implements Callback {
        AnonymousClass2() {
        }

        @Override // okhttp3.Callback
        public void onFailure(Call call, final IOException e) {
            Log.e(LoginActivity.TAG, "=== Request onFailure ===");
            Log.e(LoginActivity.TAG, "Error type: " + e.getClass().getSimpleName());
            Log.e(LoginActivity.TAG, "Error message: " + e.getMessage());
            if (e.getCause() != null) {
                Log.e(LoginActivity.TAG, "Error cause: " + e.getCause().getMessage());
            }
            e.printStackTrace();
            LoginActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.LoginActivity$2$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.m81lambda$onFailure$0$comexamplesecurechatLoginActivity$2(e);
                }
            });
        }

        /* renamed from: lambda$onFailure$0$com-example-securechat-LoginActivity$2, reason: not valid java name */
        /* synthetic */ void m81lambda$onFailure$0$comexamplesecurechatLoginActivity$2(IOException e) {
            LoginActivity.this.hideProgress();
            LoginActivity.this.handleNetworkError(e);
        }

        @Override // okhttp3.Callback
        public void onResponse(Call call, Response response) throws IOException {
            String responseBody = HttpUrl.FRAGMENT_ENCODE_SET;
            try {
                responseBody = response.body().string();
            } catch (Exception e) {
                Log.e(LoginActivity.TAG, "Error reading response body", e);
            }
            final String finalResponseBody = responseBody;
            final int responseCode = response.code();
            final boolean isSuccessful = response.isSuccessful();
            LoginActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.LoginActivity$2$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() throws JSONException {
                    this.f$0.m82lambda$onResponse$1$comexamplesecurechatLoginActivity$2(isSuccessful, responseCode, finalResponseBody);
                }
            });
        }

        /* renamed from: lambda$onResponse$1$com-example-securechat-LoginActivity$2, reason: not valid java name */
        /* synthetic */ void m82lambda$onResponse$1$comexamplesecurechatLoginActivity$2(boolean isSuccessful, int responseCode, String finalResponseBody) throws JSONException {
            if (!isSuccessful) {
                Log.e(LoginActivity.TAG, "Response not successful: " + responseCode);
                LoginActivity.this.hideProgress();
                LoginActivity.this.handleServerError(responseCode, finalResponseBody);
                return;
            }
            try {
                JSONObject jsonResponse = new JSONObject(finalResponseBody);
                if (!jsonResponse.getBoolean("success")) {
                    LoginActivity.this.hideProgress();
                    LoginActivity.this.showError("Server error: " + jsonResponse.optString("error"));
                    return;
                }
                LoginActivity.this.sessionToken = jsonResponse.getString("sessionToken");
                String serverAlgorithm = jsonResponse.getString("algorithm");
                JSONObject serverPublicKey = jsonResponse.getJSONObject("serverPublicKey");
                if (!jsonResponse.has("sessionSignature") || !jsonResponse.has("serverSignaturePublicKey")) {
                    LoginActivity.this.hideProgress();
                    Log.e(LoginActivity.TAG, "❌ SECURITY ERROR: Server did not provide signature!");
                    LoginActivity.this.showError("Security Error: Server signature missing!\nThis server is not secure. Please contact administrator.");
                    return;
                }
                try {
                    JSONObject sessionSignatureJson = jsonResponse.getJSONObject("sessionSignature");
                    JSONObject serverSigPubKey = jsonResponse.getJSONObject("serverSignaturePublicKey");
                    LoginActivity.this.cryptoManager.setServerSignaturePublicKey(serverSigPubKey);
                    String sessionId = extractSessionIdFromJWT(LoginActivity.this.sessionToken);
                    if (sessionId.isEmpty()) {
                        LoginActivity.this.hideProgress();
                        LoginActivity.this.showError("Failed to extract session ID from token");
                        return;
                    }
                    JSONObject sessionData = new JSONObject();
                    sessionData.put("sessionId", sessionId);
                    sessionData.put("algorithm", serverAlgorithm);
                    sessionData.put("userId", LoginActivity.this.userId);
                    sessionData.put("createdAt", extractCreatedAtFromJWT(LoginActivity.this.sessionToken));
                    String sessionDataString = sessionData.toString();
                    Log.d(LoginActivity.TAG, "Verifying session signature (MANDATORY)...");
                    boolean verified = LoginActivity.this.cryptoManager.verifyServerSignature(sessionDataString, sessionSignatureJson, serverSigPubKey);
                    if (!verified) {
                        LoginActivity.this.hideProgress();
                        Log.e(LoginActivity.TAG, "❌ SECURITY ALERT: Session signature verification FAILED!");
                        LoginActivity.this.showError("SECURITY ALERT!\n\nServer signature verification failed!\nThis could indicate:\n• Man-in-the-middle attack\n• Server compromise\n• Network tampering\n\nDO NOT PROCEED!");
                    } else {
                        Log.d(LoginActivity.TAG, "✅ Session signature verified successfully!");
                        Log.d(LoginActivity.TAG, "Proceeding to key exchange...");
                        LoginActivity.this.updateProgress("Exchanging keys...");
                        LoginActivity.this.performKeyExchange(serverPublicKey);
                    }
                } catch (Exception e) {
                    LoginActivity.this.hideProgress();
                    Log.e(LoginActivity.TAG, "Error verifying session signature", e);
                    LoginActivity.this.showError("Security Error: " + e.getMessage());
                }
            } catch (Exception e2) {
                LoginActivity.this.hideProgress();
                Log.e(LoginActivity.TAG, "Error parsing session response", e2);
                LoginActivity.this.showError("Failed to create session: " + e2.getMessage());
            }
        }

        private String extractSessionIdFromJWT(String jwtToken) {
            try {
                String[] parts = jwtToken.split("\\.");
                if (parts.length != 3) {
                    return HttpUrl.FRAGMENT_ENCODE_SET;
                }
                String payload = parts[1];
                while (payload.length() % 4 != 0) {
                    payload = payload + "=";
                }
                byte[] decodedBytes = Base64.decode(payload.replace('-', '+').replace('_', '/'), 2);
                String decodedString = new String(decodedBytes, "UTF-8");
                JSONObject payloadJson = new JSONObject(decodedString);
                return payloadJson.optString("sid", HttpUrl.FRAGMENT_ENCODE_SET);
            } catch (Exception e) {
                Log.e(LoginActivity.TAG, "Error extracting sessionId from JWT", e);
                return HttpUrl.FRAGMENT_ENCODE_SET;
            }
        }

        private long extractCreatedAtFromJWT(String jwtToken) {
            try {
                String[] parts = jwtToken.split("\\.");
                if (parts.length != 3) {
                    return System.currentTimeMillis();
                }
                String payload = parts[1];
                while (payload.length() % 4 != 0) {
                    payload = payload + "=";
                }
                byte[] decodedBytes = Base64.decode(payload.replace('-', '+').replace('_', '/'), 2);
                String decodedString = new String(decodedBytes, "UTF-8");
                JSONObject payloadJson = new JSONObject(decodedString);
                return payloadJson.optLong("createdAt", System.currentTimeMillis());
            } catch (Exception e) {
                Log.e(LoginActivity.TAG, "Error extracting createdAt from JWT", e);
                return System.currentTimeMillis();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void performKeyExchange(JSONObject serverPublicKey) throws JSONException {
        try {
            this.cryptoManager.generateKeyPair();
            JSONObject clientPublicKey = this.cryptoManager.getPublicKeyJson();
            this.cryptoManager.computeSharedSecret(serverPublicKey);
            JSONObject requestBody = new JSONObject();
            requestBody.put("sessionToken", this.sessionToken);
            requestBody.put("clientPublicKey", clientPublicKey);
            if (!this.cryptoManager.isSignatureSupported()) {
                hideProgress();
                showError("Signature not supported");
                return;
            }
            try {
                String publicKeyString = clientPublicKey.toString();
                Log.d(TAG, "Signing with EPHEMERAL key (key exchange)...");
                CryptoManager.SignatureWithPublicKey signResult = this.cryptoManager.signMessageEphemeral(publicKeyString);
                requestBody.put("clientPublicKeySignature", signResult.signature.toJSON());
                requestBody.put("clientSignaturePublicKey", signResult.publicKey);
                Log.d(TAG, "✅ Signed with EPHEMERAL key");
                RequestBody body = RequestBody.create(requestBody.toString(), MediaType.parse("application/json"));
                Request request = new Request.Builder().url("https://crypto-assignment.dangduongminhnhat2003.workers.dev/session/exchange?userId=" + this.userId).addHeader("x-user-id", this.userId).post(body).build();
                this.client.newCall(request).enqueue(new AnonymousClass3());
            } catch (Exception e) {
                hideProgress();
                Log.e(TAG, "Failed to sign", e);
                showError("Failed to sign: " + e.getMessage());
            }
        } catch (Exception e2) {
            hideProgress();
            Log.e(TAG, "Error in key exchange", e2);
            showError("Key exchange failed: " + e2.getMessage());
        }
    }

    /* renamed from: com.example.securechat.LoginActivity$3, reason: invalid class name */
    class AnonymousClass3 implements Callback {
        AnonymousClass3() {
        }

        @Override // okhttp3.Callback
        public void onFailure(Call call, final IOException e) {
            LoginActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.LoginActivity$3$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.m83lambda$onFailure$0$comexamplesecurechatLoginActivity$3(e);
                }
            });
        }

        /* renamed from: lambda$onFailure$0$com-example-securechat-LoginActivity$3, reason: not valid java name */
        /* synthetic */ void m83lambda$onFailure$0$comexamplesecurechatLoginActivity$3(IOException e) {
            LoginActivity.this.hideProgress();
            LoginActivity.this.handleNetworkError(e);
        }

        @Override // okhttp3.Callback
        public void onResponse(Call call, Response response) throws IOException {
            final String responseBody = response.body().string();
            final int responseCode = response.code();
            final boolean isSuccessful = response.isSuccessful();
            LoginActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.LoginActivity$3$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() throws JSONException {
                    this.f$0.m84lambda$onResponse$1$comexamplesecurechatLoginActivity$3(isSuccessful, responseBody, responseCode);
                }
            });
        }

        /* renamed from: lambda$onResponse$1$com-example-securechat-LoginActivity$3, reason: not valid java name */
        /* synthetic */ void m84lambda$onResponse$1$comexamplesecurechatLoginActivity$3(boolean isSuccessful, String finalResponseBody, int responseCode) throws JSONException {
            LoginActivity.this.hideProgress();
            if (isSuccessful) {
                try {
                    JSONObject jsonResponse = new JSONObject(finalResponseBody);
                    if (!jsonResponse.getBoolean("success")) {
                        String error = jsonResponse.optString("error", "Unknown error");
                        LoginActivity.this.showError("Key exchange failed: " + error);
                        return;
                    }
                    String updatedToken = jsonResponse.optString("sessionToken", LoginActivity.this.sessionToken);
                    LoginActivity.this.sessionToken = updatedToken;
                    if (!jsonResponse.has("clientSignatureVerified")) {
                        LoginActivity.this.showError("Server did not verify client signature");
                        return;
                    }
                    boolean clientSigVerified = jsonResponse.getBoolean("clientSignatureVerified");
                    if (!clientSigVerified) {
                        Log.e(LoginActivity.TAG, "❌ Server rejected client signature!");
                        LoginActivity.this.showError("SECURITY ERROR!\n\nServer rejected your signature.\nThis should never happen.\nPlease check your cryptographic implementation.");
                        return;
                    }
                    Log.d(LoginActivity.TAG, "✅ Server verified client signature successfully");
                    Log.d(LoginActivity.TAG, "✅ Mutual authentication complete");
                    if (LoginActivity.this.cryptoManager.isKeyExchangeComplete()) {
                        LoginActivity.this.saveSuccessfulLogin();
                        LoginActivity.this.proceedToChatActivity();
                        return;
                    } else {
                        LoginActivity.this.showError("Key exchange incomplete");
                        return;
                    }
                } catch (Exception e) {
                    Log.e(LoginActivity.TAG, "Error parsing key exchange response", e);
                    LoginActivity.this.showError("Failed to parse key exchange response: " + e.getMessage());
                    return;
                }
            }
            LoginActivity.this.handleServerError(responseCode, finalResponseBody);
        }
    }

    private void attemptSessionRestore(String savedUserId, String savedSessionToken) {
        showProgress("Restoring session...");
        Request request = new Request.Builder().url("https://crypto-assignment.dangduongminhnhat2003.workers.dev/session/status?token=" + savedSessionToken + "&userId=" + savedUserId).get().build();
        this.client.newCall(request).enqueue(new AnonymousClass4(savedUserId, savedSessionToken));
    }

    /* renamed from: com.example.securechat.LoginActivity$4, reason: invalid class name */
    class AnonymousClass4 implements Callback {
        final /* synthetic */ String val$savedSessionToken;
        final /* synthetic */ String val$savedUserId;

        AnonymousClass4(String str, String str2) {
            this.val$savedUserId = str;
            this.val$savedSessionToken = str2;
        }

        @Override // okhttp3.Callback
        public void onFailure(Call call, IOException e) {
            LoginActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.LoginActivity$4$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.m85lambda$onFailure$0$comexamplesecurechatLoginActivity$4();
                }
            });
        }

        /* renamed from: lambda$onFailure$0$com-example-securechat-LoginActivity$4, reason: not valid java name */
        /* synthetic */ void m85lambda$onFailure$0$comexamplesecurechatLoginActivity$4() {
            LoginActivity.this.hideProgress();
            Log.d(LoginActivity.TAG, "Session restore failed, need new login");
        }

        @Override // okhttp3.Callback
        public void onResponse(Call call, Response response) throws IOException {
            String responseBody = HttpUrl.FRAGMENT_ENCODE_SET;
            try {
                responseBody = response.body().string();
            } catch (Exception e) {
                Log.e(LoginActivity.TAG, "Error reading response body", e);
            }
            final String finalResponseBody = responseBody;
            final boolean isSuccessful = response.isSuccessful();
            LoginActivity loginActivity = LoginActivity.this;
            final String str = this.val$savedUserId;
            final String str2 = this.val$savedSessionToken;
            loginActivity.runOnUiThread(new Runnable() { // from class: com.example.securechat.LoginActivity$4$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() throws JSONException {
                    this.f$0.m86lambda$onResponse$1$comexamplesecurechatLoginActivity$4(isSuccessful, finalResponseBody, str, str2);
                }
            });
        }

        /* renamed from: lambda$onResponse$1$com-example-securechat-LoginActivity$4, reason: not valid java name */
        /* synthetic */ void m86lambda$onResponse$1$comexamplesecurechatLoginActivity$4(boolean isSuccessful, String finalResponseBody, String savedUserId, String savedSessionToken) throws JSONException {
            LoginActivity.this.hideProgress();
            if (isSuccessful) {
                try {
                    JSONObject result = new JSONObject(finalResponseBody);
                    boolean exists = result.getBoolean("exists");
                    if (exists) {
                        LoginActivity.this.proceedToChatActivity(savedUserId, savedSessionToken);
                    } else {
                        LoginActivity.this.clearSavedCredentials();
                    }
                    return;
                } catch (Exception e) {
                    LoginActivity.this.clearSavedCredentials();
                    return;
                }
            }
            LoginActivity.this.clearSavedCredentials();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveSuccessfulLogin() {
        CryptoSingleton.getInstance().setCryptoManager(this.cryptoManager);
        this.prefs.edit().putString("userId", this.userId).putString("sessionToken", this.sessionToken).putBoolean("freshLogin", true).apply();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void clearSavedCredentials() {
        CryptoSingleton.getInstance().clear();
        this.prefs.edit().clear().apply();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void proceedToChatActivity() {
        proceedToChatActivity(this.userId, this.sessionToken);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void proceedToChatActivity(String userId, String sessionToken) {
        Intent intent = new Intent(this, (Class<?>) ChatActivity.class);
        intent.putExtra("userId", userId);
        intent.putExtra("sessionToken", sessionToken);
        intent.putExtra("algorithmName", this.cryptoManager != null ? this.cryptoManager.getAlgorithmName() : "Unknown");
        intent.putExtra("freshLogin", true);
        startActivity(intent);
        finish();
    }

    private void showProgress(String message) {
        if (this.progressDialog == null) {
            this.progressDialog = new ProgressDialog(this);
            this.progressDialog.setCancelable(false);
        }
        this.progressDialog.setMessage(message);
        this.progressDialog.show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateProgress(String message) {
        if (this.progressDialog != null && this.progressDialog.isShowing()) {
            this.progressDialog.setMessage(message);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideProgress() {
        if (this.progressDialog != null && this.progressDialog.isShowing()) {
            this.progressDialog.dismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showError(String message) {
        new AlertDialog.Builder(this).setTitle("Login Error").setMessage(message).setPositiveButton("OK", (DialogInterface.OnClickListener) null).setIcon(android.R.drawable.ic_dialog_alert).show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleNetworkError(IOException e) {
        Log.e(TAG, "Network error", e);
        if (e.getMessage() != null && (e.getMessage().contains("Certificate pinning failure") || e.getMessage().contains("peer not authenticated"))) {
            showSSLPinningError();
        } else {
            showError("Network error: " + e.getMessage());
        }
    }

    private void showSSLPinningError() {
        new AlertDialog.Builder(this).setTitle("Security Warning").setMessage("SSL Certificate pinning failed. This could indicate a security issue or the server certificate has changed.").setPositiveButton("OK", (DialogInterface.OnClickListener) null).setIcon(android.R.drawable.ic_dialog_alert).show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleServerError(int statusCode, String responseBody) {
        String errorMessage = "Server error: " + statusCode;
        switch (statusCode) {
            case 400:
                errorMessage = "Bad request - Missing userId";
                break;
            case TypedValues.CycleType.TYPE_ALPHA /* 403 */:
                errorMessage = "Access forbidden - Invalid userId";
                break;
            case 429:
                errorMessage = "Daily quota exceeded";
                break;
            case 430:
                errorMessage = "Too many requests per minute";
                break;
        }
        showError(errorMessage);
    }
}