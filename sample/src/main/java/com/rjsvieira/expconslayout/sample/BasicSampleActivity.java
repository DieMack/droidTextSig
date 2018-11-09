package com.rjsvieira.expconslayout.sample;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import com.xpandit.datastructures.SignatureData;

/**
 * Created by ricardo.vieira
 * Kelvin Inc
 */
public class BasicSampleActivity extends Activity {

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_basic_sample);
        SignatureData signatureData = new SignatureData();
        Log.d("BasicSampleActivity", signatureData.toString());
    }

}
