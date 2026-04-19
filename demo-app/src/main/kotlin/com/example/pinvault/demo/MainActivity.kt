package com.example.pinvault.demo

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.example.pinvault.demo.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.cardTlsTls.setOnClickListener {
            startActivity(Intent(this, TlsToTlsActivity::class.java))
        }
        binding.cardTlsMtls.setOnClickListener {
            startActivity(Intent(this, TlsToMtlsActivity::class.java))
        }
        binding.cardMtlsTls.setOnClickListener {
            startActivity(Intent(this, MtlsToTlsActivity::class.java))
        }
        binding.cardMtlsMtls.setOnClickListener {
            startActivity(Intent(this, MtlsToMtlsActivity::class.java))
        }
        binding.cardVaultFiles.setOnClickListener {
            startActivity(Intent(this, VaultFileDemoActivity::class.java))
        }
        binding.cardVaultSecurity.setOnClickListener {
            startActivity(Intent(this, VaultSecurityDemoActivity::class.java))
        }
    }
}
