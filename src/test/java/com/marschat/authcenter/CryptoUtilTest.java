package com.marschat.authcenter;

import com.marschat.authcenter.util.CryptoUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AES-256-GCM 加密工具测试 (auth-center)")
class CryptoUtilTest {

    private CryptoUtil cryptoUtil;

    @BeforeEach
    void setUp() {
        // Base64 of 32-byte key
        cryptoUtil = new CryptoUtil("YWVzLTI1Ni1nY20ta2V5LTMyLWJ5dGVzISE=");
    }

    @Test
    @DisplayName("加密解密 round-trip 正确")
    void encryptDecryptRoundTrip() {
        String plaintext = "my-secret-api-token-12345";
        String encrypted = cryptoUtil.encrypt(plaintext);
        
        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);
        
        String decrypted = cryptoUtil.decrypt(encrypted);
        assertEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("每次加密生成不同密文（随机IV）")
    void encryptProducesDifferentCiphertext() {
        String plaintext = "same-input";
        String enc1 = cryptoUtil.encrypt(plaintext);
        String enc2 = cryptoUtil.encrypt(plaintext);
        
        assertNotEquals(enc1, enc2);
        assertEquals(plaintext, cryptoUtil.decrypt(enc1));
        assertEquals(plaintext, cryptoUtil.decrypt(enc2));
    }

    @Test
    @DisplayName("解密无效数据抛出异常")
    void decryptInvalidData() {
        assertThrows(Exception.class, () -> cryptoUtil.decrypt("invalid-base64-data!!!"));
    }
}
