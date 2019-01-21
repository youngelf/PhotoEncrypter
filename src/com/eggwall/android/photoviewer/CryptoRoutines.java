package com.eggwall.android.photoviewer;

import java.io.*;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Crypto routines that are identical to the Android program. This allows a quicker way to iterate on the
 * algorithms and also the development of standalone Java (yikes!) program to encrypt and decrypt files.
 *
 * Some day I would love to write this in plain C.
 */
class CryptoRoutines {
    /** AES Encryption with Block Cipher and PKCS5 padding */
    static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5PADDING";

    static private final Charset UTF_8 = Charset.forName("UTF-8");

    /**
     * Decrypt a byte array using AES with CBC, PKC5_PADDING.
     *
     * @param cipherText the text to decode
     * @param iv the initialization vector
     * @param key the secret key
     * @return the decoded text.
     * @throws Exception
     */
    public static byte[] decrypt(byte[] cipherText, byte[] iv, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("text: " + bToS(plainText) + ", cipherText: " + bToS(cipherText));
        return plainText;
    }

    /**
     * Holder for the text (ciphertext or plaintext) and the initialization vector.
     * Android has the Pair class, which can be used to hold these two together. Rather than add a Collections object,
     * I'm just lumping them together.
     */
    static class TextVector {
        byte[] text;
        byte[] initializationVector;
    }

    /**
     * Test routine to encrypt a string. This will return both the encrypted text and the IV that
     * you need to feed back to the decrypt routine.
     *
     * This uses AES with CBC, PKC5_PADDING making it the inverse operation of
     * {@link CryptoRoutines#decrypt(byte[], byte[], SecretKey)}
     * @param plainText the text to encrypt.
     * @param key the secret key.
     * @return a Pair containing the cipherText, and the Initialization Vector
     * @throws Exception
     */
    public static TextVector encrypt(byte[] plainText, SecretKey key) throws Exception {
        TextVector v = new TextVector();
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(plainText);
        key.getEncoded();
        byte[] iv = cipher.getIV();
        System.out.println("text: " + bToS(plainText) + ", cipherText: " + bToS(cipherText));
        System.out.println("IV: " + bToS(iv));
        v.text = cipherText;
        v.initializationVector = iv;
        return v;
    }

    /**
     * Decrypt a file.
     *
     * @param cipherPath the path of the file to read. This file must be readable
     * @param iv the initialization vector to use to decrypt
     * @param key the secret key used to decrypt
     * @param plainPath the location where the decrypted file is to be placed. This location must
     *                  be writable
     * @return true if the operation succeeded
     * @throws Exception
     */
    public static boolean decrypt(String cipherPath, byte[] iv, SecretKey key, String plainPath)
            throws Exception {
        // Open the input file
        File cipherFile = new File(cipherPath);


        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
        FileInputStream fis = new FileInputStream(cipherFile);
        BufferedInputStream bis = new BufferedInputStream(fis);
        CipherInputStream cis = new CipherInputStream(bis, cipher);

        // Create a file to write to.
        File toWrite = new File(plainPath);
        final int fourMegs = 4 * 1024 * 1024;
        byte[] buffer = new byte[fourMegs];
        boolean couldCreate = toWrite.createNewFile();
        if (!couldCreate) {
            System.out.println("Could not create file " + plainPath);
            return false;
        }
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(toWrite));
        int numBytes;
        while ((numBytes = cis.read(buffer)) > 0) {
            out.write(buffer, 0, numBytes);
        }
        out.close();
        System.out.println("Wrote text: " + plainPath);
        return true;
    }

    /**
     * Encrypt a file.
     *
     * @param plainPath the path of the file to encrypt. This path must be readable.
     * @param key the secret to use to encrypt the file
     * @param cipherPath the location where the encrypted file is to be written. This must be
     *                   writable
     * @return the byte array containing the initialization vector.
     * @throws Exception
     */
    public static byte[] encrypt(String plainPath, SecretKey key, String cipherPath)
            throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        File f = new File(plainPath);
        FileInputStream fis = new FileInputStream(f);

        File toWrite = new File(cipherPath);
        final int fourMegs = 4 * 1024 * 1024;
        byte[] buffer = new byte[fourMegs];

        boolean couldCreate = toWrite.createNewFile();
        if (!couldCreate) {
            System.out.println("Could not create the new file " + cipherPath);
            return null;
        }
        BufferedInputStream bis = new BufferedInputStream(fis);
        FileOutputStream fos = new FileOutputStream(toWrite);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        CipherOutputStream cos = new CipherOutputStream(bos, cipher);

        int numBytes;
        while ((numBytes = bis.read(buffer)) > 0) {
            System.out.println("encrypt read " + numBytes + " bytes.");
            cos.write(buffer, 0, numBytes);
        }
        cos.close();
        System.out.println("Wrote text: " + cipherPath);
        return iv;
    }

    /**
     * Base64 encoding of input byte
     * @param in
     * @return
     */
    public static String bToS(byte[] in) {
        Base64.Encoder e = Base64.getEncoder();
        return e.encodeToString(in);
    }

    /**
     * decode a string into its byte.
     * @param in
     * @return
     */
    public static byte[] STob(String in) {
        Base64.Decoder d = Base64.getDecoder();
        return d.decode(in);
    }

    /**
     * Create an AES key for use with the encrypt/decrypt routines.
     * @return an AES SecretKey
     */
    public static SecretKey generateKey() {
        SecretKey key = null;
        try {
            key = KeyGenerator.getInstance("AES").generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Key creation failed! ");
            e.printStackTrace();
        }
        return key;
    }

    /**
     * Create an AES SecretKey using the Base64-encoded string provided here.
     * @param in a Base64 encoded string obtained from {@link CryptoRoutines#generateKey()}
     * @return the Secret key
     */
    public static SecretKey keyFromString(String in) {
        return new SecretKeySpec(STob(in), "AES");
    }


    /**
     * Simple method to test encryption and decryption and show a result to the user.
     * @return true if the test passed
     */
    public static boolean decryptTextTest() {
        // Let's experiment with a given Base64 encoded key.
        String keyHardcode="SOh7N8bl1R5ZoJrGLzhzjA==";

        // And let's try out encrypting and decrypting
        try {
            SecretKey skey = keyFromString(keyHardcode);

            String key = bToS(skey.getEncoded());
            System.out.println("I generated this crazy long key: " + key);
            String expected = "This is a long message";
            byte[] testMessage = expected.getBytes(UTF_8);
            TextVector m = encrypt(testMessage, skey);

            byte[] cipherText = m.text;
            byte[] iv = m.initializationVector;
            // Let's print that out, and see what we can do with it.
            System.out.println("I got cipherText " + bToS(cipherText));

            // And decrypt
            byte[] plainText = decrypt(cipherText, iv, skey);
            // And let's print that out.
            String observed = new String(plainText, UTF_8);
            System.out.println("I got this message back: " + observed);

            if (expected.matches(observed)) {
                System.out.println("Test PASSED");
                return true;
            } else {
                System.out.println("Test Failed!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Simple method to test encryption and decryption of a stream and show a result to the user.
     * @return true if the test passed
     */
    public static boolean decryptFileTest() {
        // Let's experiment with a given key.
        String keyHardcode="SOh7N8bl1R5ZoJrGLzhzjA==";
        final String currentPath;
        try {
            currentPath = new File(".").getCanonicalPath();
        } catch (IOException e) {
            System.out.println("Failed to get canonical path for current directory.");
            e.printStackTrace();
            return false;
        }

        // And let's try out encrypting and decrypting
        try {
            SecretKey skey = keyFromString(keyHardcode);

            String key = bToS(skey.getEncoded());
            System.out.println("I generated this crazy long key: " + key);
            String expected = "This is a long message";
            String plainPath = currentPath.concat(File.pathSeparator).concat("plain.txt");
            String cipherPath = currentPath.concat(File.pathSeparator).concat("cipher.txt");
            // First, delete the file.
//            if ((new File(cipherPath)).delete()) {
//                System.out.printf("Old cipher file deleted.");
//            }

            byte[] iv = encrypt(plainPath, skey, cipherPath);
            if (iv == null) {
                System.out.println("Encryption failed");
                return false;
            }
            System.out.println("Encryption succeeded. IV = " + bToS(iv));

            // Try to decrypt.
            String testPlainPath = currentPath.concat(File.pathSeparator).concat("test.txt");
            boolean result = decrypt(cipherPath, iv, skey, testPlainPath);
            if (!result) {
                System.out.println("Decryption failed for  " + testPlainPath);
                return false;
            }
            // TODO: Check here to see if the file has some text in there.
            return true;
        } catch (Exception e) {
            System.out.println("Decryption failed. Error follows:");
            e.printStackTrace();
        }
        // And now delete the file.
        return false;
    }
}
