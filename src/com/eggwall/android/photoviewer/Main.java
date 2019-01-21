package com.eggwall.android.photoviewer;

import javax.crypto.SecretKey;

import static com.eggwall.android.photoviewer.CryptoRoutines.STob;
import static com.eggwall.android.photoviewer.CryptoRoutines.bToS;
import static com.eggwall.android.photoviewer.CryptoRoutines.keyFromString;

public class Main {
    public static final int START = 0;
    public static void main(String[] args) {
        // -g: Generate a key.
        if (args[START].startsWith("-g") || args[START].startsWith("--gen")){
            SecretKey k = CryptoRoutines.generateKey();
            System.out.println("The key is: " + bToS(k.getEncoded()));
            return;
        }
        // -h: Help string.
        if (args[START].startsWith("-h") || args[START].startsWith("--help")){
            System.out.println("Syntax: main "
                    + "\n\t[-h||--help] : Print Help message"
                    + "\n\t[-g||--generate] : Generate a key"
                    + "\n\t[-e||--encrypt] input.zip output.asc <Base64_Key> : Encrypt a file"
                    + "\n\t[-d||--decrypt] input.asc <Base64_Key> <Base64_Input_vector> output.zip : Decrypt a file"
            );
            return;
        }
        // -e: Encrypt file.
        if (args[START].startsWith("-e") || args[START].startsWith("--encrypt")){
            String plainTextFile = args[START + 1];
            String cipherFile = args[START + 2];
            SecretKey key = keyFromString(args[START + 3]);

            // Now encrypt the file.
            try {
                byte[] iv = CryptoRoutines.encrypt(plainTextFile, key, cipherFile);

                // Print the initial vector
                System.out.println("\nInitialization Vector = " + bToS(iv));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return;
        }
        // -d: Decrypt file
        if (args[START].startsWith("-d") || args[START].startsWith("--decrypt")){
            String cipherFile = args[START + 1];
            SecretKey key = keyFromString(args[START + 2]);
            byte[] initialVector = STob(args[START + 3]);
            String plainTextFile = args[START + 4];

            // Now decrypt the file.
            try {
                CryptoRoutines.decrypt(cipherFile, initialVector, key, plainTextFile);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return;
        }
        return;
    }
}
