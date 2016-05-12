package br.com.adelannucci;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author andre.vannucci
 */
public class Main {

    public static final int KEY_SIZE = 128;
    public static final int BUFFER_SIZE = 13107200;
    public static final int CIPHER_BUFFER_SIZE = 13107216;
    
    

    public static final int SALT_BYTES = 16; // equal 128 bits
    public static final int IV_BYTES = 12; // equal 96 bits
    public static final int TAG_BYTES = 12; // equal 96 bits
    public static final int GCM_TAG_LENGTH = 128; // in bits
    public static final int KEY_GEN_ITERATIONS = 10000;

    private static byte[] decrypt(SecretKey key, byte[] iv, byte[] aad, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            //aad[1]++;
            cipher.updateAAD(aad);
            byte[] out = cipher.doFinal(data);
            return out;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    private static byte[] encrypt(SecretKey key, byte[] iv, byte[] aad, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            cipher.updateAAD(aad);
            byte[] cipherText = cipher.doFinal(data);

            return cipherText;

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    private static byte[] secureRandonGen(int size) {
        try {
            byte[] out = new byte[size];
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.nextBytes(out);
            return out;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private static SecretKey keyGen(char[] passfree, byte[] salt) {
        try {

            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            //SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            KeySpec spec = new PBEKeySpec(passfree, salt, KEY_GEN_ITERATIONS, KEY_SIZE);
            SecretKey tmp = skf.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
            return secret;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private static void encFile(SecretKey key, byte[] aad) {
        InputStream fileInputStream = null;
        Cipher cipher;
        Cipher decipher;
        List<byte[]> ivs = new ArrayList();

        try {
            String uri = "got.mkv";
            fileInputStream = new BufferedInputStream(new FileInputStream(uri));
            FileOutputStream fileOutputStream = new FileOutputStream("file.enc");

            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;

            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                byte[] cipherText;
                byte[] iv = secureRandonGen(IV_BYTES);
                ivs.add(iv);

                if (bytesRead != BUFFER_SIZE) {
                    byte[] aux = new byte[bytesRead];
                    System.arraycopy(buffer, 0, aux, 0, bytesRead);
                    cipherText = encrypt(key, iv, aad, aux);

                } else {
                    cipherText = encrypt(key, iv, aad, buffer);
                }
                
                fileOutputStream.write(cipherText, 0, cipherText.length);
            }
            
            writeIVs(ivs);
        } catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fileInputStream.close();
            } catch (IOException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

    }

    private static void decFile(SecretKey key, byte[] aad) {
        InputStream fileInputStream = null;
        Cipher cipher;
        String uri = "file.enc";
        List<byte[]> ivs = readIVs();

        if (isExistFile(uri)) {
            try {
                fileInputStream = new BufferedInputStream(new FileInputStream(uri));
                FileOutputStream fileOutputStream = new FileOutputStream("dec.mkv");
                byte[] buffer = new byte[CIPHER_BUFFER_SIZE];
                byte[] clearText;
                int bytesRead;
                int acc = 0;
                
                while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                    byte[] iv = (byte[]) ivs.get(acc);

                    if (bytesRead != CIPHER_BUFFER_SIZE) {
                        byte[] aux = new byte[bytesRead];
                        System.arraycopy(buffer, 0, aux, 0, bytesRead);
                        clearText = decrypt(key, iv, aad, aux);
                    } else {
                        clearText = decrypt(key, iv, aad, buffer);
                    }
                    acc++;
                    fileOutputStream.write(clearText, 0, clearText.length);
                }
            } catch (Exception ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                try {
                    fileInputStream.close();
                } catch (IOException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    private static void writeMetaFile(byte[] aad, byte[] salt) {
        FileOutputStream fileOutputStream = null;

        try {
            String uri = "meta.inc";
            fileOutputStream = new FileOutputStream(uri);
            fileOutputStream.write(aad, 0, aad.length);
            fileOutputStream.write(salt, 0, salt.length);
        } catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fileOutputStream.close();
            } catch (IOException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    private static Map readMetaFile() {
        InputStream fileInputStream = null;
        Map<String, byte[]> map = new HashMap<String, byte[]>();
        String uri = "meta.inc";

        if (!isExistFile(uri)) {
            return null;
        }

        try {
            fileInputStream = new BufferedInputStream(new FileInputStream(uri));

            byte[] aad = new byte[12];
            byte[] salt = new byte[16];
            int bytesRead;
            
            if ((bytesRead = fileInputStream.read(aad)) != -1) {
                map.put("aad", aad);
            }

            if ((bytesRead = fileInputStream.read(salt)) != -1) {
                map.put("salt", salt);
            }

            fileInputStream.close();
            return map;
        } catch (Exception ex) {
            return null;
        }
    }
    
    private static void writeIVs(List<byte[]> ivs) {
        FileOutputStream fileOutputStream = null;

        try {
            String uri = "ivs.meta";
            fileOutputStream = new FileOutputStream(uri);
            for(byte[] iv : ivs){
                fileOutputStream.write(iv, 0, iv.length);
            }
        } catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fileOutputStream.close();
            } catch (IOException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    private static List<byte[]> readIVs() {
        InputStream fileInputStream = null;
        List<byte[]> ivs = new ArrayList<>();
        String uri = "ivs.meta";

        if (!isExistFile(uri)) {
            return null;
        }

        try {
            fileInputStream = new BufferedInputStream(new FileInputStream(uri));
            byte[] iv = new byte[12];
            int bytesRead;

            while ((bytesRead = fileInputStream.read(iv)) != -1) {
                byte[] aux = new byte[bytesRead];
                System.arraycopy(iv, 0, aux, 0, bytesRead);
                ivs.add(aux);
            }
            
            fileInputStream.close();
            return ivs;
        } catch (Exception ex) {
            return null;
        }
    }

    private static boolean isExistFile(String uri) {
        File f = new File(uri);
        return (f.exists() && !f.isDirectory());
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        System.out.println("PASSFREE: " + args[0]);
        Security.addProvider(new BouncyCastleProvider());
        SecretKey secretKey;

        byte[] salt;
        byte[] iv;
        byte[] aad;

        Map map = readMetaFile();

        if (map == null) {
            System.out.println("chipher ... ");
            aad = secureRandonGen(TAG_BYTES);
            salt = secureRandonGen(SALT_BYTES);

            secretKey = keyGen(args[0].toCharArray(), salt);
            writeMetaFile(aad, salt);
            encFile(secretKey,aad);
            System.out.println("end.");
        } else {
            System.out.println("dechipher ... ");
            aad = (byte[]) map.get("aad");
            salt = (byte[]) map.get("salt");

            secretKey = keyGen(args[0].toCharArray(), salt);
            decFile(secretKey, aad);
            System.out.println("end.");
        }

    }
}
