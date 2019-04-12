
import java.security.Key;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SymmetricCrypto {
    private String choosenAlgo;

    SymmetricCrypto(){
        this.choosenAlgo="AES";             // default symmetrikos algorithmos o AES
    }
    SymmetricCrypto(String algo){
        this.choosenAlgo=algo;
    }
    public String getChoosenAlgo(){return this.choosenAlgo;}  
    public void setChoosenAlgo(String algo){this.choosenAlgo=algo;}
 //=============== AES ======================
    public byte[] aes_encrypt(byte [] input,byte[] key) throws Exception{
        SecretKeySpec skeySpec= new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
         byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec);
        byte[] ciphertext =  cipher.doFinal(input);
    
        return ciphertext;
  }
    public byte[] aes_decrypt (byte[] ciphertext,byte[] key) throws Exception{
        SecretKeySpec skeySpec= new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
         byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec);

        byte[] plaintext = cipher.doFinal(ciphertext);       
        return plaintext;
    
  }
 //=============== DES ======================
  
    public byte[] des_encrypt(byte text[],byte[] key) throws Exception {
        Cipher cipher = null;
        SecretKeySpec skeySpec= new SecretKeySpec(key, "DES");
        cipher.init(1, skeySpec);
        byte data[] = text;
        byte encryptedData[] = cipher.doFinal(data);
        return encryptedData;
  }
    public byte[] des_decrypt(byte[] encText,byte[] key) throws Exception {
        Cipher cipher = null;
        SecretKeySpec skeySpec= new SecretKeySpec(key, "DES");
        cipher.init(2, skeySpec);
        byte encryptedData[] = encText;
        byte decryptedData[] = cipher.doFinal(encryptedData);
        return decryptedData;
  }
 //====================================================
    
}
