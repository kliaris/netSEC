
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public class ShaCrypto {
    private String choosenAlgo;

    ShaCrypto(){
        this.choosenAlgo="HmacSHA256";             // default algorithmos o Sha256
    }
    ShaCrypto(String algo){                         // hmac md5/Sha1/Sha256
        this.choosenAlgo=algo;
    }
    public String getChoosenAlgo(){return this.choosenAlgo;}  
    public void setChoosenAlgo(String algo){this.choosenAlgo=algo;}
    
//============ SHA-1 ================
    public byte[] encSHa(byte[] input,byte[] key,String algo) throws NoSuchAlgorithmException, InvalidKeyException{
        Mac sha256_HMAC = Mac.getInstance(algo);
        SecretKeySpec secret_key = new SecretKeySpec(key, algo);                //xrisimopoiw ws kleidi to integrityKey
        sha256_HMAC.init(secret_key);

        byte[] dataBytes = input;
        byte[] res = sha256_HMAC.doFinal(dataBytes);
        return res;
    }
    
    public byte[] decSHa(byte[] res,byte[] key,String algo) throws NoSuchAlgorithmException, InvalidKeyException{
        StringBuffer hash = new StringBuffer();
        String digest =null;
        for (int i = 0; i < res.length; i++) {
          String hex = Integer.toHexString(0xFF & res[i]);
          if (hex.length() == 1) {
            hash.append('0');
          }
          hash.append(hex);
        }
        digest = hash.toString();
        return digest.getBytes();
    }
}
