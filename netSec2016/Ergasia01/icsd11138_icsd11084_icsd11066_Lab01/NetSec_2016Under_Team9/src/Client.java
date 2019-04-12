
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import net.i2p.I2PException;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.data.DataFormatException;
import net.i2p.data.Destination;

public class Client {

    SecureRandom random = new SecureRandom();

    public static void main(String[] args) throws IOException, InterruptedException, ClassNotFoundException, NoSuchAlgorithmException, KeyStoreException, CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Exception {

        I2PSocketManager manager = I2PSocketManagerFactory.createManager();
        System.out.println("Please enter a Destination:");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String destinationString;
        try {
            destinationString = br.readLine();
        } catch (IOException ex) {
            System.out.println("Failed to get a Destination string.");
            return;
        }
        Destination destination;
        try {
            destination = new Destination(destinationString);
        } catch (DataFormatException ex) {
            System.out.println("Destination string incorrectly formatted.");
            return;
        }
        I2PSocket socket;
        try {
            socket = manager.connect(destination);
        } catch (I2PException ex) {
            System.out.println("General I2P exception occurred!");
            return;
        } catch (ConnectException ex) {
            System.out.println("Failed to connect!");
            return;
        } catch (NoRouteToHostException ex) {
            System.out.println("Couldn't find host!");
            return;
        } catch (InterruptedIOException ex) {
            System.out.println("Sending/receiving was interrupted!");
            return;
        }
        try {
            startClient(socket);
            socket.close();
        } catch (IOException ex) {
            System.out.println("Error occurred while sending/receiving!");
        }

    }

    private static void startClient(I2PSocket socket) throws IOException, ClassNotFoundException, CertificateException, KeyStoreException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IllegalBlockSizeException, IllegalBlockSizeException, IllegalBlockSizeException, IllegalBlockSizeException, BadPaddingException, IllegalBlockSizeException, Exception {
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
//============== o client stelnei minima xairetismou  ======================== 

        Message packet = new Message("Hello");

        out.writeObject(packet);

        out.flush();

//============== o server exei dexthei to minima xairetismou kai mas stelnei ena cookie =============
//============== anamenei to cookie tou pisw mazi me ena diko mou                       =============
        packet = (Message) in.readObject();
        SecureRandom random = new SecureRandom();
        String output = new BigInteger(130, random).toString(32);     // dimiourgw to coockie      

        packet.setcookieC(output);                                  // vazw to cookie sto paketo

        packet.setSuppSymmCryp1("AES");
        packet.setSuppSymmCryp2("DES");
        packet.setsuppIntegrity1("HmacSHA256");
        packet.setsuppIntegrity2("HmacSHA1");
        out.writeObject(packet);                                    // kai to stelnw

        out.flush();

//============== lipsi pistopoihtikou apo server mazi me tis epilegmenes suites ==========================  
        packet = (Message) in.readObject();                           // pernw to minima apo ton server
        // me tis epilegmenes suites 

        File file = new File("downloadedCRT.crt");                  // kai tha akolouthisei i lipsi tou crt
        byte[] content = (byte[]) in.readObject();

        Files.write(file.toPath(), content);

////========================== store certificate ======== 
        FileInputStream fis = new FileInputStream("downloadedCRT.crt");
        BufferedInputStream bis = new BufferedInputStream(fis);             //gia na perasw to crt

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        KeyStore ks = KeyStore.getInstance("JKS");                          // keystore

        ks.load(null, null);
        while (bis.available() > 0) {
            Certificate certif = cf.generateCertificate(bis);
            ks.setCertificateEntry("my", certif);                            // pernaw to crt sto keystore me pseudwnimo my             
        }
        //System.out.println(ks.getCertificate("my"));
//=============== validate of certification =====================           
        List mylist = new ArrayList();
        Certificate c = ks.getCertificate("my");

        mylist.add(c);

        CertPath cp = cf.generateCertPath(mylist);

        Certificate trust = ks.getCertificate("my");
        TrustAnchor anchor = new TrustAnchor((X509Certificate) trust, null);
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));

        params.setRevocationEnabled(false);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");      // se periptwsi pou to validate apotuxei // se periptwsi pou to validate apotuxei

        try {                                                                // egiretai exeptions
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
            //System.out.println(result);
        } catch (InvalidAlgorithmParameterException iape) {                 // an den epivevaiothei to crt
            System.err.println("validation failed: " + iape);               // kleinei i epikoinwnia
            socket.close();
            System.out.println("---------- Den epivevaiwthike i egurotita tou pistopoihtikou ---------");
            System.exit(1);
        } catch (CertPathValidatorException cpve) {
            System.err.println("validation failed: " + cpve);
            System.err.println("index of certificate that caused exception: "
                    + cpve.getIndex());
            socket.close();
            System.out.println("---------- Den epivevaiwthike i egurotita tou pistopoihtikou ---------");
            System.exit(1);

        }
//================ dimiourgia RN 128 bits       =========================
//================ sinopsi SHA256               =========================
//================ dimiourgia 2 kleidiwn        =========================           

        String rn = new BigInteger(128, random).toString(32);                 //dimiourgia alphanumeric mikous 128 bits
        //  System.out.println(rn);

        String text = packet.getcookieS() + packet.getcookieC() + rn;             // coockieBOB+coockeAlice+RN

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));

        byte confidentialityKEY[] = null;
        byte integrityKEY[] = null;                                         // kovw to hash sti mesi kai dimiourgw dio kleidia

        confidentialityKEY = Arrays.copyOfRange(hash, 0, 16);                 //kathe thesi 1 bytes=8bits
        integrityKEY = Arrays.copyOfRange(hash, 17, 32);

//            System.out.println(confidentialityKEY.toString());
//            System.out.println(integrityKEY.toString());
//========== get public key from certificate            ====================
//========== and encrypt rn with public key from crt    ==================== 
        Certificate cert = ks.getCertificate("my");                         // vriskw to crt tou server mesa apo to keystore mou
        PublicKey publicKey = cert.getPublicKey();                          // kai pairnw to public key apo auto   

        //System.out.println(publicKey.toString());    
        Cipher cipher = Cipher.getInstance("RSA");                          // kryptografw to rn me assymtri kruptografia

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);                        // me to public key pou mou edwse o server
        byte[] cipherText = null;
        try {
            cipherText = cipher.doFinal(rn.getBytes());
            //System.out.println("cipher: " + new String(cipherText));
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

        String suites = packet.getSelectedSymmCryp() + " " + packet.getSelectedIntegrity();

        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(integrityKEY, "HmacSHA256");   //xrisimopoiw ws kleidi to integrityKey

        sha256_HMAC.init(secret_key);

        byte[] dataBytes = suites.getBytes(StandardCharsets.UTF_8);
        byte[] res = sha256_HMAC.doFinal(dataBytes);
        String res1 = new String(res);
        //System.out.println(res1);

//=========== set the packet and send to server ================            
        packet.setCipherText(cipherText = cipherText);
        packet.sethmac(res);

        out.writeObject(packet);

        out.flush();
//============= irthe kryptografimeno minima apo ton server =============================    
        packet = (Message) in.readObject();
        ShaCrypto integ = new ShaCrypto();
        SymmetricCrypto conf = new SymmetricCrypto();
        byte[] decMess = packet.getEncMessage();

        if (packet.getSelectedSymmCryp().endsWith("AES")) {                   try {
            // apokryptografoume prwta gia empisteutikotita
            decMess = conf.aes_decrypt(decMess, confidentialityKEY);
            } catch (Exception ex) {
                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            try {
                decMess = conf.des_decrypt(decMess, confidentialityKEY);
            } catch (Exception ex) {
                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
            }
        }                                                                   // apokryptografoume meta gia akeraiotita
        byte[] mess = integ.decSHa(decMess, integrityKEY, packet.getSelectedIntegrity());
        //System.out.println(new String(mess));                               // vlepoume to minima

        in.close();

        out.close();

        socket.close();

        
    }

}

