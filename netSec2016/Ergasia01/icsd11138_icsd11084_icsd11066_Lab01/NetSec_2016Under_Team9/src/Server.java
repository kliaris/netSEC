
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import net.i2p.I2PException;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.util.I2PThread;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;



public class Server {

    private static ServerSocket serverSocket;

    public static void main(String[] args) throws IOException {
//
//        serverSocket = new ServerSocket(8080);
//        while (true) {
//
//            System.out.println("I'm waiting for a client!!");   //perimenw na dexthw klisi        
//            Socket socket = serverSocket.accept();              // molis dexthika ena client
//            ServerThread st = new ServerThread(socket);         //dimiourgw ena kainourio threadServer
//
//            Thread t1 = new Thread(st);
//            t1.start();
//
//        }



        I2PSocketManager manager = I2PSocketManagerFactory.createManager();
        I2PServerSocket serverSocket = manager.getServerSocket();
        I2PSession session = manager.getSession();
        //Print the base64 string, the regular string would look like garbage.
        System.out.println(session.getMyDestination().toBase64());

        //Create socket to handle clients
        I2PThread t = new I2PThread(new ClientHandler(serverSocket));
        t.setName("clienthandler1");
        t.setDaemon(false);
        t.start();
    }
    
    private static class ClientHandler implements Runnable {

        public ClientHandler(I2PServerSocket socket) {
            this.socket = socket;
        }

        public void run() {
            while(true) {
                try {
                    I2PSocket sock = this.socket.accept();
                    if(sock != null) {
            //  ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());             
            ObjectInputStream in = new ObjectInputStream((sock.getInputStream()));
            ObjectOutputStream out = new ObjectOutputStream((sock.getOutputStream()));
            //BufferedWriter out = new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));
              
            Message firstPacket = (Message) in.readObject();                         // o server dexete ena minima;        
            System.out.println(firstPacket.getmessage());
//=============  o server exei dexthei klisi kai prokeite na steilei ena cookie  =======================


            SecureRandom random = new SecureRandom();
            String output=new BigInteger(130, random).toString(32);

            firstPacket.setcookieS(output);
            out.writeObject(firstPacket);                                    // o server stelnei paketo me to string (cookie)
            out.flush();

//============ o server anamenei to cookie tou pisw (to opoio tha eleksei gia apofugi spoofing)==================
//============ mazi me ena cookie tou client                                                   ==================     
            Message secondPacket = (Message) in.readObject();
       
            if (secondPacket.getcookieS().equals(firstPacket.getcookieS())) {
                secondPacket.setSelectedSymmCryp(secondPacket.getSuppSymmCryp1());  // dialegei ton prwto algorithmo empisteutikotitas
                secondPacket.setSelectedIntegrity(secondPacket.getsuppIntegrity1());// dialegei ton prwto algorithmo akeraiotitas
                out.writeObject(secondPacket);
                out.flush();
            
                
                
                File file = new File("certificate.crt");
                                                                                    // diavazei to crt se bytes
                byte[] content = Files.readAllBytes(file.toPath());                 // kai to stelnei ston client
                out.writeObject(content);  
            }
//==================== o server pairnei to 3o minima        =============================
//==================== kai etoimazei to private key tou gia apokruptografisi============= 
            
            Message thirdPacket = (Message) in.readObject();
            
            PemObject pemObject;
            PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream("private.pem")));
            pemObject = pemReader.readPemObject();
            
            Security.addProvider(new BouncyCastleProvider());
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            PrivateKey privatekey= factory.generatePrivate(privKeySpec);
           // System.out.println(privatekey);
           
//=============================================================================           
//==================== dimiourgia apo ton server twn 2 kleidiwn ===============

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privatekey);                           // apokruptografisi tou rn me to idiwtiko kleidi pou
            byte[] decryptedKeyBytes = cipher.doFinal(thirdPacket.getCipherText()); // katexei o server
            String rn=new String(decryptedKeyBytes);            
            
            String text=firstPacket.getcookieS()+secondPacket.getcookieC()+rn;      // coockieBOB+coockeAlice+RN
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");            // hasharoume to text
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            
            byte confidentialityKEY[] = null;
            byte integrityKEY[] = null;                                             // kovw to hash sti mesi kai dimiourgw dio kleidia
           
            confidentialityKEY=Arrays.copyOfRange(hash, 0, 16);                     //kathe thesi 1 bytes=8bits
            System.out.println(confidentialityKEY.length);
            integrityKEY=Arrays.copyOfRange(hash, 17, 32);          
            System.out.println(confidentialityKEY.length);
//            System.out.println(confidentialityKEY.toString());
//            System.out.println(integrityKEY.toString());

//==================== kanw hmac stis epilegmenes suites =================  
//==================== kai tha sugkrinw me to hmac tou client ============
            String suites=secondPacket.getSelectedSymmCryp()+" "+secondPacket.getSelectedIntegrity();
            
            ShaCrypto integ=new ShaCrypto();
            byte[] ms=integ.decSHa(thirdPacket.gethmac(), integrityKEY, "HmacSHA256");
            System.out.println(new String(ms));
            
//=============================================================================================================       
//=====================o Server einai etoimos na steilei ena kruptografimeno minima epivevaiwsis================
            SymmetricCrypto conf=new SymmetricCrypto();
            byte[] encMessage=null;
            byte[] message="ACK".getBytes();
            byte[] hmacMes= integ.encSHa(message, integrityKEY, thirdPacket.getSelectedIntegrity());
            if(thirdPacket.getSelectedSymmCryp().equals("AES")){
                System.out.println(hmacMes);
                System.out.println(confidentialityKEY);
                encMessage=conf.aes_encrypt(hmacMes, confidentialityKEY);
            }else{
                encMessage=conf.des_encrypt(hmacMes, confidentialityKEY);
            }
            
            thirdPacket.setEncMessage(encMessage);
            out.writeObject(thirdPacket);

            
                        sock.close();
                    }
                } catch (I2PException ex) {
                    System.out.println("General I2P exception!");
                } catch (ConnectException ex) {
                    System.out.println("Error connecting!");
                } catch (SocketTimeoutException ex) {
                    System.out.println("Timeout!");
                } catch (IOException ex) {
                    System.out.println("General read/write-exception!");
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeySpecException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

        private I2PServerSocket socket;

    }
}
