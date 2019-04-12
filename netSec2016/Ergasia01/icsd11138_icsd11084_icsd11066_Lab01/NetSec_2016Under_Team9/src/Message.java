
import java.io.File;
import java.io.Serializable;

public class Message implements Serializable{
    private static final long serialVersionUID = 1L;
    
    private String message;
    private String cookieS,cookieC;
    private String suppSymmCryp1,suppSymmCryp2;
    private String suppIntegrity1,suppIntegrity2;
    private String selectedSymmCryp,selectedIntegrity;
    private byte[] cipherText,hmac;
    private byte[] encryptedMessage;
    
    Message(){
        this.message=null;
        this.cookieC=null;
        this.cookieS=null;
        this.suppSymmCryp1=null;
        this.suppSymmCryp2=null;
        this.suppIntegrity1=null;
        this.suppIntegrity2=null;
        
    }
    Message(String message){
        this.message=message;
    }
    Message(String cookieC,String cookieS){
        this.cookieC=cookieC;
        this.cookieS=cookieS;
    }
    
    public String getmessage(){return this.message;}
    public String getcookieS(){return this.cookieS;}
    public String getcookieC(){return this.cookieC;}
    public String getSuppSymmCryp1(){return this.suppSymmCryp1;}
    public String getSuppSymmCryp2(){return this.suppSymmCryp2;}
    public String getsuppIntegrity1(){return this.suppIntegrity1;}
    public String getsuppIntegrity2(){return this.suppIntegrity2;}
    public String getSelectedSymmCryp(){return this.selectedSymmCryp;}
    public String getSelectedIntegrity(){return this.selectedIntegrity;}
    public byte[] getCipherText(){return this.cipherText;}
    public byte[] gethmac(){return this.hmac;}
    public byte[] getEncMessage(){return this.encryptedMessage;}
    
    public void  setmessage(String message){this.message=message;}
    public void  setcookieS(String cookie){this.cookieS=cookie;}
    public void setcookieC(String cookie){this.cookieC=cookie;}
    public void setSuppSymmCryp1(String suppSymmCryp1){this.suppSymmCryp1=suppSymmCryp1;}
    public void setSuppSymmCryp2(String suppSymmCryp2){this.suppSymmCryp2=suppSymmCryp2;}
    public void setsuppIntegrity1(String suppIntegrity1){this.suppIntegrity1=suppIntegrity1;}
    public void setsuppIntegrity2(String suppIntegrity2){this.suppIntegrity2=suppIntegrity2;}
    public void setSelectedSymmCryp(String selectedSymmCryp){this.selectedSymmCryp=selectedSymmCryp;}
    public void setSelectedIntegrity(String selectedIntegrity){this.selectedIntegrity=selectedIntegrity;}
    public void setCipherText(byte[] cipherText){this.cipherText=cipherText;}
    public void sethmac(byte[] hmac){this.hmac=hmac;}
    public void setEncMessage(byte[] message){this.encryptedMessage=message;}
}
