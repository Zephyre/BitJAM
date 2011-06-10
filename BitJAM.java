import java.util.Random;
import java.applet.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class BitJAM extends Applet implements Runnable {
    Thread thread;
    boolean running = true;
    PrintWriter pf;
    BufferedReader is;
    int nonce = 0;
    Socket s = null;
    
    long lastgot_time = 0;
    long meter_time = System.currentTimeMillis();
    long meter_hash = 0;
    
    final int[] data = new int[32];
    final long[] target = new long[8];
    MessageDigest digestPrehash;
    MessageDigest digestInside;
    MessageDigest digestOutside;
    final ByteBuffer digestInput = ByteBuffer.allocate(80);
    byte[] digestOutput;

	public void init() {
	Random rng = new Random();
        // initialize to some random value
	nonce = rng.nextInt();
        try {
            digestPrehash = MessageDigest.getInstance("SHA-256");
            digestInside  = MessageDigest.getInstance("SHA-256");
            digestOutside = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {}
        thread = new Thread(this);
        thread.setPriority(Thread.MIN_PRIORITY);
        thread.start();
	}
    
    public void destroy() {
        running = false;
        thread = null;
    }
    
    public void run(){
        while(true) {

        String response = null;
        String ds;
        String ts;
        while(s == null){
            try {
                s = new Socket(getCodeBase().getHost(), 15063);
                pf = new PrintWriter(s.getOutputStream(), true);
                is = new BufferedReader(new InputStreamReader(s.getInputStream()));
                pf.println(getDocumentBase());
            } catch (IOException e) {try{thread.sleep(1000);}catch(InterruptedException ee){}}
        }
        while (response == null){
            try{
                while (!is.ready()) {}
                response = is.readLine(); // read in
                lastgot_time = System.currentTimeMillis();
                ds = response.substring(0,256);
                ts = response.substring(256,256+64);
                for(int i = 0; i < 32; i++) {
                    data[i] = Integer.reverseBytes((int)Long.parseLong(ds.substring(i*8, (i*8)+8), 16));
                    if (i < 19){
                        digestInput.putInt(i*4, data[i]);
                        if (i < 8) {target[i] = (Long.reverseBytes(Long.parseLong(ts.substring(i*8, (i*8)+8), 16) << 16)) >>> 16;}
                    }
                }
                digestPrehash.reset();
                digestPrehash.update(digestInput.array(), 0, 76);
            }catch(IOException e){}
        }
        while (System.currentTimeMillis() - lastgot_time < 30000) {
            if (nonce >= 2147483647){nonce = -2147483648;}
            else {nonce++;}

            digestInput.putInt(76, nonce);
//            digestOutput = digestOutside.digest(digestInside.digest(digestInput.array()));
            try{
                digestInside = (MessageDigest) digestPrehash.clone();
            } catch(CloneNotSupportedException e) {}
            digestInside.update(digestInput.array(), 76, 4);
            digestOutput = digestOutside.digest(digestInside.digest());
            if(digestOutput[28] == 0 && digestOutput[29] == 0 && digestOutput[30] == 0 && digestOutput[31] == 0){
                for(int bi=6; bi >= 0; bi--){
                    long X = ((long)(0xFF & digestOutput[bi+3]) << 24) | ((long)(0xFF & digestOutput[bi+2]) << 16) | ((long)(0xFF & digestOutput[bi+1]) << 8) | ((long)(0xFF & digestOutput[bi]));
                    if (X < target[bi]){ // lower than target
                        pf.println(Integer.toHexString(nonce));
                        bi = -1; // kill the loop
                    }
                    else if (X > target[bi]){ // higher than target
                        bi = -1; // kill the loop
                    }
                    // loop continues if values were equal
                }
            }
            //*
            if(System.currentTimeMillis() >= meter_time + 1000 ){
                showStatus(
                    Long.toString((nonce-meter_hash))+
                    " hashes per second. Current nonce: "+
                    Integer.toString(nonce));
                meter_hash = nonce;
                meter_time = System.currentTimeMillis();
            }//*/
            if((nonce & 65535) == 0){
                try{
                    if (is.ready()) {
                        while (is.ready()){ // we only need the recent stuff
                            response = is.readLine(); // read in from socket
                            lastgot_time = System.currentTimeMillis();
                            }
                        ds = response.substring(0,256);
                        ts = response.substring(256,256+64);
                        for(int i = 0; i < 32; i++) {
                            data[i] = Integer.reverseBytes((int)Long.parseLong(ds.substring(i*8, (i*8)+8), 16));
                            if (i < 19) {
                                 digestInput.putInt(i*4, data[i]);
                                 if (i < 8){target[i] = (Long.reverseBytes(Long.parseLong(ts.substring(i*8, (i*8)+8), 16) << 16)) >>> 16;}
                            }
                        }
                        digestPrehash.reset();
                        digestPrehash.update(digestInput.array(), 0, 76);
                    }
                }catch(IOException e){}
            }
        }
        //showStatus("Connection dropped, attempting to reconnect...");
        try{s.close();}catch (IOException e) {}
        s = null;
        // sleep a few seconds and try again.
        try{thread.sleep(5000);}catch(InterruptedException e){}
    }
    }
}
