// Java core packages

import java.io.*;
import java.net.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

// Java extension packages
import javax.swing.*;
public class LoginClient {
// LoginClient constructor
    public LoginClient() throws NoSuchAlgorithmException, InvalidKeyException {

        String secretKey = "mysecretkey";

        // open Socket connection to server and send login

        try {
            // obtain SocketFactory for creating Sockets

            SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

            // create Socket from factory

            SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 7070);

            // create PrintWriter for sending login to server

            PrintWriter output = new PrintWriter(new OutputStreamWriter( socket.getOutputStream()));

            // prompt user for user name

            String userName = JOptionPane.showInputDialog(null,"Enter User Name:");

            // send user name to server

            output.println(userName);

            // prompt user for password

            String password = JOptionPane.showInputDialog(null,"Enter Password:");

            // send password to server

            output.println(password);

            String message = JOptionPane.showInputDialog(null,"Enter a message for the server:");
            
            String nonce = LocalDateTime.now().toString();

            message = message + "," + nonce;

            byte[] secretKeyBytes = secretKey.getBytes();
            byte[] messageBytes = message.getBytes();
    
            // Create HMAC-SHA256 hash function instance
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");

            // Create secret key spec
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, "HmacSHA256");

            // Initialize the HMAC with the secret key
            hmacSha256.init(secretKeySpec);

            // Generate the HMAC hash
            byte[] hmacSha256Bytes = hmacSha256.doFinal(messageBytes);

            // Convert the hash to a string for transmission
            String hmacSha256String = bytesToHex(hmacSha256Bytes);

            System.out.println("HMAC-SHA256: " + hmacSha256String);

            output.println(message);
            output.println(hmacSha256String);
            output.flush();

            // create BufferedReader for reading server response

            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // read response from server

            String response = input.readLine();

            // display response to user

            JOptionPane.showMessageDialog(null, response);

            // clean up streams and sockects

            output.close();
            input.close();
            socket.close();

        } // end try
        
        // handle exception with server
        catch ( IOException ioException ) {
            ioException.printStackTrace();
        }
        // exit application
        finally {
            System.exit(0);
        }
    } // end LoginClient constructor

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    // execute application
    public static void main(String args[]) throws InvalidKeyException, NoSuchAlgorithmException{
        new LoginClient();
    }
}