import java.io.*;
import java.net.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Objects;

import javax.net.ServerSocketFactory;

public class LoginServerSocket {
private static final String CORRECT_USER_NAME = "meh";
private static final String CORRECT_PASSWORD = "1234";
private static final String HELLO_MESSAGE = "hola";

/**
* @param args
* @throws IOException
* @throws InterruptedException
 * @throws NoSuchAlgorithmException
 * @throws InvalidKeyException
*/
    public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeyException {

    // wait for client connection and check login information

    ServerSocketFactory socketFactory = (ServerSocketFactory)
    ServerSocketFactory.getDefault();

    String secretKey = "mysecretkey";
    ArrayList noncesRegistrados = new ArrayList<>();
    // create Socket from factory
    
    ServerSocket serverSocket = (ServerSocket)
    socketFactory.createServerSocket(7070);
        while (true) {
            try {
                System.err.println("Waiting for connection...");
                Socket socket = serverSocket.accept();

                // open BufferedReader for reading data from client

                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // open PrintWriter for writing data to client

                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
                String userName = input.readLine();
                String password = input.readLine();
                String message = input.readLine();
                String hmacSha256String = input.readLine();

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
                String hmacSha256StringServer = bytesToHex(hmacSha256Bytes);
    
                System.out.println("HMAC-SHA256: " + hmacSha256String);

                String[] parts = message.split(",");
                String cleanMessage = parts[0];
                String nonce = parts[1];


                if (!Objects.equals(hmacSha256String, hmacSha256StringServer)){
                    output.println("Integrity failure, try again");

                } else if(noncesRegistrados.contains(nonce)){
                    output.println("This message has appeared before >:(");

                } else {
                    if (userName.equals(CORRECT_USER_NAME) && password.equals(CORRECT_PASSWORD)){
                        if(cleanMessage.toLowerCase().equals(HELLO_MESSAGE)){
                            output.println("Hello, " + userName);
                        } else {
                            output.println("Message was not a welcoming one >:(");
                        }
                    } else {
                        output.println("Login Failed.");
                    }
                }

                noncesRegistrados.add(nonce);

                output.close();
                input.close();
                socket.close();
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        } // end while
    }

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

    //serverSocket.close();
}