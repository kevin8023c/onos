import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;

public class SocketClient {
    public static void main(String[] args) {
        String serverAddress = "127.0.0.1"; 
        int port = 5000; 

        try (Socket socket = new Socket(serverAddress, port)) {
            PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            output.println("Hello from ONOS Client!");
            String response = input.readLine();
            System.out.println("Server replied: " + response);

        } catch (Exception ex) {
            System.out.println("SocketClient while loop error ex" + ex);
            ex.printStackTrace();
        }
    }
}

