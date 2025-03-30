import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class SocketServer {
    public static void main(String[] args) {
        int port = 5000;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is listening on port " + port);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("New client connected");

                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter output = new PrintWriter(socket.getOutputStream(), true);

                String message = input.readLine();
                System.out.println("Received: " + message);

                output.println("Hello from ONOS Server!");
                socket.close();
            }
        } catch (Exception ex) {
            System.out.println("SocketServer while loop error ex:" + ex);
            ex.printStackTrace();
        }
    }
}

