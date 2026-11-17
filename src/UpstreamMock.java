import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

public class UpstreamMock {

    static final String TEST_IP = "198.51.100.7";

    public static void main(String[] args) throws Exception {

        int ttl = 5;

        if (args.length > 0) {
            ttl = Integer.parseInt(args[0]);
        }

        InetAddress localhost = InetAddress.getByName("127.0.0.1");

        try (DatagramSocket socket = new DatagramSocket(5354, localhost)) {

            byte[] buffer = new byte[4096];
            int requestNumber = 0;

            System.out.println("Upstream server is running on port 5354");

            while (true) {

                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                String text = new String(
                        packet.getData(),
                        0,
                        packet.getLength(),
                        StandardCharsets.UTF_8
                ).trim();

                if (!text.startsWith("QUERY ")) {
                    continue;
                }

                String domain = text.substring(6).trim();

                if (domain.isEmpty()) {
                    continue;
                }

                String reply;

                if (domain.equals("missing.example.net")) {
                    reply = "NOT_FOUND";
                } else {
                    reply = "OK " + TEST_IP + " " + ttl;
                }

                requestNumber++;

                System.out.println(
                        "Request #" + requestNumber + ": "
                                + domain + " -> " + reply
                );

                System.out.flush();

                byte[] data = reply.getBytes(StandardCharsets.US_ASCII);

                DatagramPacket responsePacket = new DatagramPacket(
                        data,
                        data.length,
                        packet.getAddress(),
                        packet.getPort()
                );

                socket.send(responsePacket);
            }
        }
    }
}
