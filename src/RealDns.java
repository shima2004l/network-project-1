
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.Locale;

public class RealDns {

    static class Result {
        String status;
        String ip;
        int ttl;

        Result(String status, String ip, int ttl) {
            this.status = status;
            this.ip = ip;
            this.ttl = ttl;
        }
    }

    static Result query(String domain, String server, int port, int timeoutMs) {

        try (DatagramSocket socket = new DatagramSocket()) {

            socket.setSoTimeout(timeoutMs);

            int id = new Random().nextInt(65536);

            byte[] request = buildQuery(domain, id);

            InetAddress address = InetAddress.getByName(server);

            DatagramPacket requestPacket = new DatagramPacket(
                    request,
                    request.length,
                    address,
                    port
            );

            socket.send(requestPacket);

            byte[] buffer = new byte[4096];

            DatagramPacket responsePacket = new DatagramPacket(
                    buffer,
                    buffer.length
            );

            socket.receive(responsePacket);

            if (!responsePacket.getAddress().equals(address)
                    || responsePacket.getPort() != port) {
                return serverError();
            }

            return parseResponse(
                    buffer,
                    responsePacket.getLength(),
                    id,
                    domain
            );

        } catch (Exception e) {
            return serverError();
        }
    }

    static byte[] buildQuery(String domain, int id) throws Exception {

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);

        out.writeShort(id);
        out.writeShort(0x0100);
        out.writeShort(1);
        out.writeShort(0);
        out.writeShort(0);
        out.writeShort(0);

        for (String label : domain.split("\\.")) {

            byte[] data = label.getBytes(StandardCharsets.US_ASCII);

            if (data.length == 0 || data.length > 63) {
                throw new Exception("Bad domain label");
            }

            out.writeByte(data.length);
            out.write(data);
        }

        out.writeByte(0);

        out.writeShort(1);
        out.writeShort(1);

        out.flush();

        return bytes.toByteArray();
    }

    static Result parseResponse(byte[] data, int length, int id, String domain) {

        try {

            if (length < 12) {
                return serverError();
            }

            if (readU16(data, 0) != id) {
                return serverError();
            }

            int flags = readU16(data, 2);

            if ((flags & 0x8000) == 0) {
                return serverError();
            }

            if ((flags & 0x7800) != 0) {
                return serverError();
            }

            if ((flags & 0x0200) != 0) {
                return serverError();
            }

            int rcode = flags & 0x000F;

            int questions = readU16(data, 4);
            int answers = readU16(data, 6);

            if (questions != 1) {
                return serverError();
            }

            int offset = 12;

            String questionName = readName(data, 12, length);

            String expectedName = domain.toLowerCase(Locale.ROOT);
            if (expectedName.endsWith(".")) {
                expectedName = expectedName.substring(0, expectedName.length() - 1);
            }

            if (!questionName.equals(expectedName)) {
                return serverError();
            }

            offset = skipName(data, offset, length);


            if (offset + 4 > length) {
                return serverError();
            }

            int questionType = readU16(data, offset);
            offset += 2;

            int questionClass = readU16(data, offset);
            offset += 2;

            if (questionType != 1 || questionClass != 1) {
                return serverError();
            }

            if (rcode == 3) {
                return notFound();
            }

            if (rcode != 0) {
                return serverError();
            }

            for (int i = 0; i < answers; i++) {

                offset = skipName(data, offset, length);

                if (offset + 10 > length) {
                    return serverError();
                }

                int type = readU16(data, offset);
                offset += 2;

                int clazz = readU16(data, offset);
                offset += 2;

                long ttl = readU32(data, offset);
                offset += 4;

                int dataLength = readU16(data, offset);
                offset += 2;

                if (dataLength > length - offset) {
                    return serverError();
                }

                if (type == 1 && clazz == 1) {

                    if (dataLength != 4) {
                        return serverError();
                    }

                    String ip = (data[offset] & 0xFF) + "."
                            + (data[offset + 1] & 0xFF) + "."
                            + (data[offset + 2] & 0xFF) + "."
                            + (data[offset + 3] & 0xFF);

                    int ttlValue = ttl > Integer.MAX_VALUE
                            ? Integer.MAX_VALUE
                            : (int) ttl;

                    return new Result("OK", ip, ttlValue);
                }

                offset += dataLength;
            }

            return notFound();

        } catch (Exception e) {
            return serverError();
        }
    }

    static String readName(byte[] data, int offset, int length) throws Exception {
        StringBuilder name = new StringBuilder();
        boolean[] visited = new boolean[length];

        while (true) {
            if (offset >= length) {
                throw new Exception("Invalid DNS name");
            }

            int size = data[offset] & 0xFF;

            if (size == 0) {
                return name.toString().toLowerCase(Locale.ROOT);
            }

            if ((size & 0xC0) == 0xC0) {
                if (offset + 1 >= length || visited[offset]) {
                    throw new Exception("Invalid compression pointer");
                }

                visited[offset] = true;

                int pointer = ((size & 0x3F) << 8)
                        | (data[offset + 1] & 0xFF);

                if (pointer >= offset) {
                    throw new Exception("Invalid compression target");
                }

                offset = pointer;
                continue;
            }

            if ((size & 0xC0) != 0 || size > 63) {
                throw new Exception("Invalid DNS label");
            }

            if (offset + 1 + size > length) {
                throw new Exception("Incomplete DNS label");
            }

            if (name.length() > 0) {
                name.append('.');
            }

            name.append(new String(
                    data,
                    offset + 1,
                    size,
                    StandardCharsets.US_ASCII
            ));

            offset += 1 + size;
        }
    }
    static int skipName(byte[] data, int offset, int length)
            throws Exception {

        while (true) {

            if (offset >= length) {
                throw new Exception("Invalid DNS name");
            }

            int size = data[offset] & 0xFF;


            if (size == 0) {
                return offset + 1;
            }


            if ((size & 0xC0) == 0xC0) {

                if (offset + 1 >= length) {
                    throw new Exception("Invalid compression pointer");
                }

                int pointer = ((size & 0x3F) << 8)
                        | (data[offset + 1] & 0xFF);

                if (pointer >= length) {
                    throw new Exception("Invalid compression target");
                }

                return offset + 2;
            }


            if ((size & 0xC0) != 0) {
                throw new Exception("Invalid DNS label");
            }

            if (offset + 1 + size > length) {
                throw new Exception("Incomplete DNS label");
            }

            offset += 1 + size;
        }
    }

    static int readU16(byte[] data, int offset) {

        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    static long readU32(byte[] data, int offset) {

        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    static Result notFound() {
        return new Result("NOT_FOUND", null, 0);
    }

    static Result serverError() {
        return new Result("SERVER_ERROR", null, 0);
    }
}
