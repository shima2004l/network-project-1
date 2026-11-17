import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * Minimal DNS client used only by the optional B6 feature.
 * It sends a real type-A query over UDP and reads the IPv4 address and TTL
 * from the answer section.
 */
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
            socket.send(new DatagramPacket(request, request.length, address, port));

            byte[] buffer = new byte[4096];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);

            return parseResponse(buffer, packet.getLength(), id);
        } catch (Exception e) {
            return serverError();
        }
    }

    static byte[] buildQuery(String domain, int id) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);

        out.writeShort(id);
        out.writeShort(0x0100); // standard query, recursion desired
        out.writeShort(1);      // QDCOUNT
        out.writeShort(0);      // ANCOUNT
        out.writeShort(0);      // NSCOUNT
        out.writeShort(0);      // ARCOUNT

        for (String label : domain.split("\\.")) {
            byte[] data = label.getBytes(StandardCharsets.US_ASCII);
            if (data.length == 0 || data.length > 63) {
                throw new Exception("bad label");
            }
            out.writeByte(data.length);
            out.write(data);
        }
        out.writeByte(0);

        out.writeShort(1); // QTYPE = A
        out.writeShort(1); // QCLASS = IN
        out.flush();
        return bytes.toByteArray();
    }

    static Result parseResponse(byte[] data, int length, int id) {
        try {
            if (length < 12) {
                return serverError();
            }
            if (readU16(data, 0) != id) {
                return serverError();
            }

            int flags = readU16(data, 2);
            int rcode = flags & 0x000F;
            int questions = readU16(data, 4);
            int answers = readU16(data, 6);

            if (rcode == 3) {
                return notFound();
            }
            if (rcode != 0) {
                return serverError();
            }

            int offset = 12;
            for (int i = 0; i < questions; i++) {
                offset = skipName(data, offset, length);
                offset += 4;
                if (offset > length) {
                    return serverError();
                }
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

                if (offset + dataLength > length) {
                    return serverError();
                }

                if (type == 1 && clazz == 1 && dataLength == 4) {
                    String ip = (data[offset] & 0xFF) + "."
                            + (data[offset + 1] & 0xFF) + "."
                            + (data[offset + 2] & 0xFF) + "."
                            + (data[offset + 3] & 0xFF);
                    int ttlValue = ttl > Integer.MAX_VALUE
                            ? Integer.MAX_VALUE : (int) ttl;
                    return new Result("OK", ip, ttlValue);
                }

                offset += dataLength;
            }

            return notFound();
        } catch (Exception e) {
            return serverError();
        }
    }

    static int skipName(byte[] data, int offset, int length) throws Exception {
        while (true) {
            if (offset >= length) {
                throw new Exception("bad name");
            }
            int size = data[offset] & 0xFF;
            if (size == 0) {
                return offset + 1;
            }
            if ((size & 0xC0) == 0xC0) {
                if (offset + 1 >= length) {
                    throw new Exception("bad pointer");
                }
                return offset + 2;
            }
            if ((size & 0xC0) != 0) {
                throw new Exception("bad label");
            }
            offset += 1 + size;
        }
    }

    static int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
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
