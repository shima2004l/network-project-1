import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class DnsProxy {
    static final String PROMPT = "Enter domain (or exit): ";
    static final String ALLOWED_CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.";
    static final List<String> REQUIRED_KEYS = Arrays.asList(
            "upstream_ip", "upstream_port", "sinkhole_ip",
            "proxy_ip", "ad_list_file", "sanction_list_file");
    static final DateTimeFormatter LOG_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    static Path baseDir;
    static Path configPath;
    static Path logPath;

    public static void main(String[] args) {
        try {
            run();
        } catch (ConfigException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
    }

    static void run() {
        baseDir = findBaseDir();
        configPath = baseDir.resolve("config.txt");
        logPath = baseDir.resolve("log.txt");

        Config config = loadConfig();
        Map<String, List<String>> lists = loadLists(config);
        Cache cache = new Cache(config.cacheEnabled, config.cacheMaxEntries);
        Stats stats = new Stats();

        System.out.println("DNS Proxy ready.");

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));

        while (true) {
            System.out.print(PROMPT);
            System.out.flush();

            String line;
            try {
                line = reader.readLine();
            } catch (IOException e) {
                System.out.println("Bye.");
                return;
            }

            if (line == null) {
                System.out.println("Bye.");
                return;
            }

            String text = line.trim();
            String command = text.toLowerCase();

            if (command.equals("exit")) {
                System.out.println("Bye.");
                return;
            }
            if (command.equals("stats")) {
                printStats(stats);
                continue;
            }
            if (command.equals("reload")) {
                reloadLists(config, lists);
                continue;
            }
            if (command.equals("cache")) {
                printCache(cache);
                continue;
            }

            Result result = handleDomain(text, config, lists, cache, stats);
            printResult(result);
            System.out.println();
        }
    }

    static Path findBaseDir() {
        Path current = Paths.get("").toAbsolutePath();
        if (Files.exists(current.resolve("config.txt"))) {
            return current;
        }
        try {
            Path location = Paths.get(
                    DnsProxy.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (Files.isDirectory(location)) {
                return location;
            }
            return location.getParent();
        } catch (Exception e) {
            return current;
        }
    }


    static class Config {
        String upstreamIp;
        int upstreamPort;
        int timeoutMs;
        String sinkholeIp;
        String proxyIp;
        int localTtl;
        String adListFile;
        String sanctionListFile;
        boolean cacheEnabled;
        Integer cacheMaxEntries;
        boolean realDnsEnabled;
    }

    static class ConfigException extends RuntimeException {
        ConfigException(String message) {
            super(message);
        }
    }

    static void failConfig(String message) {
        throw new ConfigException("Config error: " + message);
    }

    static Config loadConfig() {
        if (!Files.exists(configPath)) {
            failConfig("config.txt not found");
        }

        List<String> lines = new ArrayList<>();
        try {
            lines = Files.readAllLines(configPath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            failConfig("cannot read config.txt");
        }

        Map<String, String> values = new LinkedHashMap<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int equals = line.indexOf('=');
            if (equals < 0) {
                failConfig("invalid line " + (i + 1) + " in config.txt");
            }
            String key = line.substring(0, equals).trim();
            String value = line.substring(equals + 1).trim();
            if (key.isEmpty()) {
                failConfig("invalid line " + (i + 1) + " in config.txt");
            }
            values.put(key, value);
        }

        for (String key : REQUIRED_KEYS) {
            if (!values.containsKey(key)) {
                failConfig("missing key: " + key);
            }
        }

        Config config = new Config();
        config.upstreamIp = parseIpv4(values.get("upstream_ip"), "upstream_ip");
        config.upstreamPort = parseInt(values.get("upstream_port"), "upstream_port", 1, 65535);
        config.timeoutMs = parseTimeout(values.get("upstream_timeout_sec"));
        config.sinkholeIp = parseIpv4(values.get("sinkhole_ip"), "sinkhole_ip");
        config.proxyIp = parseIpv4(values.get("proxy_ip"), "proxy_ip");
        config.localTtl = parseInt(values.getOrDefault("local_ttl", "60"), "local_ttl", 1, null);
        config.adListFile = values.get("ad_list_file");
        config.sanctionListFile = values.get("sanction_list_file");
        config.cacheEnabled = parseBool(values.getOrDefault("cache_enabled", "true"), "cache_enabled");
        config.realDnsEnabled = parseBool(
                values.getOrDefault("real_dns_enabled", "false"), "real_dns_enabled");

        return config;
    }

    static String parseIpv4(String value, String key) {
        if (!isValidIpv4(value)) {
            failConfig("invalid " + key + ": " + value);
        }

        return value;
    }

    static int parseInt(String value, String key, int minimum, Integer maximum) {
        int number;
        try {
            number = Integer.parseInt(value);
        } catch (NumberFormatException e) {
            failConfig("invalid " + key + ": " + value);
            return 0;
        }
        if (number < minimum || (maximum != null && number > maximum)) {
            failConfig("invalid " + key + ": " + value);
        }
        return number;
    }

    static int parseTimeout(String value) {
        double seconds;

        try {
            seconds = Double.parseDouble(value == null ? "2" : value);
        } catch (Exception e) {
            failConfig("invalid upstream_timeout_sec: " + value);
            return 2000;
        }

        if (!Double.isFinite(seconds)
                || seconds <= 0) {

            failConfig("invalid upstream_timeout_sec: " + value);
        }

        return Math.max(1, (int) Math.round(seconds * 1000));
    }

    static boolean parseBool(String value, String key) {
        String lowered = value.toLowerCase();
        if (!lowered.equals("true") && !lowered.equals("false")) {
            failConfig("invalid " + key + ": " + value);
        }
        return lowered.equals("true");
    }


    static List<String> loadList(String filename, List<String> warnings) throws IOException {
        Path path = Paths.get(filename);
        if (!path.isAbsolute()) {
            path = baseDir.resolve(path);
        }

        List<String> entries = new ArrayList<>();
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String item = line.trim();
            if (item.isEmpty() || item.startsWith("#")) {
                continue;
            }
            if (!isValidDomain(item)) {
                warnings.add("Warning: bad line in " + filename + ": " + item);
                continue;
            }
            entries.add(normalizeDomain(item));
        }
        return entries;
    }


    static Map<String, List<String>> loadLists(Config config) {
        List<String> warnings = new ArrayList<>();

        List<String> ad = new ArrayList<>();
        List<String> sanction = new ArrayList<>();

        try {
            ad = loadList(config.adListFile, warnings);
        } catch (IOException e) {
            failConfig("cannot read ad list file: " + config.adListFile);
        }

        try {
            sanction = loadList(config.sanctionListFile, warnings);
        } catch (IOException e) {
            failConfig("cannot read sanction list file: " + config.sanctionListFile);
        }

        for (String warning : warnings) {
            System.out.println(warning);
        }

        Map<String, List<String>> lists = new HashMap<>();
        lists.put("ad", ad);
        lists.put("sanction", sanction);

        return lists;
    }

    static void reloadLists(Config config, Map<String, List<String>> lists) {
        List<String> warnings = new ArrayList<>();
        try {
            List<String> ad = loadList(config.adListFile, warnings);
            List<String> sanction = loadList(config.sanctionListFile, warnings);
            lists.put("ad", ad);
            lists.put("sanction", sanction);
        } catch (IOException e) {
            System.out.println("Reload error: cannot read " + e.getMessage());
            return;
        }

        for (String warning : warnings) {
            System.out.println(warning);
        }
        System.out.println("Lists reloaded.");
    }

    static boolean isValidDomain(String name) {
        if (name.isEmpty() || name.startsWith(".") || name.contains("..")) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            if (ALLOWED_CHARS.indexOf(name.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    static String normalizeDomain(String name) {
        String result = name.trim().toLowerCase();
        if (result.endsWith(".")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    static boolean inList(String name, List<String> entries) {
        for (String entry : entries) {
            if (name.equals(entry) || name.endsWith("." + entry)) {
                return true;
            }
        }
        return false;
    }

    static boolean isValidIpv4(String value) {
        if (value == null) {
            return false;
        }

        String[] parts = value.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }

            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);

                if (c < '0' || c > '9') {
                    return false;
                }
            }

            int number = Integer.parseInt(part);

            if (number > 255) {
                return false;
            }
        }

        return true;
    }


    static class CacheEntry {
        String ip;
        int ttl;
        long storedNanos;

        CacheEntry(String ip, int ttl) {
            this.ip = ip;
            this.ttl = ttl;
            this.storedNanos = System.nanoTime();
        }
    }

    static class CachedAnswer {
        String ip;
        int ttl;

        CachedAnswer(String ip, int ttl) {
            this.ip = ip;
            this.ttl = ttl;
        }
    }

    static class Cache {
        boolean enabled;
        Integer maxEntries;
        LinkedHashMap<String, CacheEntry> entries = new LinkedHashMap<>();

        Cache(boolean enabled, Integer maxEntries) {
            this.enabled = enabled;
            this.maxEntries = maxEntries;
        }

        CachedAnswer get(String name) {
            if (!enabled) {
                return null;
            }
            CacheEntry entry = entries.get(name);
            if (entry == null) {
                return null;
            }
            int remaining = remainingTtl(entry);
            if (remaining < 1) {
                entries.remove(name);
                return null;
            }
            return new CachedAnswer(entry.ip, remaining);
        }

        void put(String name, String ip, int ttl) {
            if (!enabled || ttl <= 0) {
                return;
            }
            if (entries.containsKey(name)) {
                entries.remove(name);
            }
            entries.put(name, new CacheEntry(ip, ttl));
        }

        List<String[]> validEntries() {
            List<String[]> result = new ArrayList<>();
            Iterator<Map.Entry<String, CacheEntry>> iterator = entries.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, CacheEntry> item = iterator.next();
                int remaining = remainingTtl(item.getValue());
                if (remaining < 1) {
                    iterator.remove();
                } else {
                    result.add(new String[]{
                            item.getKey(), item.getValue().ip, String.valueOf(remaining)});
                }
            }
            return result;
        }

        int remainingTtl(CacheEntry entry) {
            long elapsedSeconds =
                    (System.nanoTime() - entry.storedNanos) / 1_000_000_000L;

            return entry.ttl - (int) elapsedSeconds;
        }
    }


     static class UpstreamResult {
        String status;
        String ip;
        int ttl;

        UpstreamResult(String status, String ip, int ttl) {
            this.status = status;
            this.ip = ip;
            this.ttl = ttl;
        }

        static UpstreamResult serverError() {
            return new UpstreamResult("SERVER_ERROR", null, 0);
        }

        static UpstreamResult notFound() {
            return new UpstreamResult("NOT_FOUND", null, 0);
        }
    }

    static UpstreamResult queryUpstream(String domain, Config config) {
        return queryTextUpstream(domain, config);
    }

    static UpstreamResult queryTextUpstream(String domain, Config config) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(config.timeoutMs);
            byte[] message = ("QUERY " + domain).getBytes(StandardCharsets.US_ASCII);
            InetAddress address = InetAddress.getByName(config.upstreamIp);
            DatagramPacket request = new DatagramPacket(
                    message, message.length, address, config.upstreamPort);
            socket.send(request);

            byte[] buffer = new byte[4096];
            DatagramPacket response = new DatagramPacket(buffer, buffer.length);
            socket.receive(response);
            String reply = new String(
                    buffer, 0, response.getLength(), StandardCharsets.UTF_8).trim();
            return parseUpstreamReply(reply);
        } catch (IOException e) {
            return UpstreamResult.serverError();
        }
    }

    static UpstreamResult parseUpstreamReply(String reply) {
        if (reply.equals("NOT_FOUND")) {
            return UpstreamResult.notFound();
        }
        String[] parts = reply.split("\\s+");
        if (parts.length == 3 && parts[0].equals("OK") && isValidIpv4(parts[1])) {
            try {
                int ttl = Integer.parseInt(parts[2]);
                if (ttl >= 0) {
                    return new UpstreamResult("OK", parts[1], ttl);
                }
            } catch (NumberFormatException e) {
                return UpstreamResult.serverError();
            }
        }
        return UpstreamResult.serverError();
    }


    static class Result {
        String domain;
        String source;
        String status;
        String ip;
        Integer ttl;

        Result(String domain, String source, String status, String ip, Integer ttl) {
            this.domain = domain;
            this.source = source;
            this.status = status;
            this.ip = ip;
            this.ttl = ttl;
        }
    }

    static Result handleDomain(String text, Config config,
                               Map<String, List<String>> lists,
                               Cache cache, Stats stats) {
        String raw = text.trim();

        if (!isValidDomain(raw)) {
            String domain = raw.isEmpty() ? "(empty)" : raw;
            Result result = new Result(domain, "NONE", "INVALID_INPUT", null, null);
            stats.update(result);
            writeLog(result);
            return result;
        }

        String domain = normalizeDomain(raw);
        Result result;

        if (inList(domain, lists.get("ad"))) {
            result = new Result(domain, "AD_BLOCK", "OK",
                    config.sinkholeIp, config.localTtl);
        } else if (inList(domain, lists.get("sanction"))) {
            result = new Result(domain, "SANCTION", "OK",
                    config.proxyIp, config.localTtl);
        } else {
            CachedAnswer cached = cache.get(domain);
            if (cached != null) {
                result = new Result(domain, "CACHE", "OK", cached.ip, cached.ttl);
            } else {
                UpstreamResult upstream = queryUpstream(domain, config);
                if (upstream.status.equals("OK")) {
                    cache.put(domain, upstream.ip, upstream.ttl);
                    result = new Result(domain, "UPSTREAM", "OK",
                            upstream.ip, upstream.ttl);
                } else {
                    result = new Result(domain, "UPSTREAM", upstream.status, null, null);
                }
            }
        }

        stats.update(result);
        writeLog(result);
        return result;
    }


    static void printResult(Result result) {
        System.out.println("Domain : " + result.domain);
        System.out.println("Source : " + result.source);
        System.out.println("Status : " + result.status);
        System.out.println("IP : " + (result.ip == null ? "-" : result.ip));
        System.out.println("TTL : " + (result.ttl == null ? "-" : result.ttl));
    }

    static void printStats(Stats stats) {
        System.out.println("Total: " + stats.total
                + " | AD_BLOCK: " + stats.adBlock
                + " | SANCTION: " + stats.sanction
                + " | CACHE: " + stats.cache
                + " | UPSTREAM: " + stats.upstream
                + " | ERRORS: " + stats.errors);
    }

    static void printCache(Cache cache) {
        List<String[]> entries = cache.validEntries();
        if (entries.isEmpty()) {
            System.out.println("Cache is empty.");
            return;
        }
        for (String[] entry : entries) {
            System.out.println(entry[0] + " | " + entry[1] + " | " + entry[2]);
        }
    }

    static void writeLog(Result result) {
        String stamp = LocalDateTime.now().format(LOG_TIME);
        String line = stamp + " | " + result.domain + " | " + result.source
                + " | " + result.status + " | "
                + (result.ip == null ? "-" : result.ip) + " | "
                + (result.ttl == null ? "-" : result.ttl) + System.lineSeparator();
        try {
            Files.writeString(logPath, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Failed to write log: " + e.getMessage());
        }
    }

    static class Stats {
        int total;
        int adBlock;
        int sanction;
        int cache;
        int upstream;
        int errors;

        void update(Result result) {
            total++;
            if (result.status.equals("INVALID_INPUT") || result.status.equals("SERVER_ERROR")) {
                errors++;
            } else if (result.source.equals("AD_BLOCK")) {
                adBlock++;
            } else if (result.source.equals("SANCTION")) {
                sanction++;
            } else if (result.source.equals("CACHE")) {
                cache++;
            } else if (result.source.equals("UPSTREAM")) {
                upstream++;
            }
        }
    }
}

