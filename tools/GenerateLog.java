import java.io.IOException;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class GenerateLog {
    record Line(ZonedDateTime time, String text) {}

    public static void main(String[] args) throws IOException {
        Random rnd = new Random(42); // fixed seed = same file every run
        DateTimeFormatter fmt =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);
        ZonedDateTime start = ZonedDateTime.of(2026, 10, 10, 13, 0, 0, 0, ZoneOffset.UTC);

        String[] ips = {"192.168.1.10", "192.168.1.11", "10.0.0.5", "10.0.0.8",
                        "172.16.4.2", "172.16.4.9", "192.168.1.50", "10.0.0.21"};
        String[] endpoints = {"/", "/index.html", "/about", "/products",
                              "/products/42", "/api/items", "/contact",
                              "/static/app.js", "/static/style.css"};

        List<Line> lines = new ArrayList<>();

        // 1) Normal traffic: 350 requests spread over 30 minutes
        for (int i = 0; i < 350; i++) {
            ZonedDateTime t = start.plusSeconds(rnd.nextInt(1800));
            int r = rnd.nextInt(100);
            int status = r < 85 ? 200 : r < 92 ? 301 : r < 98 ? 404 : 500;
            String ip = ips[rnd.nextInt(ips.length)];
            String ep = endpoints[rnd.nextInt(endpoints.length)];
            lines.add(make(fmt, t, ip, "GET", ep, status, 200 + rnd.nextInt(5000)));
        }

        // 2) Brute-force attacker: 60 failed logins, one per second
        for (int i = 0; i < 60; i++) {
            lines.add(make(fmt, start.plusSeconds(600 + i),
                    "203.0.113.66", "POST", "/login", 401, 128));
        }

        // 3) Flooder: 90 requests inside 10 seconds
        for (int i = 0; i < 90; i++) {
            lines.add(make(fmt, start.plusSeconds(1200 + i / 9),
                    "198.51.100.7", "GET", "/api/items", 200, 512));
        }

        lines.sort(Comparator.comparing(Line::time)); // real logs are chronological

        List<String> out = new ArrayList<>();
        for (Line l : lines) out.add(l.text());
        Files.write(Path.of("sample_access.log"), out);
        System.out.println("Wrote " + out.size() + " lines.");
    }

    static Line make(DateTimeFormatter fmt, ZonedDateTime t, String ip,
                     String method, String ep, int status, int bytes) {
        String text = String.format("%s - - [%s] \"%s %s HTTP/1.1\" %d %d",
                ip, t.format(fmt), method, ep, status, bytes);
        return new Line(t, text);
    }
}