import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.regex.*;

public class LogParser {
    private static final Pattern LINE = Pattern.compile(
        "^(\\S+) \\S+ \\S+ \\[([^\\]]+)\\] \"(\\S+) (\\S+) [^\"]*\" (\\d{3}) (\\d+|-).*$");

    private static final DateTimeFormatter TS =
        DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    private int skipped = 0;

    public int getSkipped() { return skipped; }

    public List<LogEntry> parse(Path file) throws IOException {
        skipped = 0;
        List<LogEntry> entries = new ArrayList<>();
        try (BufferedReader br = Files.newBufferedReader(file)) {
            String line;
            while ((line = br.readLine()) != null) {
                LogEntry e = parseLine(line);
                if (e == null) skipped++;
                else entries.add(e);
            }
        }
        return entries;
    }

    static LogEntry parseLine(String line) {
        Matcher m = LINE.matcher(line);
        if (!m.matches()) return null;
        try {
            Instant ts = ZonedDateTime.parse(m.group(2), TS).toInstant();
            String bytesStr = m.group(6);
            long bytes = bytesStr.equals("-") ? 0 : Long.parseLong(bytesStr);
            String endpoint = m.group(4);
            int q = endpoint.indexOf('?');
            if (q >= 0) endpoint = endpoint.substring(0, q);
            return new LogEntry(m.group(1), ts, m.group(3), endpoint,
                                Integer.parseInt(m.group(5)), bytes);
        } catch (DateTimeParseException | NumberFormatException e) {
            return null;
        }
    }
}