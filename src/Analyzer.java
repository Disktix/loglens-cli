import java.util.*;

public class Analyzer {
    public static final int AUTH_FAIL_THRESHOLD = 10;
    public static final int RATE_LIMIT_REQUESTS = 50;
    public static final long RATE_WINDOW_SECONDS = 10;

    public record Alert(String ip, String type, String detail) {}

    private final List<LogEntry> entries;
    private final Map<String, Integer> endpointHits = new HashMap<>();
    private final Map<Integer, Integer> statusCounts = new TreeMap<>();
    private final Map<String, Integer> authFailsByIp = new HashMap<>();
    private final Map<String, List<Long>> timesByIp = new HashMap<>();

    public Analyzer(List<LogEntry> entries) {
        this.entries = entries;
        for (LogEntry e : entries) {
            endpointHits.merge(e.endpoint(), 1, Integer::sum);
            statusCounts.merge(e.status(), 1, Integer::sum);
            if (e.status() == 401 || e.status() == 403) {
                authFailsByIp.merge(e.ip(), 1, Integer::sum);
            }
            timesByIp.computeIfAbsent(e.ip(), k -> new ArrayList<>())
                     .add(e.timestamp().getEpochSecond());
        }
    }

    public int totalRequests() { return entries.size(); }
        // Min-heap of size K: O(D log K), D = distinct endpoints
    public List<Map.Entry<String, Integer>> topEndpoints(int k) {
        PriorityQueue<Map.Entry<String, Integer>> heap =
            new PriorityQueue<Map.Entry<String, Integer>>(Map.Entry.comparingByValue());
        for (Map.Entry<String, Integer> e : endpointHits.entrySet()) {
            heap.offer(e);
            if (heap.size() > k) heap.poll();   // evict the smallest
        }
        List<Map.Entry<String, Integer>> result = new ArrayList<>(heap);
        result.sort(Map.Entry.<String, Integer>comparingByValue().reversed());
        return result;
    }
        public List<Alert> detectAlerts() {
        List<Alert> alerts = new ArrayList<>();

        for (Map.Entry<String, Integer> e : authFailsByIp.entrySet()) {
            if (e.getValue() > AUTH_FAIL_THRESHOLD) {
                alerts.add(new Alert(e.getKey(), "BRUTE_FORCE",
                        e.getValue() + " failed auth attempts (401/403)"));
            }
        }

        for (Map.Entry<String, List<Long>> e : timesByIp.entrySet()) {
            int peak = peakInWindow(e.getValue());
            if (peak > RATE_LIMIT_REQUESTS) {
                alerts.add(new Alert(e.getKey(), "RATE_LIMIT",
                        peak + " requests within " + RATE_WINDOW_SECONDS + "s"));
            }
        }

        alerts.sort(Comparator.comparing(Alert::type).thenComparing(Alert::ip));
        return alerts;
    }

    // Sliding window (two pointers) over sorted timestamps
    static int peakInWindow(List<Long> times) {
        Collections.sort(times);
        int best = 0, left = 0;
        for (int right = 0; right < times.size(); right++) {
            while (times.get(right) - times.get(left) >= RATE_WINDOW_SECONDS) {
                left++;
            }
            best = Math.max(best, right - left + 1);
        }
        return best;
    }
        static String statusLabel(int code) {
        return switch (code) {
            case 200 -> "OK";
            case 301 -> "Moved Permanently";
            case 304 -> "Not Modified";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 500 -> "Server Error";
            default -> "";
        };
    }

    public String buildReport(String source, int skipped) {
        StringBuilder sb = new StringBuilder();
        String bar = "=".repeat(52);
        sb.append(bar).append(String.format("%n"));
        sb.append(String.format("LOGLENS AUDIT REPORT%n"));
        sb.append(bar).append(String.format("%n"));
        sb.append(String.format("Source file    : %s%n", source));
        sb.append(String.format("Total requests : %d%n", totalRequests()));
        sb.append(String.format("Malformed lines: %d%n%n", skipped));

        sb.append(String.format("TOP 5 ENDPOINTS%n"));
        sb.append(String.format("%-28s %8s%n", "Endpoint", "Hits"));
        for (Map.Entry<String, Integer> e : topEndpoints(5)) {
            sb.append(String.format("%-28s %8d%n", e.getKey(), e.getValue()));
        }

        sb.append(String.format("%nSTATUS DISTRIBUTION%n"));
        sb.append(String.format("%-6s %-20s %7s %7s%n", "Code", "Meaning", "Count", "Share"));
        for (Map.Entry<Integer, Integer> e : statusCounts.entrySet()) {
            double pct = e.getValue() * 100.0 / totalRequests();
            sb.append(String.format("%-6d %-20s %7d %6.1f%%%n",
                    e.getKey(), statusLabel(e.getKey()), e.getValue(), pct));
        }

        sb.append(String.format("%nANOMALIES%n"));
        List<Alert> alerts = detectAlerts();
        if (alerts.isEmpty()) {
            sb.append(String.format("None detected.%n"));
        } else {
            for (Alert a : alerts) {
                sb.append(String.format("[%s] %-16s %s%n", a.type(), a.ip(), a.detail()));
            }
        }
        return sb.toString();
    }
}