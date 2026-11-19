import java.time.Instant;

public record LogEntry(String ip, Instant timestamp, String method,
                       String endpoint, int status, long bytes) {}