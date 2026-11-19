import java.io.IOException;
import java.nio.file.*;
import java.util.*;

public class Main {
    private static Analyzer analyzer = null;
    private static String source = "";
    private static int skipped = 0;

    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        while (true) {
            System.out.println("\n=== LogLens ===");
            System.out.println("1) Load log file");
            System.out.println("2) Show report");
            System.out.println("3) Export report to audit_report.txt");
            System.out.println("4) Quit");
            System.out.print("> ");
            if (!in.hasNextLine()) break;
            String choice = in.nextLine().trim();

            if (choice.equals("4")) break;
            switch (choice) {
                case "1" -> load(in);
                case "2" -> show();
                case "3" -> export();
                default -> System.out.println("Pick 1-4.");
            }
        }
        System.out.println("Bye.");
    }

    private static void load(Scanner in) {
        System.out.print("Path [sample_access.log]: ");
        String input = in.hasNextLine() ? in.nextLine().trim() : "";
        Path p = Path.of(input.isEmpty() ? "sample_access.log" : input);
        try {
            LogParser parser = new LogParser();
            List<LogEntry> entries = parser.parse(p);
            analyzer = new Analyzer(entries);
            source = p.toString();
            skipped = parser.getSkipped();
            System.out.printf("Loaded %d entries (%d skipped).%n", entries.size(), skipped);
        } catch (IOException e) {
            System.out.println("Could not read file: " + e.getMessage());
        }
    }

    private static void show() {
        if (analyzer == null) { System.out.println("Load a file first (option 1)."); return; }
        System.out.println(analyzer.buildReport(source, skipped));
    }

    private static void export() {
        if (analyzer == null) { System.out.println("Load a file first (option 1)."); return; }
        try {
            Files.writeString(Path.of("audit_report.txt"), analyzer.buildReport(source, skipped));
            System.out.println("Saved audit_report.txt");
        } catch (IOException e) {
            System.out.println("Could not write report: " + e.getMessage());
        }
    }
}