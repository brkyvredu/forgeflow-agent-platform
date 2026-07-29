package dev.forgeflow.analysis.service;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

@Service
public class JavaMetricService {
    private static final Pattern IMPORT = Pattern.compile("(?m)^\\s*import\\s+[^;]+;");
    private static final Pattern TYPE = Pattern.compile("\\b(class|interface|enum|record)\\s+[A-Za-z_$][\\w$]*");
    private static final Pattern METHOD = Pattern.compile(
            "(?m)^(?![\\t ]*(?:if|for|while|switch|catch|try|else|do)\\b)[\\t ]*"
                    + "(?:(?:public|protected|private|static|final|synchronized|abstract|native|default)\\s+)*"
                    + "[\\w$<>, ?\\[\\].]+\\s+[A-Za-z_$][\\w$]*\\s*"
                    + "\\([^;{}]*\\)\\s*(?:throws\\s+[^{}]+)?\\{"
    );
    private static final Pattern TODO = Pattern.compile("(?i)\\b(TODO|FIXME|HACK)\\b");
    private static final Pattern DECISION = Pattern.compile("\\b(if|for|while|case|catch)\\b|&&|\\|\\||\\?");
    private static final Set<String> DANGEROUS_APIS = Set.of(
            "Runtime.getRuntime().exec", "ProcessBuilder", "ObjectInputStream", "ScriptEngineManager"
    );

    public JavaMetrics analyze(String source) {
        int lineCount = source.isEmpty() ? 0 : source.split("\\R", -1).length;
        int importCount = count(IMPORT, source);
        int typeCount = count(TYPE, source);
        int methodCount = count(METHOD, source);
        int todoCount = count(TODO, source);
        int complexityEstimate = 1 + count(DECISION, source);
        int maximumNesting = maximumBraceNesting(source);
        var dangerousApis = DANGEROUS_APIS.stream().filter(source::contains).sorted().toList();

        return new JavaMetrics(
                lineCount,
                importCount,
                typeCount,
                methodCount,
                todoCount,
                complexityEstimate,
                maximumNesting,
                dangerousApis
        );
    }

    private int count(Pattern pattern, String source) {
        Matcher matcher = pattern.matcher(source);
        int total = 0;
        while (matcher.find()) {
            total++;
        }
        return total;
    }

    private int maximumBraceNesting(String source) {
        int depth = 0;
        int maximum = 0;
        boolean inString = false;
        boolean escaped = false;
        for (char value : source.toCharArray()) {
            if (value == '"' && !escaped) {
                inString = !inString;
            }
            if (!inString) {
                if (value == '{') {
                    maximum = Math.max(maximum, ++depth);
                } else if (value == '}') {
                    depth = Math.max(0, depth - 1);
                }
            }
            escaped = value == '\\' && !escaped;
            if (value != '\\') {
                escaped = false;
            }
        }
        return maximum;
    }

    public record JavaMetrics(
            int lineCount,
            int importCount,
            int typeCount,
            int methodCount,
            int todoCount,
            int complexityEstimate,
            int maximumNesting,
            java.util.List<String> dangerousApis
    ) { }
}
