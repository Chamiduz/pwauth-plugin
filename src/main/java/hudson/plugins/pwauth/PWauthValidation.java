package hudson.plugins.pwauth;

import java.io.File;
import java.util.regex.Pattern;

public class PWauthValidation {
    static final String listSeparatorEx = "(\\s)*[,|;|\\s](\\s)*";
    private static final String ipEx = "^\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b$";
    
    // Step C: Define a whitelist of allowed directories for file paths
    private static final String[] ALLOWED_DIRECTORIES = {
        "/usr/local/pwauth",
        "/opt/pwauth"
    };

    static boolean validateIP(String ip) {
        if (ip == null) {
            return false;
        }
        return Pattern.matches(ipEx, ip);
    }

    static boolean validateWhitelist(String whitelist) {
        if (whitelist != null && !whitelist.isEmpty()) {
            for (String ip : whitelist.split(listSeparatorEx)) {
                if (!validateIP(ip.trim())) {
                    return false;
                }
            }
        }
        return true;
    }

    static boolean validatePath(String path) {
        if (path == null || path.isEmpty()) {
            return true;
        }
        String cleanPath = path.trim();
        // Step B: Prevent path traversal by rejecting paths containing '../' or '..\\'
        if (cleanPath.contains("../") || cleanPath.contains("..\\")) {
            return false;
        }
        try {
            File file = new File(cleanPath);
            // Step C: Validate that the file resides in one of the allowed directories
            if (!isPathAllowed(file)) {
                return false;
            }
            return file.isFile() && file.canExecute();
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isPathAllowed(File file) {
        try {
            String canonicalPath = file.getCanonicalPath();
            for (String allowedDir : ALLOWED_DIRECTORIES) {
                if (canonicalPath.startsWith(allowedDir)) {
                    return true;
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }
}
