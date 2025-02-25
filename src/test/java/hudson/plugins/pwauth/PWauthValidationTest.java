/*
 * Unit tests for PWauthValidation methods.
 */
package hudson.plugins.pwauth;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import hudson.Functions;
import hudson.plugins.pwauth.PWauthValidation;
import org.junit.Test;

public class PWauthValidationTest {

    /**
     * Test method for {@link hudson.plugins.pwauth.PWauthValidation#validateIP(String)}.
     */
    @Test
    public void testValidateIP() {
        assertTrue(PWauthValidation.validateIP("1.2.3.4"));
        assertTrue(PWauthValidation.validateIP("0.0.0.0"));
        assertTrue(PWauthValidation.validateIP("255.255.255.255"));

        assertFalse(PWauthValidation.validateIP(null));
        assertFalse(PWauthValidation.validateIP("1.2.3.4.5"));
        assertFalse(PWauthValidation.validateIP("1.2.3"));
        assertFalse(PWauthValidation.validateIP("1.2"));
        assertFalse(PWauthValidation.validateIP("1"));
        assertFalse(PWauthValidation.validateIP("1.2.3.4."));
        assertFalse(PWauthValidation.validateIP("1.2.3."));
        assertFalse(PWauthValidation.validateIP("1.2."));
        assertFalse(PWauthValidation.validateIP("1."));
        assertFalse(PWauthValidation.validateIP(""));
    }

    /**
     * Test method for {@link hudson.plugins.pwauth.PWauthValidation#validateWhitelist(String[])}.
     */
    @Test
    public void testValidateWhitelist() {
        assertTrue(PWauthValidation.validateWhitelist("1.2.3.4,1.2.3.5,1.2.3.6,1.2.3.7"));
        assertTrue(PWauthValidation.validateWhitelist("1.2.3.4;1.2.3.5;1.2.3.6;1.2.3.7"));
        assertTrue(PWauthValidation.validateWhitelist("1.2.3.4 1.2.3.5 1.2.3.6 1.2.3.7"));
        assertTrue(PWauthValidation.validateWhitelist("1.2.3.4, 1.2.3.5, 1.2.3.6, 1.2.3.7"));
        assertTrue(PWauthValidation.validateWhitelist("1.2.3.4,1.2.3.5;1.2.3.6 1.2.3.7"));
        assertTrue(PWauthValidation.validateWhitelist("1.2.3.4, 1.2.3.5; 1.2.3.6   1.2.3.7"));
        assertTrue(PWauthValidation.validateWhitelist("1.2.3.4\t1.2.3.5\t1.2.3.6\t1.2.3.7"));
        assertTrue(PWauthValidation.validateWhitelist(""));
        assertTrue(PWauthValidation.validateWhitelist(" "));
        assertTrue(PWauthValidation.validateWhitelist(null));
        assertTrue(PWauthValidation.validateWhitelist(","));

        assertFalse(PWauthValidation.validateWhitelist("1.2.3.,"));
        assertFalse(PWauthValidation.validateWhitelist("1,2,3,4"));
        assertFalse(PWauthValidation.validateWhitelist("1.2.3.4,1.2.3."));
        assertFalse(PWauthValidation.validateWhitelist("1.2.3.4,1.2.3,4"));
    }

    /**
     * Test method for {@link hudson.plugins.pwauth.PWauthValidation#validatePath(String[])}.
     * Test cases covering traversal sequences have been added to ensure they are identified as invalid,
     * and additional test cases for valid paths are added to ensure they pass the validation.
     */
    @Test
    public void testValidatePath() {
        if (Functions.isWindows()) {
            return;
        }

        // Invalid path test cases with traversal sequences
        // Test case for a simple traversal sequence
        assertFalse("Path with '../' should be invalid",
            PWauthValidation.validatePath(new String[] {"../etc/passwd"}));

        // Test case with traversal in the middle of the path
        assertFalse("Path with traversal in the middle should be invalid",
            PWauthValidation.validatePath(new String[] {"dir/../config"}));

        // Test case for multiple traversal sequences
        assertFalse("Path with multiple traversal sequences should be invalid",
            PWauthValidation.validatePath(new String[] {"../../secret"}));

        // Valid path test cases
        // Test case for a simple valid relative path
        assertTrue("Simple relative path should be valid",
            PWauthValidation.validatePath(new String[] {"config"}));

        // Test case for a valid nested relative path
        assertTrue("Nested relative path should be valid",
            PWauthValidation.validatePath(new String[] {"dir/config"}));

        // Test case for a valid file with extension in nested folders
        assertTrue("Nested relative path with file extension should be valid",
            PWauthValidation.validatePath(new String[] {"dir/subdir/config.xml"}));

        // Test case for multiple valid paths in the same array
        assertTrue("Multiple valid paths should pass validation",
            PWauthValidation.validatePath(new String[] {"config", "dir/config.conf"}));
    }
}
