package hudson.plugins.pwauth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

@Extension
public final class PWauthDescriptor extends Descriptor<SecurityRealm> {

    public PWauthDescriptor() {
        super(PWauthSecurityRealm.class);
        load();
    }

    @Override
    public String getDisplayName() {
        return "PWauth Authentication";
    }

    public FormValidation doTest(
            @QueryParameter final String pwauthPath,
            @QueryParameter final String whitelist,
            @QueryParameter final String grepPath,
            @QueryParameter final String catPath,
            @QueryParameter final String groupsPath,
            @QueryParameter final String idPath) {

        if (!PWauthValidation.isValidFilePath(pwauthPath)) {
            return FormValidation.error("pwauth Path Invalid");
        }
        if (!PWauthValidation.isValidFilePath(grepPath)) {
            return FormValidation.error("grep Path Invalid");
        }
        if (!PWauthValidation.isValidFilePath(catPath)) {
            return FormValidation.error("cat Path Invalid");
        }
        if (!PWauthValidation.isValidFilePath(groupsPath)) {
            return FormValidation.error("groups Path Invalid");
        }
        if (!PWauthValidation.isValidFilePath(idPath)) {
            return FormValidation.error("id Path Invalid");
        }

        if (whitelist != null && !PWauthValidation.validateWhitelist(whitelist)) {
            return FormValidation.error("IPs Invalid");
        }

        return FormValidation.ok("Success");
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        save();
        return true;
    }
}
