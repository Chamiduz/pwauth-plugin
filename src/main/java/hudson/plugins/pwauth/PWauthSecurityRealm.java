package hudson.plugins.pwauth;

import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

/**
 * TODO Replace String Messages with Property Messages
 * TODO additional to white list, support username:password@host URL-Authentication in {@link PWauthFilter}
 * TODO allow host names in white list
 *
 * Refactored to use the updated file path validation (PWauthValidation.isValidFilePath) for all file path usages.
 * This revision ensures consistency as required by defect fix plan step B.
 *
 * @author mallox
 */
public class PWauthSecurityRealm extends AbstractPasswordBasedSecurityRealm {
    public final String pwauthPath;
    public final String whitelist;
    public final boolean enableParamAuth;
    public final String idPath;
    public final String groupsPath;
    public final String catPath;
    public final String grepPath;
    
    @DataBoundConstructor
    public PWauthSecurityRealm(final String pwauthPath, final String whitelist, final boolean enableParamAuth, final String idPath, final String groupsPath,
                               final String catPath, final String grepPath) {
        this.pwauthPath = pwauthPath;
        this.whitelist = whitelist;
        this.enableParamAuth = enableParamAuth;
        this.idPath = idPath;
        this.groupsPath = groupsPath;
        this.catPath = catPath;
        this.grepPath = grepPath;
        
        // Validate and set each file path using the updated validation method
        validateAndSetPath(pwauthPath, new PathSetter() {
            public void setPath(String path) {
                PWauthUtils.setPwAuthPath(path);
            }
        });
        validateAndSetPath(grepPath, new PathSetter() {
            public void setPath(String path) {
                PWauthUtils.setGrepPath(path);
            }
        });
        validateAndSetPath(catPath, new PathSetter() {
            public void setPath(String path) {
                PWauthUtils.setCatPath(path);
            }
        });
        validateAndSetPath(groupsPath, new PathSetter() {
            public void setPath(String path) {
                PWauthUtils.setGroupsPath(path);
            }
        });
        validateAndSetPath(idPath, new PathSetter() {
            public void setPath(String path) {
                PWauthUtils.setIdPath(path);
            }
        });
    }
    
    // Helper interface for setting file paths
    private interface PathSetter {
        void setPath(String path);
    }
    
    // Helper method that validates a file path using PWauthValidation and then applies the appropriate setter
    private void validateAndSetPath(String filePath, PathSetter setter) {
        if (PWauthValidation.isValidFilePath(filePath)) {
            setter.setPath(filePath);
        }
        // Optionally, handle invalid file paths (e.g., logging a warning) if needed
    }
    
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
            new PWauthAthenticationManager(),
            new UserDetailsService() {
                public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
                    try {
                        if (PWauthUtils.userExists(username)) {
                            return new User(username, "", true, true, true, true,
                                new GrantedAuthority[] { AUTHENTICATED_AUTHORITY });
                        }
                    } catch (IOException e) {
                        // Optionally log the exception
                    }
                    throw new UsernameNotFoundException("No such Unix user: " + username);
                }
            }
        );
    }
    
    @Override
    public UserDetails authenticate(String username, String password) throws AuthenticationException {
        try {
            if (PWauthUtils.isUserValid(username, password)) {
                return new User(username, "", true, true, true, true,
                    new GrantedAuthority[] { AUTHENTICATED_AUTHORITY });
            }
        } catch (Exception e) {
            throw new AuthenticationException("User could not be authenticated", e) {
                private static final long serialVersionUID = 8636276439158457192L;
            };
        }
        return null;
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        try {
            if (PWauthUtils.userExists(username)) {
                return new User(username, "", true, true, true, true,
                    new GrantedAuthority[] { AUTHENTICATED_AUTHORITY });
            }
        } catch (IOException e) {
            // Optionally log the exception
        }
        throw new UsernameNotFoundException("No such Unix user: " + username);
    }
    
    @Override
    public GroupDetails loadGroupByGroupname(final String groupname) throws UsernameNotFoundException, DataAccessException {
        if (PWauthUtils.groupExists(groupname)) {
            throw new UsernameNotFoundException(groupname);
        }
        return new GroupDetails() {
            @Override
            public String getName() {
                return groupname;
            }
        };
    }
    
    @Override
    public Filter createFilter(FilterConfig filterConfig) {
        return new PWauthFilter(super.createFilter(filterConfig), this);
    }
}
