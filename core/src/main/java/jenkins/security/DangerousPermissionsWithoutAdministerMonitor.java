/*
 * The MIT License
 *
 * Copyright (c) 2016, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package jenkins.security;
import hudson.Extension;
import hudson.PluginManager;
import hudson.model.AdministrativeMonitor;
import hudson.model.User;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Extension
@Restricted(NoExternalUse.class)
public class DangerousPermissionsWithoutAdministerMonitor extends AdministrativeMonitor {
    @Override
    public boolean isActivated() {
        return !getUsersWithDangerousPermissionsButNotAdminister().isEmpty() || !getDangerousPermissionsForAnonymousWithoutAdminister().isEmpty();
    }
    // TODO check authenticated to not duplicate for each user -- is this even possible?

    public Map<User, List<Permission>> getUsersWithDangerousPermissionsButNotAdminister() {
        Jenkins j = Jenkins.getInstance();
        final Map<User, List<Permission>> affectedUsersAndPermissions = new HashMap<>();
        for (User user : User.getAll()) {
            try {
                Authentication auth = user.impersonate();
                if (j.getACL().hasPermission(auth, Jenkins.ADMINISTER)) {
                    // We only care about non-admins
                    continue;
                }
                affectedUsersAndPermissions.put(user, getGrantedDangerousPermissions(auth));
            } catch (UsernameNotFoundException ex) {
                // not a real user, so just move on
            }
        }
        return affectedUsersAndPermissions;
    }

    public List<Permission> getDangerousPermissionsForAnonymousWithoutAdminister() {
        if (!Jenkins.getInstance().getACL().hasPermission(Jenkins.ANONYMOUS, Jenkins.ADMINISTER)) {
            return Collections.emptyList();
        }
        List<Permission> grantedPermissions = getGrantedDangerousPermissions(Jenkins.ANONYMOUS);
        if (!grantedPermissions.isEmpty()) {
            return grantedPermissions;
        }
        return Collections.emptyList();
    }

    private List<Permission> getGrantedDangerousPermissions(Authentication authentication) {
        Jenkins j = Jenkins.getInstance();
        List<Permission> grantedPermissions = new ArrayList<>();
        for (Permission permission : new Permission[]{ Jenkins.RUN_SCRIPTS, PluginManager.UPLOAD_PLUGINS, PluginManager.CONFIGURE_UPDATECENTER }) {
            if (j.getACL().hasPermission(authentication, permission)) {
                grantedPermissions.add(permission);
            }
        }
        return grantedPermissions;
    }

    @Override
    public String getDisplayName() {
        return Messages.DangerousPermissionsWithoutAdministerMonitor_DisplayName();
    }
}