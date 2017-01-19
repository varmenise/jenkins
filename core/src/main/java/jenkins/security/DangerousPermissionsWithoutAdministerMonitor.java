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
import hudson.ExtensionList;
import hudson.PluginManager;
import hudson.XmlFile;
import hudson.model.AdministrativeMonitor;
import hudson.model.AsyncPeriodicWork;
import hudson.model.Saveable;
import hudson.model.TaskListener;
import hudson.model.User;
import hudson.model.listeners.SaveableListener;
import hudson.security.AuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.Permission;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import jenkins.util.SystemProperties;
import org.acegisecurity.Authentication;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Shows a warning when users have a 'dangerous' permission without being administrators.
 *
 * Administrators may not realize what RunScripts, ConfigureUpdateCenter or UploadPlugins do, exactly,
 * and grant these permissions to users who really shouldn't have them.
 */
@Extension
@Restricted(NoExternalUse.class)
public class DangerousPermissionsWithoutAdministerMonitor extends AdministrativeMonitor {

    private transient Map<User, List<Permission>> affectedUsersAndPermissions;
    private transient List<Permission> dangerousPermissionsForAnonymousWithoutAdminister;
    private transient List<Permission> dangerousPermissionsGrantedToAllUsers;

    @Override
    public synchronized boolean isActivated() {
        return !getUsersWithDangerousPermissionsButNotAdminister().isEmpty() || !getDangerousPermissionsForAnonymousWithoutAdminister().isEmpty();
    }

    /**
     * A map of users and the dangerous permissions they're granted. Only contains entries for users who have at least
     * one dangerous permission.
     *
     * @return map of users and the dangerous permissions they're granted
     */
    public synchronized Map<User, List<Permission>> getUsersWithDangerousPermissionsButNotAdminister() {
        if (this.affectedUsersAndPermissions == null) {
            return Collections.emptyMap();
        }
        return this.affectedUsersAndPermissions;
    }

    /**
     * Returns the list of dangerous permissions granted to the anonymous user.
     * @return the list of dangerous permissions granted to the anonymous user.
     */
    public synchronized List<Permission> getDangerousPermissionsForAnonymousWithoutAdminister() {
        if (this.dangerousPermissionsForAnonymousWithoutAdminister == null) {
            return Collections.emptyList();
        }
        return this.dangerousPermissionsForAnonymousWithoutAdminister;
    }

    public synchronized List<Permission> getDangerousPermissionsGrantedToAllUsers() {
        if (this.dangerousPermissionsGrantedToAllUsers == null) {
            return Collections.emptyList();
        }
        return this.dangerousPermissionsGrantedToAllUsers;
    }

    public synchronized boolean isAnyUsersWithDangerousPermissionsNotGrantedToAllUsers() {
        if (getUsersWithDangerousPermissionsButNotAdminister().isEmpty()) {
            // no users recorded
            return false;
        }
        // users with dangerous permissions recorded

        List<Permission> dangerousPermissionsGrantedToAllUsers = getDangerousPermissionsGrantedToAllUsers();

        if (dangerousPermissionsGrantedToAllUsers.isEmpty()) {
            // no permissions granted to all
            return true;
        }

        for (List<Permission> permissions : getUsersWithDangerousPermissionsButNotAdminister().values()) {
            for (Permission permission : permissions) {
                if (!dangerousPermissionsGrantedToAllUsers.contains(permission)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns true if Jenkins is known to be able to enumerate all users in the security realm.
     * Can return false even if all users are known to Jenkins due to limitations of the security realm API.
     *
     * @return true if Jenkins is known to be able to enumerate all users in the security realm.
     */
    public boolean isAbleToEnumerateAllUsers() {
        Jenkins j = Jenkins.getInstance();
        return j != null && j.getSecurityRealm() instanceof HudsonPrivateSecurityRealm;
    }

    private synchronized void setData(Map<User, List<Permission>> affectedUsersAndPermissions, List<Permission> dangerousPermissionsForAnonymousWithoutAdminister,
                                      List<Permission> dangerousPermissionsGrantedToAllUsers) {
        this.affectedUsersAndPermissions = affectedUsersAndPermissions;
        this.dangerousPermissionsForAnonymousWithoutAdminister = dangerousPermissionsForAnonymousWithoutAdminister;
        this.dangerousPermissionsGrantedToAllUsers = dangerousPermissionsGrantedToAllUsers;
    }

    @Override
    public String getDisplayName() {
        return Messages.DangerousPermissionsWithoutAdministerMonitor_DisplayName();
    }

    /**
     * Periodically scan all users for dangerous permissions
     */
    @Extension
    public static class Scanner extends AsyncPeriodicWork {

        public Scanner() {
            super("Dangerous Permissions Scan");
        }

        /**
         * Trigger the scan manually.
         */
        public static void scan() {
            new Thread(ExtensionList.lookup(AsyncPeriodicWork.class).get(DangerousPermissionsWithoutAdministerMonitor.Scanner.class)).start();
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
        protected synchronized void execute(TaskListener listener) throws IOException, InterruptedException {
            Jenkins j = Jenkins.getInstance();
            if (j == null) {
                return;
            }

            DangerousPermissionsWithoutAdministerMonitor monitor = (DangerousPermissionsWithoutAdministerMonitor)
                    j.getAdministrativeMonitor(DangerousPermissionsWithoutAdministerMonitor.class.getName());

            if (monitor == null) {
                // don't scan if extension isn't found
                listener.getLogger().println("DangerousPermissionsWithoutAdministerMonitor extension not found, skipping scan.");

                return;
            }

            if (!monitor.isEnabled()) {
                // don't scan if monitor is disabled
                listener.getLogger().println("DangerousPermissionsWithoutAdministerMonitor is disabled, skipping scan.");
                return;
            }

            final Map<User, List<Permission>> affectedUsersAndPermissions = new HashMap<>();
            List<Permission> permissionsGrantedToAllUsers = null;
            for (User user : User.getAll()) {
                try {
                    Authentication auth = user.impersonate();
                    if (j.getACL().hasPermission(auth, Jenkins.ADMINISTER)) {
                        // We only care about non-admins
                        listener.getLogger().println(String.format("User %s has Administer permission", user.getId()));
                        continue;
                    }

                    List<Permission> permissions = getGrantedDangerousPermissions(auth);
                    if (permissions.isEmpty()) {
                        // harmless permissions only
                        permissionsGrantedToAllUsers = Collections.emptyList();
                        listener.getLogger().println(String.format("User %s has no dangerous permissions", user.getId()));
                        continue;
                    }

                    listener.getLogger().println(String.format("User %s has DANGEROUS permissions but not Administer", user.getId()));
                    affectedUsersAndPermissions.put(user, permissions);

                    if (permissionsGrantedToAllUsers == null) {
                        // first non-admin user: initialize
                        permissionsGrantedToAllUsers = new ArrayList<>(permissions);
                        continue;
                    }

                    permissionsGrantedToAllUsers.retainAll(permissions);

                } catch (UsernameNotFoundException ex) {
                    listener.getLogger().println(String.format("User %s wasn't found in the security realm", user.getId()));
                    // not a real user, so just move on
                }
            }

            // determine permissions for anonymous user
            List<Permission> dangerousPermissionsForAnonymousWithoutAdminister;
            if (j.getACL().hasPermission(Jenkins.ANONYMOUS, Jenkins.ADMINISTER)) {
                listener.getLogger().println("Anonymous has Administer permission");
                dangerousPermissionsForAnonymousWithoutAdminister = Collections.emptyList();
            } else {
                dangerousPermissionsForAnonymousWithoutAdminister = getGrantedDangerousPermissions(Jenkins.ANONYMOUS);
                if (dangerousPermissionsForAnonymousWithoutAdminister.isEmpty()) {
                    listener.getLogger().println("Anonymous does not have dangerous permissions");
                } else {
                    listener.getLogger().println("Anonymous has DANGEROUS permissions but not Administer");
                }
            }


            monitor.setData(affectedUsersAndPermissions, dangerousPermissionsForAnonymousWithoutAdminister, permissionsGrantedToAllUsers);
        }

        @Override
        public long getRecurrencePeriod() {
            return SystemProperties.getLong(DangerousPermissionsWithoutAdministerMonitor.class.getName() + ".interval", 1000l * 60 * 5);
        }

        @Override
        public long getInitialDelay() {
            return 1000 * 60 * 15;
        }

    }

    /**
     * Trigger a re-scan of dangerous permissions whenever it looks like something related to permissions was saved
     * to prevent admins fixing whatever is wrong, but the admin monitor still showing up (or vice versa)
     */
    @Extension
    public static class Listener extends SaveableListener {
        @Override
        public void onChange(Saveable o, XmlFile file) {
            if (o instanceof Jenkins || o instanceof AuthorizationStrategy || o instanceof SecurityRealm) {
                DangerousPermissionsWithoutAdministerMonitor.Scanner.scan();
            }
        }
    }
}