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

package jenkins.security.DangerousPermissionsWithoutAdministerMonitor;

def f = namespace(lib.FormTagLib)

boolean shouldShowCollapsedList(def my) {
    return my.usersWithDangerousPermissionsButNotAdminister.size() > 5 && !my.dangerousPermissionsGrantedToAllUsers.isEmpty();
}

div(class: "warning") {
    if (!my.usersWithDangerousPermissionsButNotAdminister.isEmpty()) {

        if (shouldShowCollapsedList(my)) {
            // once there's 6+ listed users, collapse entries
            if (my.ableToEnumerateAllUsers) {
                p(_("allUsers"))
            } else {
                p(_("allKnownUsers"))
            }
            ul {
                my.dangerousPermissionsGrantedToAllUsers.each { permission ->
                    li(_(permission.name))
                }
            }

            if (my.anyUsersWithDangerousPermissionsNotGrantedToAllUsers) {
                p(_("plusSomeUsers"))
            }
        }

        if (!shouldShowCollapsedList(my)) {
            p(_("someUsers"))
        }
        ul {
            my.usersWithDangerousPermissionsButNotAdminister.each { user, permissions ->
                if (shouldShowCollapsedList(my)) {
                    extraPermissions = new ArrayList<>(permissions)
                    extraPermissions.removeAll(my.dangerousPermissionsGrantedToAllUsers)
                    if (extraPermissions.isEmpty()) {
                        return
                    }
                    permissions = extraPermissions
                }

                li {
                    a(user.displayName, href: rootURL + '/' + user.ugrl)
                    ul {
                        permissions.each { permission ->
                            li(_(permission.name))
                        }
                    }
                }
            }
        }
        if (!my.ableToEnumerateAllUsers) {
            p(_("cannotEnumerate"))
        }
    }

    if (!my.dangerousPermissionsForAnonymousWithoutAdminister.isEmpty()) {
        p {
            text(_("The following dangerous permissions are granted to anonymous users, without them being administrators:"))
            ul {
                my.dangerousPermissionsForAnonymousWithoutAdminister.each { permission ->
                    li(_(permission.name))
                }
            }
        }
    }
}
p(raw(_("explanation", rootURL + '/configureSecurity')))
p {
    a (_("Learn more…"), href: "https://jenkins.io/redirect/dangerous-permissions", target: '_blank')
}
form(method: "post", action: "${rootURL}/${it.url}/disable") {
    div {
        f.submit(value: _("Do not show this warning again"))
    }
}
