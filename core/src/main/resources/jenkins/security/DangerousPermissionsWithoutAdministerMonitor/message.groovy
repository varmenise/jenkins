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

div(class: "warning") {
    if (!my.usersWithDangerousPermissionsButNotAdminister.empty) {
        p(_("The users below have at least one dangerous permission, but are not administrators:"))

        ul {
            my.usersWithDangerousPermissionsButNotAdminister.each { user, permissions ->
                li {
                    a(user.displayName, href: rootURL + '/' + user.url)
                    ul {
                        permissions.each { permission ->
                            li(_(permission.name))
                        }
                    }
                }
            }
        }
        if (!my.ableToEnumerateAllUsers) {
            p(_("The above list may be incomplete, as Jenkins may not be able to enumerate all users that can log in."))
        }
    }

    if (!my.dangerousPermissionsForAnonymousWithoutAdminister.empty) {
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