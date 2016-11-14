/*
 * The MIT License
 *
 * Copyright (c) 2015 Red Hat, Inc.
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
package hudson.model;

import static org.junit.Assert.*;

import java.io.File;
import java.util.concurrent.Callable;

import com.gargoylesoftware.htmlunit.xml.XmlPage;
import hudson.slaves.OfflineCause;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import hudson.slaves.DumbSlave;

import jenkins.security.ApiTokenProperty;
import org.hamcrest.Matcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.kohsuke.stapler.Stapler;

public class ComputerTest {

    @Rule public JenkinsRule j = new JenkinsRule();

    @Test
    public void discardLogsAfterDeletion() throws Exception {
        DumbSlave delete = j.createOnlineSlave(Jenkins.getInstance().getLabelAtom("delete"));
        DumbSlave keep = j.createOnlineSlave(Jenkins.getInstance().getLabelAtom("keep"));
        File logFile = delete.toComputer().getLogFile();
        assertTrue(logFile.exists());

        Jenkins.getInstance().removeNode(delete);

        assertFalse("Slave log should be deleted", logFile.exists());
        assertFalse("Slave log directory should be deleted", logFile.getParentFile().exists());

        assertTrue("Slave log should be kept", keep.toComputer().getLogFile().exists());
    }

    /**
     * Verify we can't rename a node over an existing node.
     */
    @Issue("JENKINS-31321")
    @Test
    public void testProhibitRenameOverExistingNode() throws Exception {
        final String NOTE = "Rename node to name of another node should fail.";

        Node nodeA = j.createSlave("nodeA", null, null);
        Node nodeB = j.createSlave("nodeB", null, null);

        WebClient wc = j.createWebClient();
        HtmlForm form = wc.getPage(nodeB, "configure").getFormByName("config");
        form.getInputByName("_.name").setValueAttribute("nodeA");

        try {
            j.submit(form);
            fail(NOTE);
        } catch (FailingHttpStatusCodeException e) {
            assertThat(NOTE, e.getStatusCode(), equalTo(400));
            assertThat(NOTE, e.getResponse().getContentAsString(),
                    containsString("Agent called ‘nodeA’ already exists"));
        }
    }

    @Test
    public void doNotShowUserDetailsInOfflineCause() throws Exception {
        DumbSlave slave = j.createOnlineSlave();
        final Computer computer = slave.toComputer();
        computer.setTemporarilyOffline(true, new OfflineCause.UserCause(User.get("username"), "msg"));

        XmlPage page = j.createWebClient().goToXml("computer/" + computer.getName() + "/config.xml");
        String content = page.getWebResponse().getContentAsString("UTF-8");
        assertThat(content, containsString("temporaryOfflineCause"));
        assertThat(content, containsString(">username<"));
        assertThat(content, not(containsString("ApiTokenProperty")));
        assertThat(content, not(containsString("apiToken")));
    }
}
