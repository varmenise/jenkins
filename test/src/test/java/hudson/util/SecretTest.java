/*
 * The MIT License
 *
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi
 * Copyright (c) 2016, CloudBees Inc.
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
package hudson.util;

import hudson.model.FreeStyleProject;
import hudson.model.ParametersDefinitionProperty;
import hudson.model.PasswordParameterDefinition;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * Tests {@link Secret}.
 */
public class SecretTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();


    @Test
    @Issue("SECURITY-304")
    public void encryptedValueStaysTheSameAfterRoundtrip() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        project.addProperty(new ParametersDefinitionProperty(new PasswordParameterDefinition("p", "s3cr37", "Keep this a secret")));
        project = j.configRoundtrip(project);
        String round1 = project.getConfigFile().asString();
        project = j.configRoundtrip(project);
        String round2 = project.getConfigFile().asString();
        assertEquals(round1, round2);


        //But reconfiguring will make it a new value
        project = j.jenkins.getItemByFullName(project.getFullName(), FreeStyleProject.class);
        project.removeProperty(ParametersDefinitionProperty.class);
        project.addProperty(new ParametersDefinitionProperty(new PasswordParameterDefinition("p", "s3cr37", "Keep this a secret")));
        project = j.configRoundtrip(project);
        String round3 = project.getConfigFile().asString();
        assertNotEquals(round2, round3);
        //Saving again will produce the same
        project = j.configRoundtrip(project);
        String round4 = project.getConfigFile().asString();
        assertEquals(round3, round4);
    }
}
