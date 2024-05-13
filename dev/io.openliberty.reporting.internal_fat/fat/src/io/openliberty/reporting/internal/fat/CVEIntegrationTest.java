/*******************************************************************************
 * Copyright (c) 2024 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.reporting.internal.fat;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.runner.RunWith;
import org.testcontainers.containers.Network;

import com.ibm.websphere.simplicity.config.ServerConfiguration;

import componenttest.annotation.Server;
import componenttest.containers.SimpleLogConsumer;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.utils.HttpRequest;
import io.openliberty.reporting.internal.fat.integration.CVEServiceContainer;
import io.openliberty.reporting.internal.fat.integration.GetCVEs;
import io.openliberty.reporting.internal.fat.integration.ReportingServiceContainer;
import io.openliberty.reporting.internal.fat.integration.SiServiceContainer;

/**
 *
 */
@RunWith(FATRunner.class)
public class CVEIntegrationTest {

    public static Network network = Network.newNetwork();
    public static final String SERVER_NAME = "io.openliberty.reporting.integration.server";

    private static final String STORE_PATH = "/output/resources/security/";
    private static final String KEYSTORE_FILENAME = "key.p12";

    private static final String STORE_FULL = STORE_PATH + KEYSTORE_FILENAME;
    private static final String STORE_PASSWORD = "Liberty";

    public static ReportingServiceContainer reportingServiceContainer = new ReportingServiceContainer()
                    .withLogConsumer(new SimpleLogConsumer(CVEIntegrationTest.class, "ReportingServiceContainer"))
                    .withEnv("CVE_CLIENT_URI", "http://cve-service:9081/cve-service/cve")
                    .withEnv("SERVER_INFO_CLIENT_URI", "http://si-service:9082/server-info-service/serverInfo")
                    .withNetworkAliases("reporting-service")
                    .withNetwork(network);
    public static SiServiceContainer siServiceContainer = new SiServiceContainer().withLogConsumer(new SimpleLogConsumer(CVEIntegrationTest.class, "SIServiceContainer"))
                    .withNetwork(network)
                    .withNetworkAliases("si-service");
    public static CVEServiceContainer cveServiceContainer = new CVEServiceContainer().withLogConsumer(new SimpleLogConsumer(CVEIntegrationTest.class, "CVEServiceContainer"))
                    .withNetwork(network)
                    .withNetworkAliases("cve-service");

    @ClassRule
    public static RuleChain chain = RuleChain.outerRule(network).around(reportingServiceContainer).around(siServiceContainer).around(cveServiceContainer);

    protected static final Class<?> c = CVEIntegrationTest.class;

    @Server(SERVER_NAME)
    public static LibertyServer server;

    @BeforeClass
    public static void setUp() throws Exception {
        GetCVEs.setVersion();
    }

    @After
    public void teardown() throws Exception {
        server.stopServer();
    }

    public static void copyTrustStore(ReportingServiceContainer container, LibertyServer server) throws Exception {
        reportingServiceContainer.copyFileFromContainer(STORE_FULL, server.getServerRoot() + "/" + KEYSTORE_FILENAME);
        Path tmpDest = Paths.get(KEYSTORE_FILENAME);
        System.out.println("PATH IS: " + tmpDest);
    }

    @Test
    public void testNoCVEFound() throws Exception {
        new HttpRequest(cveServiceContainer.getFullUrl() + "/cve-service/cve/deleteAll").expectCode(204).run(String.class);
        ServerConfiguration config = server.getServerConfiguration();
        config.getCVEReporting().setUrlLink("https://" + reportingServiceContainer.getHost() + ":" + reportingServiceContainer.getMappedPort(9443) + "/report");
        server.updateServerConfiguration(config);
        copyTrustStore(reportingServiceContainer, server);
        server.setJvmOptions(Arrays.asList("-Dcom.ibm.ws.beta.edition=true", "-Dcve.insight.enabled=true",
                                           "-Djavax.net.ssl.trustStore=" + server.getServerRoot() + "/" + KEYSTORE_FILENAME,
                                           "-Djavax.net.ssl.trustStorePassword=" + STORE_PASSWORD, "-Djavax.net.ssl.trustStoreType=PKCS12"));
        server.startServer();

        assertNotNull("CVE Reporting checks not been carried out", server.waitForStringInLog("CWWKF1700I"));

        assertNotNull("CVEs have been found", server.waitForStringInLog("CWWKF1703I:.*"));
    }

    @Test
    public void testCVEFound() throws Exception {
        ServerConfiguration config = server.getServerConfiguration();
        config.getCVEReporting().setUrlLink("https://" + reportingServiceContainer.getHost() + ":" + reportingServiceContainer.getMappedPort(9443) + "/report");
        server.updateServerConfiguration(config);
        copyTrustStore(reportingServiceContainer, server);
        server.setJvmOptions(Arrays.asList("-Dcom.ibm.ws.beta.edition=true", "-Dcve.insight.enabled=true",
                                           "-Djavax.net.ssl.trustStore=" + server.getServerRoot() + "/" + KEYSTORE_FILENAME,
                                           "-Djavax.net.ssl.trustStorePassword=" + STORE_PASSWORD, "-Djavax.net.ssl.trustStoreType=PKCS12"));
        postCVEs();

        server.startServer();

        server.addIgnoredErrors(Collections.singletonList("CWWKF1702W"));

        assertNotNull("CVE Reporting checks not been carried out", server.waitForStringInLog("CWWKF1700I"));

        assertNotNull("No CVEs have been found", server.waitForStringInLog("CWWKF1702W:.*"));

        assertNotNull("CVE000 not found", server.waitForStringInLog("cve000"));
        assertNotNull("CVE001, CVE002 not found", server.waitForStringInLog("cve001, cve002"));
        assertNull("CVE003 found but shouldn't be", server.waitForStringInLog("cve004"));
        assertNull("CVE004 found but shouldn't be", server.waitForStringInLog("cve004"));
    }

    private void postCVEs() throws Exception {
        new HttpRequest(cveServiceContainer.getFullUrl() + "/cve-service/cve").method("POST").jsonBody(GetCVEs.getCVE1()).expectCode(204).run(String.class);
        new HttpRequest(cveServiceContainer.getFullUrl() + "/cve-service/cve").method("POST").jsonBody(GetCVEs.getCVE2()).expectCode(204).run(String.class);
        new HttpRequest(cveServiceContainer.getFullUrl() + "/cve-service/cve").method("POST").jsonBody(GetCVEs.getCVE3()).expectCode(204).run(String.class);
        new HttpRequest(cveServiceContainer.getFullUrl() + "/cve-service/cve").method("POST").jsonBody(GetCVEs.getCVE4()).expectCode(204).run(String.class);
        new HttpRequest(cveServiceContainer.getFullUrl() + "/cve-service/cve").method("POST").jsonBody(GetCVEs.getCVE5()).expectCode(204).run(String.class);
    }

}
