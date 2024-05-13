/*******************************************************************************
 * Copyright (c) 2024 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.reporting.internal.fat.integration;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.runner.RunWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import componenttest.custom.junit.runner.FATRunner;

/**
 *
 */
@RunWith(FATRunner.class)
public class ReportingServiceContainer extends GenericContainer<ReportingServiceContainer> {

    public static final int HTTP_PORT = 9080;

    public static final int HTTPS_PORT = 9443;

    private static final String KEYSTORE_FILENAME = "key.p12";
    private static final String STORE_PATH = "/output/resources/security";
    private static final String STORE_FULL = STORE_PATH + "/" + KEYSTORE_FILENAME;
    private static final String STORE_PASSWORD = "Liberty";

    public ReportingServiceContainer() {
        this(DockerImageName.parse("localhost/cve-reporting:latest"));

    }

    public ReportingServiceContainer(DockerImageName imageName) {
        super(imageName);

        withExposedPorts(HTTP_PORT, HTTPS_PORT);
    }

    /** {@inheritDoc} */
    @Override
    protected void configure() {
        super.configure();

        List<String> subCommands = new ArrayList<>();

        subCommands.add("rm -rf " + STORE_FULL);
        subCommands.add("echo '<server description=\"Default Server\">\n    <keyStore id=\"defaultKeyStore\" password=\"" + STORE_PASSWORD
                        + "\" />\n</server>' > /config/configDropins/defaults/keystore.xml");
        subCommands.add(getCertGenerationCommand(STORE_FULL, STORE_PASSWORD, getHost()));
        subCommands.add("/opt/ol/wlp/bin/server run defaultServer");
        String var = String.join(" && ", subCommands);
        withCommand("sh", "-c", var);

    }

    public File getKeystoreFile() {
        return new File(STORE_FULL);
    }

    private String getCertGenerationCommand(String filepath, String password, String ipAddress) {
        List<String> sans = new ArrayList<>();
        if (looksLikeIp(ipAddress)) {
            sans.add("IP:" + ipAddress);
        } else {
            sans.add("DNS:" + ipAddress);
        }
        List<String> cmd = Arrays.asList("keytool",
                                         "-genkey",
                                         "-keystore", filepath,
                                         "-storetype", "PKCS12",
                                         "-storepass", password,
                                         "-keypass", password,
                                         "-validity", "30",
                                         "-dname", "CN=testCVEReporting",
                                         "-ext", "SAN=" + String.join(",", sans),
                                         "-sigalg", "SHA256withRSA",
                                         "-keyalg", "RSA",
                                         "-keysize", "2048");

        return String.join(" ", cmd);
    }

    private boolean looksLikeIp(String maybeIp) {
        return maybeIp.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
    }

}
