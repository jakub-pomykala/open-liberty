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

import org.junit.runner.RunWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import componenttest.custom.junit.runner.FATRunner;

/**
 *
 */
@RunWith(FATRunner.class)
public class SiServiceContainer extends GenericContainer<SiServiceContainer> {

    public static final int HTTP_PORT = 9082;

    public SiServiceContainer() {
        this(DockerImageName.parse("localhost/si-service:latest"));
    }

    public SiServiceContainer(DockerImageName imageName) {
        super(imageName);

        withExposedPorts(HTTP_PORT);
    }

    public int getHttpPort() {
        return getMappedPort(HTTP_PORT);
    }

    public String getFullUrl() {
        return "http://" + getHost() + ":" + getHttpPort();
    }
}
