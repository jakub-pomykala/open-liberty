/*******************************************************************************
 * Copyright (c) 2018, 2023 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.fat.common.mp.jwt.utils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.FileAsset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;

import com.ibm.websphere.simplicity.ShrinkHelper;
import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.security.fat.common.mp.jwt.MPJwt11FatConstants;
import com.ibm.ws.security.fat.common.mp.jwt.MPJwtFatConstants;

import componenttest.topology.impl.LibertyServer;

public class MPJwtAppSetupUtils {

    protected static Class<?> thisClass = MPJwtAppSetupUtils.class;

    /***************************************************/
    public void deployMicroProfileApp(LibertyServer server) throws Exception {
        List<String> classList = createAppClassList("com.ibm.ws.jaxrs.fat.microProfileApp.ClaimInjection.ApplicationScoped.Instance.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.ClaimInjection.NotScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.ClaimInjection.RequestScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.ClaimInjection.SessionScoped.Instance.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.ClaimInjectionAllTypesMicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.ClaimInjectionInstanceMicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.CommonMicroProfileMarker",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.Injection.ApplicationScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.Injection.NotScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.Injection.RequestScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.Injection.SessionScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.JsonWebTokenInjectionMicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.SecurityContext.ApplicationScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.SecurityContext.NotScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.SecurityContext.RequestScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.SecurityContext.SessionScoped.MicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.SecurityContextMicroProfileApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.Utils");
        ShrinkHelper.exportAppToServer(server, genericCreateArchiveWithJsps(MPJwt11FatConstants.MICROPROFILE_SERVLET, classList));
        server.addInstalledAppForValidation(MPJwt11FatConstants.MICROPROFILE_SERVLET);

    }

    public void deployRSServerNoMPConfigInAppApp(LibertyServer server) throws Exception {
        List<String> classList = createAppClassList("com.ibm.ws.jaxrs.fat.microProfileApp.CommonMicroProfileMarker_MPConfigNotInApp",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.microProfileMPConfigNotInApp.MicroProfileApp");
        ShrinkHelper.exportAppToServer(server, genericCreateArchiveWithPems(MPJwtFatConstants.NO_MP_CONFIG_IN_APP_ROOT_CONTEXT + ".war",
                                                                            MPJwtFatConstants.NO_MP_CONFIG_IN_APP_ROOT_CONTEXT, classList));
        server.addInstalledAppForValidation(MPJwtFatConstants.NO_MP_CONFIG_IN_APP_ROOT_CONTEXT);

    }

    public void deployRSServerMPConfigInAppInMetaInfApp(LibertyServer server, String warName, String configSettings) throws Exception {
        String sourceName = "microProfileMP-ConfigInMETA-INF.war";
        String metaInfFile = "/META-INF/microprofile-config.properties";
        List<String> classList = createAppClassList("com.ibm.ws.jaxrs.fat.microProfileApp.CommonMicroProfileMarker_MPConfigInMetaInf",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.microProfileMPConfigInMetaInf.MicroProfileApp");
        ShrinkHelper.exportAppToServer(server, genericCreateArchiveWithPemsAndMPConfig(sourceName, warName, classList, metaInfFile, configSettings));
        server.addInstalledAppForValidation(warName);

    }

    public void deployRSServerMPConfigInAppUnderWebInfApp(LibertyServer server, String warName, String configSettings) throws Exception {
        String sourceName = "microProfileMP-ConfigUnderWeb-INF.war";
        String webInfFile = "/WEB-INF/classes/META-INF/microprofile-config.properties";
        List<String> classList = createAppClassList("com.ibm.ws.jaxrs.fat.microProfileApp.CommonMicroProfileMarker_MPConfigUnderWebInf",
                                                    "com.ibm.ws.jaxrs.fat.microProfileApp.microProfileMPConfigUnderWebInf.MicroProfileApp");
        ShrinkHelper.exportAppToServer(server, genericCreateArchiveWithPemsAndMPConfig(sourceName, warName, classList, webInfFile, configSettings));
        server.addInstalledAppForValidation(warName);

    }

    /**
     * Create a test war using files from the source war and the classList. Add a default list of pem files
     *
     * @param sourceWarName - the source war to get xml files from
     * @param baseWarName - the base name of the war file to create
     * @param classList - the list of classes to add to the war
     * @return - return a war built from the specified built class files, xml's and pem files
     * @throws Exception
     */
    protected WebArchive genericCreateArchiveWithPems(String sourceWarName, String baseWarName, List<String> classList) throws Exception {
        try {
            String warName = baseWarName + ".war";
            WebArchive newWar = ShrinkWrap.create(WebArchive.class, warName);
            addDefaultFileAssetsForAppsToWar(sourceWarName, newWar);
            addPemFilesForAppsToWar(warName, newWar);
            for (String theClass : classList) {
                newWar.addClass(theClass);
            }
            return newWar;
        } catch (Exception e) {
            Log.error(thisClass, "genericCreateArchive", e);
            throw e;
        }
    }

    /**
     * Create a test war using files from the source war and the classList. Add a default list of pem files.
     * Also add a microprofile-config.properties file with the content passed to this method
     *
     * @param sourceWarName - the source war to get xml files from
     * @param baseWarName - the base name of the war file to create
     * @param classList - the list of classes to add to the war
     * @param mpConfig - the path the the microprofile-config.properties file
     * @param fileContent - the content of the microprofile-config.properties file
     * @return - return a war built from the specified built class files, xml's and pem files
     * @throws Exception
     */
    protected WebArchive genericCreateArchiveWithPemsAndMPConfig(String sourceWarName, String baseWarName, List<String> classList, String mpConfig,
                                                                 String fileContent) throws Exception {
        try {
            WebArchive newWar = genericCreateArchiveWithPems(sourceWarName, baseWarName, classList);
            newWar.add(new StringAsset(fileContent), mpConfig);
            return newWar;
        } catch (Exception e) {
            Log.error(thisClass, "genericCreateArchive", e);
            throw e;
        }
    }

    public WebArchive addPemFilesForAppsToWar(String warName, WebArchive war) throws Exception {
        war.add(new FileAsset(new File("publish/shared/securityKeys/bad_key.pem")), "/WEB-INF/classes/bad_key.pem");
        war.add(new FileAsset(new File("publish/shared/securityKeys/rsa_key_withCert.pem")), "/WEB-INF/classes/rsa_key_withCert.pem");
        war.add(new FileAsset(new File("publish/shared/securityKeys/rsa_key.pem")), "/WEB-INF/classes/rsa_key.pem");
        return war;
    }

    /***************************************************/
    /**
     * Create a new war with "standard" content for tests using these utils. Add the extra jsps that some apps need.
     * Finally add the classes that are specific to this war (they come from the classList passed in)
     *
     * @param baseWarName - the base name of the war
     * @param classList - the list of classes specific to this war
     * @return - the generated war
     * @throws Exception
     */
    public WebArchive genericCreateArchiveWithJsps(String baseWarName, List<String> classList) throws Exception {
        try {
            String warName = getWarName(baseWarName);
            WebArchive newWar = genericCreateArchiveWithoutJsps(warName, classList);
            addDefaultJspsForAppsToWar(warName, newWar);
            return newWar;
        } catch (Exception e) {
            Log.error(thisClass, "genericCreateArchive", e);
            throw e;
        }
    }

    /**
     * Create a new war with "standard" content for tests using these utils.
     * Finally add the classes that are specific to this war (they come from the classList passed in)
     *
     * @param baseWarName - the base name of the war
     * @param classList - the list of classes specific to this war
     * @return - the generated war
     * @throws Exception
     */
    public WebArchive genericCreateArchiveWithoutJsps(String baseWarName, List<String> classList) throws Exception {
        try {
            String warName = getWarName(baseWarName);
            WebArchive newWar = ShrinkWrap.create(WebArchive.class, warName);
            addDefaultFileAssetsForAppsToWar(warName, newWar);
            for (String theClass : classList) {
                newWar.addClass(theClass);
            }
            return newWar;
        } catch (Exception e) {
            Log.error(thisClass, "genericCreateArchive", e);
            throw e;
        }
    }

    /**
     * build the war name (some methods may sometimes be passed the already built war name,
     * other times, they may only get the base name. Put the logic to set the war name
     * properly in one place
     *
     * @param baseWarName - the warname passed to the caller - add .war if it's not already there
     * @return - either baseWarName or baseWarName.war depending on what was passed in.
     */
    protected String getWarName(String baseWarName) {
        if (baseWarName.endsWith(".war")) {
            return baseWarName;
        } else {
            return baseWarName + ".war";
        }
    }

    /**
     * All of the test apps following the same naming convention. We can build the class names
     *
     * @param app1 - test app 1
     * @param app2 - test app 2
     * @param app3 - test app 3 if it exists
     * @return
     * @throws Exception
     */
    public List<String> createAppClassListBuildAppNames(String app1, String app2, String app3) throws Exception {

        List<String> classList = createAppClassListBuildAppNames(app1, app2);
        classList.add("com.ibm.ws.jaxrs.fat.microProfileApp." + app2 + ".MicroProfileApp" + app3);
        return classList;

    }

    public List<String> createAppClassListBuildAppNames(String app1, String app2) throws Exception {

        List<String> classList = new ArrayList<String>();
        classList.add("com.ibm.ws.jaxrs.fat.microProfileApp." + app1);
        classList.add("com.ibm.ws.jaxrs.fat.microProfileApp." + app2 + ".MicroProfileApp");
        return classList;

    }

    public List<String> createAppClassList(String... apps) throws Exception {

        List<String> classList = new ArrayList<String>();
        for (String app : apps) {
            classList.add(app);
        }
        return classList;

    }

    public WebArchive addDefaultFileAssetsForAppsToWar(String warName, WebArchive war) throws Exception {
        war.add(new FileAsset(new File("lib/com/ibm/ws/security/fat/common/mp/jwt/CommonMicroProfileApp.class")),
                "/WEB-INF/classes/com/ibm/ws/security/fat/common/mp/jwt/CommonMicroProfileApp.class");
        war.add(new FileAsset(new File("lib/com/ibm/ws/security/fat/common/mp/jwt/MPJwtFatConstants.class")),
                "/WEB-INF/classes/com/ibm/ws/security/fat/common/mp/jwt/MPJwtFatConstants.class");
        war.add(new FileAsset(new File("test-applications/" + warName + "/resources/WEB-INF/web.xml")), "/WEB-INF/web.xml");
        war.add(new FileAsset(new File("test-applications/" + warName + "/resources/META-INF/permissions.xml")), "/META-INF/permissions.xml");
        return war;
    }

    public WebArchive addDefaultJspsForAppsToWar(String warName, WebArchive war) throws Exception {
        war.add(new FileAsset(new File("test-applications/" + warName + "/resources/login.jsp")), "/login.jsp");
        war.add(new FileAsset(new File("test-applications/" + warName + "/resources/loginError.jsp")), "/loginError.jsp");
        return war;
    }

}
