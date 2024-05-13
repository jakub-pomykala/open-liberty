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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

/**
 * Class used for creating string representing JSON formatted strings to POST to the cve-serice container.
 */
public class GetCVEs {

    private static String previousYearEndVersion;
    private static String previousYearStartVersion;
    private static String currentYearEndVersion;
    private static String currentYearStartVersion;
    private static String nextYearEndVersion;
    private static String nextYearStartVersion;

    /**
     * Populate all the different version used in the getCVE...() methods.
     */
    public static void setVersion() {

        String end = ".0.0.15";
        String start = ".0.0.1";

        DateFormat df = new SimpleDateFormat("yy");
        String currentYear = df.format(Calendar.getInstance().getTime());
        String nextYear = String.valueOf(1 + Integer.valueOf(currentYear));
        String previousYear = String.valueOf(Integer.valueOf(currentYear) - 1);

        currentYearEndVersion = new StringBuilder(currentYear).append(end).toString();
        currentYearStartVersion = new StringBuilder(currentYear).append(start).toString();

        nextYearEndVersion = new StringBuilder(nextYear).append(end).toString();
        nextYearStartVersion = new StringBuilder(nextYear).append(start).toString();

        previousYearEndVersion = new StringBuilder(previousYear).append(end).toString();
        previousYearStartVersion = new StringBuilder(previousYear).append(start).toString();
    }

    /**
     * Generating a string representing a CVE with an empty feature (Open Liberty CVE).
     *
     * @return CVE as a string
     */
    public static String getCVE1() {
        String cve1 = "{\n"
                      + "  \"bulletinModificationDate\": \"2024-05-16T13:54:11.123Z[UTC]\",\n"
                      + "  \"id\": \"cve000\",\n"
                      + "  \"url\": \"www.example.com/cves/cve000\",\n"
                      + "  \"affectedProducts\": [\n"
                      + "    {\n"
                      + "      \"ifixes\": [],\n"
                      + "      \"libertyFeatures\": [\n"
                      + "        \"\"\n"
                      + "      ],\n"
                      + "      \"operatingSystems\": [\n"
                      + "        \"Mac OS X\",\n"
                      + "        \"Windows\",\n"
                      + "        \"AIX\",\n"
                      + "        \"z/OS\",\n"
                      + "        \"IBM i\",\n"
                      + "        \"Linux\"\n"
                      + "      ],\n"
                      + "      \"productEdition\": \"Open\",\n"
                      + "      \"productName\": \"Liberty\",\n"
                      + "       \"versions\": [\n"
                      + "        {\n"
                      + "          \"endVersion\": \"" + currentYearEndVersion + "\",\n"
                      + "          \"startVersion\": \"" + currentYearStartVersion + "\"\n"
                      + "        }, \n"
                      + "        {\n"
                      + "          \"endVersion\": \"" + nextYearEndVersion + "\",\n"
                      + "          \"startVersion\": \"" + nextYearStartVersion + "\"\n"
                      + "        }\n"
                      + "      ]\n"
                      + "    }\n"
                      + "  ]\n"
                      + "}";

        return cve1;
    }

    /**
     * Generating a string representing a CVE affecting a single feature (Servlet).
     *
     * @return CVE as a string
     */
    public static String getCVE2() {
        String cve2 = "{\n"
                      + "  \"bulletinModificationDate\": \"2024-05-16T13:54:11.123Z[UTC]\",\n"
                      + "  \"id\": \"cve001\",\n"
                      + "  \"url\": \"www.example.com/cves/cve001\",\n"
                      + "  \"affectedProducts\": [\n"
                      + "    {\n"
                      + "      \"ifixes\": [],\n"
                      + "      \"libertyFeatures\": [\n"
                      + "        \"servlet-3.1\",\n"
                      + "        \"servlet-4.0\",\n"
                      + "        \"servlet-5.0\",\n"
                      + "        \"servlet-6.0\"\n"
                      + "      ],\n"
                      + "      \"operatingSystems\": [\n"
                      + "        \"Mac OS X\",\n"
                      + "        \"Windows\",\n"
                      + "        \"AIX\",\n"
                      + "        \"z/OS\",\n"
                      + "        \"IBM i\",\n"
                      + "        \"Linux\"\n"
                      + "      ],\n"
                      + "      \"productEdition\": \"Open\",\n"
                      + "      \"productName\": \"Liberty\",\n"
                      + "       \"versions\": [\n"
                      + "        {\n"
                      + "          \"endVersion\": \"" + currentYearEndVersion + "\",\n"
                      + "          \"startVersion\": \"" + currentYearStartVersion + "\"\n"
                      + "        }, \n"
                      + "        {\n"
                      + "          \"endVersion\": \"" + nextYearEndVersion + "\",\n"
                      + "          \"startVersion\": \"" + nextYearStartVersion + "\"\n"
                      + "        }\n"
                      + "      ]\n"
                      + "    }\n"
                      + "  ]\n"
                      + "}";

        return cve2;
    }

    /**
     * Generating a string representing a CVE which has the same bulletin as CVE from getCVE2().
     *
     * @return CVE as a string
     */
    public static String getCVE3() {
        String cve3 = "{\n"
                      + "  \"bulletinModificationDate\": \"2024-05-16T13:54:11.123Z[UTC]\",\n"
                      + "  \"id\": \"cve002\",\n"
                      + "  \"url\": \"www.example.com/cves/cve001\",\n"
                      + "  \"affectedProducts\": [\n"
                      + "    {\n"
                      + "      \"ifixes\": [],\n"
                      + "      \"libertyFeatures\": [\n"
                      + "        \"transportSecurity-1.0\"\n"
                      + "      ],\n"
                      + "      \"operatingSystems\": [\n"
                      + "        \"Mac OS X\",\n"
                      + "        \"Windows\",\n"
                      + "        \"AIX\",\n"
                      + "        \"z/OS\",\n"
                      + "        \"IBM i\",\n"
                      + "        \"Linux\"\n"
                      + "      ],\n"
                      + "      \"productEdition\": \"Open\",\n"
                      + "      \"productName\": \"Liberty\",\n"
                      + "       \"versions\": [\n"
                      + "        {\n"
                      + "          \"endVersion\": \"" + currentYearEndVersion + "\",\n"
                      + "          \"startVersion\": \"" + currentYearStartVersion + "\"\n"
                      + "        }, \n"
                      + "        {\n"
                      + "          \"endVersion\": \"" + nextYearEndVersion + "\",\n"
                      + "          \"startVersion\": \"" + nextYearStartVersion + "\"\n"
                      + "        }\n"
                      + "      ]\n"
                      + "    }\n"
                      + "  ]\n"
                      + "}";
        return cve3;
    }

    /**
     * Generating a string representing a CVE for Traditional WebSphere.
     *
     * @return CVE as a string
     */
    public static String getCVE4() {
        String cve4 = "{\n"
                      + "  \"bulletinModificationDate\": \"2024-05-16T13:54:11.123Z[UTC]\",\n"
                      + "  \"id\": \"cve003\",\n"
                      + "  \"url\": \"www.example.com/cves/cve003\",\n"
                      + "  \"affectedProducts\": [\n"
                      + "    {\n"
                      + "      \"ifixes\": [],\n"
                      + "      \"libertyFeatures\": [\n"
                      + "        \"transportSecurity-1.0\"\n"
                      + "      ],\n"
                      + "      \"operatingSystems\": [\n"
                      + "        \"Mac OS X\",\n"
                      + "        \"Windows\",\n"
                      + "        \"AIX\",\n"
                      + "        \"z/OS\",\n"
                      + "        \"IBM i\",\n"
                      + "        \"Linux\"\n"
                      + "      ],\n"
                      + "      \"productName\": \"Traditional\",\n"
                      + "       \"versions\": [\n"
                      + "        {\n"
                      + "          \"endVersion\": \"8.5.5.12\",\n"
                      + "          \"startVersion\": \"8.5.0.0\"\n"
                      + "        }\n"
                      + "      ]\n"
                      + "    }\n"
                      + "  ]\n"
                      + "}";

        return cve4;
    }

    /**
     * Generating a string representing a CVE for a Open Liberty releases in the previous year.
     *
     * @return CVE as a string
     */
    public static String getCVE5() {
        String cve5 = "{\n"
                      + "  \"bulletinModificationDate\": \"2024-05-16T13:54:11.123Z[UTC]\",\n"
                      + "  \"id\": \"cve004\",\n"
                      + "  \"url\": \"www.example.com/cves/cve004\",\n"
                      + "  \"affectedProducts\": [\n"
                      + "    {\n"
                      + "      \"ifixes\": [],\n"
                      + "      \"libertyFeatures\": [\n"
                      + "        \"servlet-6.0\",\n"
                      + "        \"transportSecurity-1.0\"\n"
                      + "      ],\n"
                      + "      \"operatingSystems\": [\n"
                      + "        \"Mac OS X\",\n"
                      + "        \"Windows\",\n"
                      + "        \"AIX\",\n"
                      + "        \"z/OS\",\n"
                      + "        \"IBM i\",\n"
                      + "        \"Linux\"\n"
                      + "      ],\n"
                      + "      \"productEdition\": \"Open\",\n"
                      + "      \"productName\": \"Liberty\",\n"
                      + "       \"versions\": [\n"
                      + "        {\n"
                      + "          \"endVersion\": \"" + previousYearEndVersion + "\",\n"
                      + "          \"startVersion\": \"" + previousYearStartVersion + "\"\n"
                      + "        }\n"
                      + "      ]\n"
                      + "    }\n"
                      + "  ]\n"
                      + "}";

        return cve5;
    }

}
