/*******************************************************************************
 * Copyright (c) 2011, 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 * 
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.logs;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/TraceURL")
public class TraceServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String id = req.getParameter("id");
        if (id == null) {
            id = "";
        } else {
            id = " " + id;
        }

        //Set up the logger for this class
        String loggerName = "com.ibm.logs.TraceServlet";
        java.util.logging.Logger logger = java.util.logging.Logger.getLogger(loggerName);
        //Log the trace message
        logger.logp(java.util.logging.Level.FINE, loggerName, "Method.Info", "TEST JUL TRACE" + id);

        PrintWriter out;
        res.setContentType("text/html");
        out = res.getWriter();
        out.println("<HTML><HEAD><TITLE>Trace Servlet</TITLE></HEAD><BODY BGCOLOR=\"#FFFFEE\">Trace Servlet</BODY></HTML>");

    }
}
