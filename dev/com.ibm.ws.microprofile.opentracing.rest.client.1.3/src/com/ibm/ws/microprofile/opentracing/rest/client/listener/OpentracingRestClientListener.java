/*******************************************************************************
 * Copyright (c) 2019, 2020 IBM Corporation and others.
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
package com.ibm.ws.microprofile.opentracing.rest.client.listener;

import org.eclipse.microprofile.opentracing.Traced;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.spi.RestClientListener;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;

/**
 *
 */
public class OpentracingRestClientListener implements RestClientListener {

    private static final TraceComponent tc = Tr.register(OpentracingRestClientListener.class);

    /** {@inheritDoc} */
    @Override
    public void onNewClient(Class<?> serviceInterface, RestClientBuilder builder) {
        Traced traced = serviceInterface.getAnnotation(Traced.class);
        if (traced != null && !traced.value()) {
            // tracing is disabled
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "@Traced(false) specified on service interface");
            }
            return;
        }
        builder.register(OpentracingRestClientFilter.class);
    }

}
