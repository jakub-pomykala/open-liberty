/*******************************************************************************
 * Copyright (c) 2021 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 * 
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.sip.stack.transport.sip.netty;

import com.ibm.ws.sip.stack.util.SipStackUtil;
import io.netty.channel.Channel;

/**
 * represents an outbound tls connection
 * 
 * @author ran
 */
public class SipTlsOutboundConnLink extends SipOutboundConnLink
{
	/**
	 * constructor for outbound connections
	 * @param peerHost remote host address in dotted form
	 * @param peerPort remote port number
	 * @param channel channel that created this connection
	 */
	public SipTlsOutboundConnLink(String peerHost, int peerPort, SipInboundChannel sipInboundChannel, Channel channel) {
		super(peerHost, peerPort, sipInboundChannel, channel, true);
	}
	
	// ----------------------------
	// SIPConnection implementation
	// ----------------------------

	/**
	 * @see com.ibm.ws.sip.stack.transaction.transport.connections.SIPConnection#getTransport()
	 */
	public String getTransport() {
		return SipStackUtil.TLS_TRANSPORT;
	}

	/**
	 * @see com.ibm.ws.sip.stack.transaction.transport.connections.SIPConnection#isReliable()
	 */
	public boolean isReliable() {
		return true;
	}

	/**
	 * @see com.ibm.ws.sip.stack.transaction.transport.connections.SIPConnection#isSecure()
	 */
	public boolean isSecure() {
		return true;
	}

	/**
	 * @see com.ibm.ws.sip.stack.transaction.transport.connections.SIPConnection#getPathMTU()
	 */
	public int getPathMTU() {
		return -1;
	}
}
