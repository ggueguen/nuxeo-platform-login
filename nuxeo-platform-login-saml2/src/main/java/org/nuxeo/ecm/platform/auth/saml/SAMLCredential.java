/*
 * (C) Copyright 2014 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Nelson Silva <nelson.silva@inevo.pt>
 */

package org.nuxeo.ecm.platform.auth.saml;

import java.io.Serializable;
import java.util.List;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;

/**
 *
 * @since 6.0
 */
public class SAMLCredential {
    private final NameID nameID;
    private final List<String> sessionIndexes;
    private String remoteEntityID;
    private String relayState;
    private List<Attribute> attributes;
    private String localEntityID;
    private Serializable additionalData;
    
    public SAMLCredential(NameID nameID, List<String> sessionIndexes) {
        this.nameID = nameID;
        this.sessionIndexes = sessionIndexes;
    }
    
    public SAMLCredential(NameID nameID, List<String> sessionIndexes, String remoteEntityID, String relayState, List<Attribute> attributes, String localEntityID, Serializable additionalData) {
        this.nameID = nameID;
        this.sessionIndexes = sessionIndexes;
        this.remoteEntityID = remoteEntityID;
        this.relayState = relayState;
        this.attributes = attributes;
        this.localEntityID = localEntityID;
        this.additionalData = additionalData;
    }
    
    @Override
    public String toString() {
        return "SAMLCredential [nameID=" + this.nameID + ", sessionIndexes=" + this.sessionIndexes + ", remoteEntityID=" + this.remoteEntityID
                        + ", relayState=" + this.relayState + ", attributes=" + this.attributes + ", localEntityID=" + this.localEntityID
                        + ", additionalData=" + this.additionalData + "]";
    }
    
    public NameID getNameID() {
        return this.nameID;
    }
    
    public List<String> getSessionIndexes() {
        return this.sessionIndexes;
    }
    
    public String getRemoteEntityID() {
        return this.remoteEntityID;
    }
    
    public Attribute getAttributeByName(String name) {
        for (Attribute attribute : this.getAttributes()) {
            if (name.equalsIgnoreCase(attribute.getName())) {
                return attribute;
            }
        }
        return null;
    }
    
    public List<Attribute> getAttributes() {
        return this.attributes;
    }
    
    public String getRelayState() {
        return this.relayState;
    }
    
    public String getLocalEntityID() {
        return this.localEntityID;
    }
    
    public Serializable getAdditionalData() {
        return this.additionalData;
    }
}
