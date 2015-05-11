package org.nuxeo.ecm.platform.auth.saml.decoding;

import org.opensaml.common.binding.decoding.URIComparator;
import org.opensaml.util.SimpleURLCanonicalizer;

public class SchemaLessURLComparator implements URIComparator {
    private boolean caseInsensitive;
    
    @Override
    public boolean compare(String uri1, String uri2) {
        if (uri1 == null) {
            return (uri2 == null);
        }
        if (uri2 == null) {
            return (uri1 == null);
        }
        String uri1Canon = SimpleURLCanonicalizer.canonicalize(uri1).substring(uri1.indexOf("://"));
        String uri2Canon = SimpleURLCanonicalizer.canonicalize(uri2).substring(uri2.indexOf("://"));
        
        if (this.isCaseInsensitive()) {
            return uri1Canon.equalsIgnoreCase(uri2Canon);
        }
        return uri1Canon.equals(uri2Canon);
    }
    
    public boolean isCaseInsensitive() {
        return this.caseInsensitive;
    }
    
    public void setCaseInsensitive(boolean flag) {
        this.caseInsensitive = flag;
    }
}