package org.nuxeo.ecm.platform.auth.saml.decoding;

import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.xml.parse.ParserPool;

public class HTTPPostDecoderRP extends HTTPPostDecoder {
    
    public HTTPPostDecoderRP() {
        super();
        this.setURIComparator(new SchemaLessURLComparator());
    }
    
    public HTTPPostDecoderRP(ParserPool pool) {
        super(pool);
        this.setURIComparator(new SchemaLessURLComparator());
    }
    
}
