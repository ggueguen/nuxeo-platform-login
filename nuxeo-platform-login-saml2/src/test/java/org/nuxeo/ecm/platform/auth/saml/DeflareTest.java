package org.nuxeo.ecm.platform.auth.saml;

import org.junit.Test;
import org.nuxeo.ecm.platform.auth.saml.utils.DeflateUtils;

public class DeflareTest {

    private static String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<saml2p:AuthnRequest"
                    + "      AssertionConsumerServiceURL=\"https://colibri-b-dev.sii24.pole-emploi.intra:9680/nuxeo/nxstartup.faces\""
                    + "      ID=\"954cbd30-6654-4482-a79e-65bbeaadda0d\" IssueInstant=\"2015-04-15T10:19:20.236Z\""
                    + "      ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""
                    + "      Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                    + "      <saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://colibri-b-dev.sii24.pole-emploi.intra:9680/nuxeo/</saml2:Issuer>"
                    + "      <saml2p:NameIDPolicy"
                    + "            Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" />"
                    + "      <saml2p:RequestedAuthnContext Comparison=\"exact\">"
                    + "            <saml2:AuthnContextClassRef xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>"
                    + "      </saml2p:RequestedAuthnContext>" + "</saml2p:AuthnRequest>";
    
    
    @Test
    public void compress() throws Exception {
        
        byte[] data = xml.toString().getBytes();

        byte[] output = DeflateUtils.compress(data);

        System.out.println("Original: " + (data.length) + " b");
        System.out.println("Compressed: " + (output.length) + " b");

        output.toString();
    }

    @Test
    public void decompress() throws Exception {

        byte[] data = xml.toString().getBytes();

        byte[] output = DeflateUtils.compress(data);

        System.out.println("Original: " + (data.length) + " b");
        System.out.println("Compressed: " + (output.length) + " b");
    }
}
