package org.nuxeo.ecm.platform.auth.saml;

import static junit.framework.Assert.assertEquals;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.nuxeo.ecm.platform.auth.saml.utils.DeflateUtils;

public class DeflateTest {
    
    String xml = "<saml2p:AuthnRequest AssertionConsumerServiceURL=\"http://localhost:8080/nuxeo/nxstartup.faces\" ID=\"80c08989-5ca6-429b-9b42-b7cd505eed8f\" IssueInstant=\"2015-04-28T16:09:09.039Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">TTTTTTTTTTTTOOOOOOO</saml2:Issuer><saml2p:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"/><saml2p:RequestedAuthnContext Comparison=\"exact\"><saml2:AuthnContextClassRef xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2p:RequestedAuthnContext></saml2p:AuthnRequest>";

    String result = "nVLLTsMwEPyVyPckbmghsZpKpQhRiUfUBg7cXGdDLSV28DoQ/h43fZAD9MDKkqXd8czOrqfI6ypq2Ly1W7WC9xbQenNEMFZqtdAK2xrMGsyHFPC8uk/J1tqGhWGlBa+2Gi2LaUxD1XagQ9Wh5ca2TVByAUi85U1KYiponMSJPxH80h9HycZPNuPI31yJYkInAEVcOiRiC0vl3iubkoiOJj4d+1Gcjy4ZTdwJ6EXySrzMaKuFrq6lKqR6S0lrFNMcJTLFa0BmBVvPH+5ZFFC22YOQ3eV55mdP65x4L2DQWXMaASVeV1cK2X4I57magzCZTXs46zs2Q4bzBPw4VTLLB/G0j2k4ZD1oNOzR0SxvMl1J8eXdalNz+7fKKBj1GVn4ZQ9lrcIGhCwlFCQ8kR72DEW/dbdkC531FrpuuJG4mw10XNiT0yFsUTkfKyj/5fssTDCx43bpzF2f2hS7XYNwfeaGOyPa2OOUfutodij+4e+nPPzrs28=";

    @Test
    public void compress() throws Exception {

        System.out.println(">>>>>>>>>>>> SAML request");
        System.out.println("---------- XML -----------");
        System.out.println(this.xml);
        System.out.println("--------- DEFLATE --------");
        byte[] bytes;
        bytes = this.xml.getBytes("UTF-8");
        byte[] compress = DeflateUtils.compress(bytes);
        System.out.println(new String(compress, "UTF-8"));
        System.out.println("---------- BASE 64 --------");
        String encodeBase64String = Base64.encodeBase64String(compress);
        System.out.println(encodeBase64String);
        System.out.println("<<<<<<<<<<<< SAML request");
        
        System.out.println("Original: " + (bytes.length) + " b");
        System.out.println("Compressed: " + (compress.length) + " b");
        
        assertEquals(this.result,encodeBase64String);
        
    }
    
    @Test
    public void decompress() throws Exception {
        

    }
}
