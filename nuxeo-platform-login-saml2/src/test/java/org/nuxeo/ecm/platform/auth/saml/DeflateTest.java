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

    String response = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6%0D%0AU0FNTDoyLjA6cHJvdG9jb2wiIERlc3RpbmF0aW9uPSJodHRwczovL2NvbGlicmkt%0D%0AYi1kZXYuc2lpMjQucG9sZS1lbXBsb2kuaW50cmE6OTY4MC9udXhlby9ueHN0YXJ0%0D%0AdXAuZmFjZXMiIElEPSJpZC0tU2J0dXhmN3ZpbnhBTG82N3pCQmU3S2daVG8tIiBJ%0D%0AblJlc3BvbnNlVG89ImI3Mzk1YzZmLWQwOWEtNGNiYS05OWRmLTJjMTI4MzJjNTY0%0D%0ANCIgSXNzdWVJbnN0YW50PSIyMDE1LTA1LTA0VDE0OjAxOjExWiIgVmVyc2lvbj0i%0D%0AMi4wIj48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRj%0D%0AOlNBTUw6Mi4wOmFzc2VydGlvbiIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6%0D%0AU0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPklEUF9QT0xFLUVNUExPSV9J%0D%0AUUw8L3NhbWw6SXNzdWVyPjxzYW1scDpTdGF0dXM%2BPHNhbWxwOlN0YXR1c0NvZGUg%0D%0AVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2Vz%0D%0AcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiB4bWxuczpzYW1sPSJ1%0D%0Acm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iaWQtZFlO%0D%0ARWh0MjdjTzg2YkhxSFFud3VSVW55R1NnLSIgSXNzdWVJbnN0YW50PSIyMDE1LTA1%0D%0ALTA0VDE0OjAxOjExWiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0%0D%0APSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRp%0D%0AdHkiPklEUF9QT0xFLUVNUExPSV9JUUw8L3NhbWw6SXNzdWVyPjxkc2lnOlNpZ25h%0D%0AdHVyZSB4bWxuczpkc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRz%0D%0AaWcjIj48ZHNpZzpTaWduZWRJbmZvPjxkc2lnOkNhbm9uaWNhbGl6YXRpb25NZXRo%0D%0Ab2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMt%0D%0AYzE0biMiLz48ZHNpZzpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8v%0D%0Ad3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48ZHNpZzpSZWZl%0D%0AcmVuY2UgVVJJPSIjaWQtZFlORWh0MjdjTzg2YkhxSFFud3VSVW55R1NnLSI%2BPGRz%0D%0AaWc6VHJhbnNmb3Jtcz48ZHNpZzpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8v%0D%0Ad3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIv%0D%0APjxkc2lnOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIw%0D%0AMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHNpZzpUcmFuc2Zvcm1zPjxkc2lnOkRp%0D%0AZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkv%0D%0AeG1sZHNpZyNzaGExIi8%2BPGRzaWc6RGlnZXN0VmFsdWU%2BS2h6WS92VzB5clhzTVVh%0D%0AM2hTbno0a1VHd2tFPTwvZHNpZzpEaWdlc3RWYWx1ZT48L2RzaWc6UmVmZXJlbmNl%0D%0APjwvZHNpZzpTaWduZWRJbmZvPjxkc2lnOlNpZ25hdHVyZVZhbHVlPmk2WUpOb0Rh%0D%0Ad28xS1pEK3YzYXZCeDVyd3VpZ1llWnQ1djZYY1F4NHdkazNicmwxQTVlbk5YTzZQ%0D%0AOW14alBOWjJZQmVoOXl3V0VVWkRGWFJHeng1VXkvMnZXdDVESVlCbHlyakJjTG1E%0D%0ARkV5Z1czcFJjTEhJNTVqVkwrRTZLVVFROE1UU3R3N21VQVFNa2RNUkR6QjR3N3J4%0D%0AdGZjK1A1ZkxweFhobEtqcDl2SjVhRU5ZcVFWdWg5enRzc1c0QTNHVjdYVGljYXVr%0D%0AOWh3K3gvY3B2U0tDM3F1ejI4cnp2SnFKV0p4OE1GZkZzVndYbFJ1MnZwaXZEVlRO%0D%0AMzNLSUtXRDBwM2NyZkdvYXJKVFlZak9Ed1lISUhNSldWczNnWmVQVnZxSFYvMWtz%0D%0AK0haRXQ0d0VHZmVjRjg3dk1GSkxYejRYeGVTZG8rVnJHeXlVZHFzeUdLeG02dz09%0D%0APC9kc2lnOlNpZ25hdHVyZVZhbHVlPjwvZHNpZzpTaWduYXR1cmU%2BPHNhbWw6U3Vi%0D%0AamVjdD48c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FN%0D%0ATDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiIE5hbWVRdWFsaWZpZXI9IklE%0D%0AUF9QT0xFLUVNUExPSV9JUUwiIFNQTmFtZVF1YWxpZmllcj0iU1BfTlVYRU9fVFUi%0D%0APmlkLVpYdllyWTMxS21VZGVxTWdiWWpiT21sMnBwVS08L3NhbWw6TmFtZUlEPjxz%0D%0AYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6%0D%0AdGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9u%0D%0ARGF0YSBJblJlc3BvbnNlVG89ImI3Mzk1YzZmLWQwOWEtNGNiYS05OWRmLTJjMTI4%0D%0AMzJjNTY0NCIgTm90T25PckFmdGVyPSIyMDE1LTA1LTA0VDE0OjA2OjExWiIgUmVj%0D%0AaXBpZW50PSJodHRwczovL2NvbGlicmktYi1kZXYuc2lpMjQucG9sZS1lbXBsb2ku%0D%0AaW50cmE6OTY4MC9udXhlby9ueHN0YXJ0dXAuZmFjZXMiLz48L3NhbWw6U3ViamVj%0D%0AdENvbmZpcm1hdGlvbj48L3NhbWw6U3ViamVjdD48c2FtbDpDb25kaXRpb25zIE5v%0D%0AdEJlZm9yZT0iMjAxNS0wNS0wNFQxNDowMToxMVoiIE5vdE9uT3JBZnRlcj0iMjAx%0D%0ANS0wNS0wNFQxNDowNjoxMVoiPjxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24%2BPHNh%0D%0AbWw6QXVkaWVuY2U%2BU1BfTlVYRU9fVFU8L3NhbWw6QXVkaWVuY2U%2BPC9zYW1sOkF1%0D%0AZGllbmNlUmVzdHJpY3Rpb24%2BPC9zYW1sOkNvbmRpdGlvbnM%2BPHNhbWw6QXV0aG5T%0D%0AdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE1LTA1LTA0VDEzOjUwOjAzWiIgU2Vz%0D%0Ac2lvbkluZGV4PSJpZC1aTkRoeVJKOURlUjFFS1A4YlpYT3JmN0EzNTAtIiBTZXNz%0D%0AaW9uTm90T25PckFmdGVyPSIyMDE1LTA1LTA0VDE1OjAxOjExWiI%2BPHNhbWw6QXV0%0D%0AaG5Db250ZXh0PjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpu%0D%0AYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJh%0D%0AbnNwb3J0PC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDpBdXRobkNv%0D%0AbnRleHQ%2BPC9zYW1sOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24%2BPC9z%0D%0AYW1scDpSZXNwb25zZT4%3D%0D%0A";

    @Test
    public void decompress() throws Exception {

        
    }
}
