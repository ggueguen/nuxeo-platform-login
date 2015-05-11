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

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static org.mockito.Matchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.test.CoreFeature;
import org.nuxeo.ecm.core.test.DefaultRepositoryInit;
import org.nuxeo.ecm.core.test.annotations.Granularity;
import org.nuxeo.ecm.core.test.annotations.RepositoryConfig;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.auth.saml.binding.HTTPRedirectBinding;
import org.nuxeo.ecm.platform.auth.saml.utils.DeflateUtils;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.runtime.test.runner.LocalDeploy;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.collect.ImmutableMap;
import com.google.inject.Inject;

@RunWith(FeaturesRunner.class)
@Features(CoreFeature.class)
@RepositoryConfig(init = DefaultRepositoryInit.class,
cleanup = Granularity.METHOD)
@Deploy({ "org.nuxeo.ecm.directory.api",
    "org.nuxeo.ecm.directory",
    "org.nuxeo.ecm.directory.sql",
    "org.nuxeo.ecm.directory.types.contrib",
    "org.nuxeo.ecm.platform.usermanager",
    "org.nuxeo.ecm.platform.web.common",
"org.nuxeo.ecm.platform.login.saml2" })
@LocalDeploy("org.nuxeo.ecm.platform.auth.saml:OSGI-INF/test-sql-directory.xml")
public class SAMLAuthenticatorTest {
    
    @Inject
    protected UserManager userManager;
    
    private DocumentModel user;
    
    private SAMLAuthenticationProvider samlAuth;
    
    @Before
    public void doBefore() throws URISyntaxException {
        this.samlAuth = new SAMLAuthenticationProvider();
        
        String metadata = this.getClass().getResource("/idp-meta.xml").toURI().getPath();
        
        Map<String, String> params = new ImmutableMap.Builder<String, String>() //
                        .put("metadata", metadata)
                        .build();
        
        this.samlAuth.initPlugin(params);
        
        this.user = this.userManager.getUserModel("user");
        
        if (this.user == null) {
            this.user = this.userManager.getBareUserModel();
            this.user.setPropertyValue(this.userManager.getUserIdField(), "user");
            this.user.setPropertyValue(this.userManager.getUserEmailField(), "user@dummy");
            this.user = this.userManager.createUser(this.user);
        }
    }
    
    @Test
    public void testLoginPrompt() throws Exception {
        
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        this.samlAuth.handleLoginPrompt(req, resp, "/");
        
        verify(resp).sendRedirect(startsWith("http://dummy/SSORedirect"));
    }
    
    @Test
    public void testAuthRequest() throws Exception {
        
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        
        String loginURL = this.samlAuth.getSSOUrl(req, resp);
        String query = URI.create(loginURL).getQuery();
        
        assertTrue(loginURL.startsWith("http://dummy/SSORedirect"));
        assertTrue(query.startsWith(HTTPRedirectBinding.SAML_REQUEST));
        
        String samlRequest = query.replaceFirst(HTTPRedirectBinding.SAML_REQUEST + "=", "");
        
        SAMLObject message = this.decodeMessage(samlRequest);
        
        // Validate type
        assertTrue(message instanceof AuthnRequest);
        
        AuthnRequest auth = (AuthnRequest) message;
        assertEquals(SAMLVersion.VERSION_20, auth.getVersion());
        assertNotNull(auth.getID());
        assertEquals(SAMLConstants.SAML2_POST_BINDING_URI,
                        auth.getProtocolBinding());
    }
    
    @Test
    public void testRetrieveIdentity() throws Exception {
        
        HttpServletRequest req = this.getMockRequest("/saml-response.xml", "POST",
                        "http://localhost:8080/login", "text/html");
        
        HttpServletResponse resp = mock(HttpServletResponse.class);
        
        UserIdentificationInfo info = this.samlAuth.handleRetrieveIdentity(req, resp);
        assertEquals(info.getUserName(), this.user.getId());
        
        final ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        
        verify(resp).addCookie(captor.capture());
        
        final List<Cookie> cookies = captor.getAllValues();
        
        assertTrue(!cookies.isEmpty());
    }
    
    @Test
    public void testRetrieveIdentityPE() throws Exception {
        
        String metadata = this.getClass().getResource("/metadata_idpiql.xml").toURI().getPath();
        Map<String, String> params = new ImmutableMap.Builder<String, String>() //
                        .put("metadata", metadata).build();
        
        this.samlAuth.initPlugin(params);

        HttpServletRequest req = this.getMockRequest("/saml-response-pe.xml", "POST",
                        "http://colibri-b-dev.sii24.pole-emploi.intra:9680/nuxeo/nxstartup.faces",
                        "text/html");
        
        HttpServletResponse resp = mock(HttpServletResponse.class);
        
        UserIdentificationInfo info = this.samlAuth.handleRetrieveIdentity(req, resp);
        assertEquals(info.getUserName(), this.user.getId());
        
        final ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        
        verify(resp).addCookie(captor.capture());
        
        final List<Cookie> cookies = captor.getAllValues();
        
        assertTrue(!cookies.isEmpty());
    }
    
    @Test
    public void testLogoutRequest() throws Exception {
        
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        Cookie[] cookies = new Cookie[] {
                        new Cookie(SAMLAuthenticationProvider.SAML_SESSION_KEY,
                                        "sessionId|user@dummy|format")
        };
        when(req.getCookies()).thenReturn(cookies);
        String logoutURL = this.samlAuth.getSLOUrl(req, resp);
        
        assertTrue(logoutURL.startsWith("http://dummy/SLORedirect"));
    }
    
    protected HttpServletRequest getMockRequest(String messageFile,
        String method, String url, String contentType) throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        URL urlP = new URL(url);
        File file = new File(this.getClass().getResource(messageFile).toURI());
        String message = Base64.encodeFromFile(file.getAbsolutePath());
        
        // String message = URLDecoder
        // .decode("PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6%0D%0AU0FNTDoyLjA6cHJvdG9jb2wiIERlc3RpbmF0aW9uPSJodHRwczovL2NvbGlicmkt%0D%0AYi1kZXYuc2lpMjQucG9sZS1lbXBsb2kuaW50cmE6OTY4MC9udXhlby9ueHN0YXJ0%0D%0AdXAuZmFjZXMiIElEPSJpZC0tU2J0dXhmN3ZpbnhBTG82N3pCQmU3S2daVG8tIiBJ%0D%0AblJlc3BvbnNlVG89ImI3Mzk1YzZmLWQwOWEtNGNiYS05OWRmLTJjMTI4MzJjNTY0%0D%0ANCIgSXNzdWVJbnN0YW50PSIyMDE1LTA1LTA0VDE0OjAxOjExWiIgVmVyc2lvbj0i%0D%0AMi4wIj48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRj%0D%0AOlNBTUw6Mi4wOmFzc2VydGlvbiIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6%0D%0AU0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPklEUF9QT0xFLUVNUExPSV9J%0D%0AUUw8L3NhbWw6SXNzdWVyPjxzYW1scDpTdGF0dXM%2BPHNhbWxwOlN0YXR1c0NvZGUg%0D%0AVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2Vz%0D%0AcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiB4bWxuczpzYW1sPSJ1%0D%0Acm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iaWQtZFlO%0D%0ARWh0MjdjTzg2YkhxSFFud3VSVW55R1NnLSIgSXNzdWVJbnN0YW50PSIyMDE1LTA1%0D%0ALTA0VDE0OjAxOjExWiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0%0D%0APSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRp%0D%0AdHkiPklEUF9QT0xFLUVNUExPSV9JUUw8L3NhbWw6SXNzdWVyPjxkc2lnOlNpZ25h%0D%0AdHVyZSB4bWxuczpkc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRz%0D%0AaWcjIj48ZHNpZzpTaWduZWRJbmZvPjxkc2lnOkNhbm9uaWNhbGl6YXRpb25NZXRo%0D%0Ab2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMt%0D%0AYzE0biMiLz48ZHNpZzpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8v%0D%0Ad3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48ZHNpZzpSZWZl%0D%0AcmVuY2UgVVJJPSIjaWQtZFlORWh0MjdjTzg2YkhxSFFud3VSVW55R1NnLSI%2BPGRz%0D%0AaWc6VHJhbnNmb3Jtcz48ZHNpZzpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8v%0D%0Ad3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIv%0D%0APjxkc2lnOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIw%0D%0AMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHNpZzpUcmFuc2Zvcm1zPjxkc2lnOkRp%0D%0AZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkv%0D%0AeG1sZHNpZyNzaGExIi8%2BPGRzaWc6RGlnZXN0VmFsdWU%2BS2h6WS92VzB5clhzTVVh%0D%0AM2hTbno0a1VHd2tFPTwvZHNpZzpEaWdlc3RWYWx1ZT48L2RzaWc6UmVmZXJlbmNl%0D%0APjwvZHNpZzpTaWduZWRJbmZvPjxkc2lnOlNpZ25hdHVyZVZhbHVlPmk2WUpOb0Rh%0D%0Ad28xS1pEK3YzYXZCeDVyd3VpZ1llWnQ1djZYY1F4NHdkazNicmwxQTVlbk5YTzZQ%0D%0AOW14alBOWjJZQmVoOXl3V0VVWkRGWFJHeng1VXkvMnZXdDVESVlCbHlyakJjTG1E%0D%0ARkV5Z1czcFJjTEhJNTVqVkwrRTZLVVFROE1UU3R3N21VQVFNa2RNUkR6QjR3N3J4%0D%0AdGZjK1A1ZkxweFhobEtqcDl2SjVhRU5ZcVFWdWg5enRzc1c0QTNHVjdYVGljYXVr%0D%0AOWh3K3gvY3B2U0tDM3F1ejI4cnp2SnFKV0p4OE1GZkZzVndYbFJ1MnZwaXZEVlRO%0D%0AMzNLSUtXRDBwM2NyZkdvYXJKVFlZak9Ed1lISUhNSldWczNnWmVQVnZxSFYvMWtz%0D%0AK0haRXQ0d0VHZmVjRjg3dk1GSkxYejRYeGVTZG8rVnJHeXlVZHFzeUdLeG02dz09%0D%0APC9kc2lnOlNpZ25hdHVyZVZhbHVlPjwvZHNpZzpTaWduYXR1cmU%2BPHNhbWw6U3Vi%0D%0AamVjdD48c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FN%0D%0ATDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiIE5hbWVRdWFsaWZpZXI9IklE%0D%0AUF9QT0xFLUVNUExPSV9JUUwiIFNQTmFtZVF1YWxpZmllcj0iU1BfTlVYRU9fVFUi%0D%0APmlkLVpYdllyWTMxS21VZGVxTWdiWWpiT21sMnBwVS08L3NhbWw6TmFtZUlEPjxz%0D%0AYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6%0D%0AdGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9u%0D%0ARGF0YSBJblJlc3BvbnNlVG89ImI3Mzk1YzZmLWQwOWEtNGNiYS05OWRmLTJjMTI4%0D%0AMzJjNTY0NCIgTm90T25PckFmdGVyPSIyMDE1LTA1LTA0VDE0OjA2OjExWiIgUmVj%0D%0AaXBpZW50PSJodHRwczovL2NvbGlicmktYi1kZXYuc2lpMjQucG9sZS1lbXBsb2ku%0D%0AaW50cmE6OTY4MC9udXhlby9ueHN0YXJ0dXAuZmFjZXMiLz48L3NhbWw6U3ViamVj%0D%0AdENvbmZpcm1hdGlvbj48L3NhbWw6U3ViamVjdD48c2FtbDpDb25kaXRpb25zIE5v%0D%0AdEJlZm9yZT0iMjAxNS0wNS0wNFQxNDowMToxMVoiIE5vdE9uT3JBZnRlcj0iMjAx%0D%0ANS0wNS0wNFQxNDowNjoxMVoiPjxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24%2BPHNh%0D%0AbWw6QXVkaWVuY2U%2BU1BfTlVYRU9fVFU8L3NhbWw6QXVkaWVuY2U%2BPC9zYW1sOkF1%0D%0AZGllbmNlUmVzdHJpY3Rpb24%2BPC9zYW1sOkNvbmRpdGlvbnM%2BPHNhbWw6QXV0aG5T%0D%0AdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE1LTA1LTA0VDEzOjUwOjAzWiIgU2Vz%0D%0Ac2lvbkluZGV4PSJpZC1aTkRoeVJKOURlUjFFS1A4YlpYT3JmN0EzNTAtIiBTZXNz%0D%0AaW9uTm90T25PckFmdGVyPSIyMDE1LTA1LTA0VDE1OjAxOjExWiI%2BPHNhbWw6QXV0%0D%0AaG5Db250ZXh0PjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpu%0D%0AYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJh%0D%0AbnNwb3J0PC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDpBdXRobkNv%0D%0AbnRleHQ%2BPC9zYW1sOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24%2BPC9z%0D%0AYW1scDpSZXNwb25zZT4%3D%0D%0A");
        // .decode("nZNPb%2BMgEMW%2FisUd27hu4qAkUpruaiP1j5U41aqXCuPxFskGl8Fd77df4qbdHNoc9oTEPB7zewNzFG2TdHzVu2e9hZce0AVD22jkb5UF6a3mRqBCrkULyJ3ku9XtDU%2FCmHfWOCNNQ4IVIlinjF4bjX0Ldgf2VUnYb28W5Nm5DnkUeaUqraIlreA1RKWSNOxMAxTarjEqVNpZwWeTLI50P4CJ9IBOWNd3YS0kIAk21wsyFVUK9eyCiouS0XQqpnSWVoKWADErs3JS17VXIvaw0f68dguSxOySxpeUsYIlPM04y8JJxh5JkB8RrpSulP51nrd8EyH%2FURQ5ze93BQkewKLn9neEMVnOx9j4eLs9TfK8sXiPjyx3%2BdPd%2Fue3%2B6diP49O3Y7eHb%2FzxzfXuQ9T%2Fgm%2BG9sK97U7C9m4oypaj1Lea%2BxAqlpBRaIP0%2BPwoRqfgp%2Big8EFa9N2wio88MEgpPsgPJWtG9%2F%2FFur%2F4j0rk1wevP127pffxlaHeYH0fRZWeBBj3XtKn3W0PBa%2F4PtXPv0Ay78%3D");
        
        // String message =
        // "nZNPb+MgEMW/isUd27hu4qAkUpruaiP1j5U41aqXCuPxFskGl8Fd77df4qbdHNoc9oTEPB7zewNzFG2TdHzVu2e9hZce0AVD22jkb5UF6a3mRqBCrkULyJ3ku9XtDU/CmHfWOCNNQ4IVIlinjF4bjX0Ldgf2VUnYb28W5Nm5DnkUeaUqraIlreA1RKWSNOxMAxTarjEqVNpZwWeTLI50P4CJ9IBOWNd3YS0kIAk21wsyFVUK9eyCiouS0XQqpnSWVoKWADErs3JS17VXIvaw0f68dguSxOySxpeUsYIlPM04y8JJxh5JkB8RrpSulP51nrd8EyH/URQ5ze93BQkewKLn9neEMVnOx9j4eLs9TfK8sXiPjyx3+dPd/ue3+6diP49O3Y7eHb/zxzfXuQ9T/gm+G9sK97U7C9m4oypaj1Lea+xAqlpBRaIP0+PwoRqfgp+ig8EFa9N2wio88MEgpPsgPJWtG9//Fur/4j0rk1wevP127pffxlaHeYH0fRZWeBBj3XtKn3W0PBa/4PtXPv0Ay78=";
        
        when(request.getMethod()).thenReturn(method);
        when(request.getContentLength()).thenReturn(message.length());
        when(request.getContentType()).thenReturn(contentType);
        when(request.getParameter("SAMLart")).thenReturn(null);
        when(request.getParameter("SAMLRequest")).thenReturn(null);
        when(request.getParameter("SAMLResponse")).thenReturn(message);
        when(request.getParameter("RelayState")).thenReturn("");
        when(request.getParameter("Signature")).thenReturn("");
        when(request.getRequestURI()).thenReturn(urlP.getPath());
        when(request.getRequestURL()).thenReturn(new StringBuffer(url));
        when(request.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(null);
        when(request.isSecure()).thenReturn(false);
        //when(request.getAttribute(SAMLConstants.LOCAL_ENTITY_ID)).thenReturn(null);
        return request;
    }
    
    protected SAMLObject decodeMessage(String message) throws IOException, DataFormatException {
        try {
            byte[] decodedBytes = Base64.decode(message);
            if (decodedBytes == null) {
                throw new MessageDecodingException(
                                "Unable to Base64 decode incoming message");
            }
            
            InputStream is = new ByteArrayInputStream(DeflateUtils.decompress(decodedBytes));
            
            Document messageDoc = new BasicParserPool().parse(is);
            Element messageElem = messageDoc.getDocumentElement();
            
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory()
                            .getUnmarshaller(messageElem);
            
            return (SAMLObject) unmarshaller.unmarshall(messageElem);
        } catch (MessageDecodingException | XMLParserException | UnmarshallingException e) {
            //
        }
        return null;
    }
}
