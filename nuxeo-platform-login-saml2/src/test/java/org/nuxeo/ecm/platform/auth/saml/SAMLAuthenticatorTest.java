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

        String samlRequest = query.replaceFirst(
                        HTTPRedirectBinding.SAML_REQUEST + "=", "");

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
