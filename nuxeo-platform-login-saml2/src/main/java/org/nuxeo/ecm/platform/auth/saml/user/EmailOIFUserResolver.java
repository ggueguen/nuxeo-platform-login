package org.nuxeo.ecm.platform.auth.saml.user;

import java.util.List;
import java.util.regex.Pattern;

import org.nuxeo.ecm.platform.auth.saml.SAMLCredential;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;



/**
 * Implementation for OIF provider
 * 
 * @author Gildas Gueguen <gildas.gueguen@gmail.com>
 *
 */
public class EmailOIFUserResolver extends EmailBasedUserResolver {
    
    private static final String mailRegex = "^[_a-z0-9-]+(\\.[_a-z0-9-]+)*@[a-z0-9-]+(\\.[a-z0-9-]+)+$";
    
    private boolean valideMail(String mail){
        return Pattern.matches(mailRegex, mail);
    }

    @Override
    protected String getEmailFromCredential(SAMLCredential credential) {

        String mail = null;
        
        for (Attribute attribute : credential.getAttributes()) {
            if ("mail".equals(attribute.getName())) {
                
                List<XMLObject> attributeValues = attribute.getAttributeValues();
                for (XMLObject xmlObject : attributeValues) {
                    if (xmlObject instanceof XSString){
                        mail = ((XSString)xmlObject).getValue();
                        
                        if (valideMail(mail))
                            break;
                        else
                            mail = null;
                        
                    }
                }
                break;
            }
        }
        
        return mail;
    }
    
}
