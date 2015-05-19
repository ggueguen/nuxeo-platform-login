package org.nuxeo.ecm.platform.auth.saml.user;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.platform.auth.saml.SAMLCredential;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;

public class AttributeUserResolver  extends UserResolver {

private static final String mailRegex = "^[_a-z0-9-]+(\\.[_a-z0-9-]+)*@[a-z0-9-]+(\\.[a-z0-9-]+)+$";

    private static final Log log = LogFactory.getLog(AttributeUserResolver.class);

    public static String getIdentificatorAttribute() {
        return Framework.getProperty("nuxeo.saml2.identificator.attribute", "employeeid"); // employeeid mail
    }
    
    public static String getUserManagerField() {
        return Framework.getProperty("nuxeo.saml2.userManagerField", "getUserIdField"); // getUserEmailField getUserIdField
    }
    
    
    private boolean valideMail(String mail){
        return Pattern.matches(mailRegex, mail);
    }

    protected String getValueFromCredential(SAMLCredential credential) {

        String value = null;
        String identificator = getIdentificatorAttribute();
        
        for (Attribute attribute : credential.getAttributes()) {
            if (identificator.equals(attribute.getName())) {
                
                List<XMLObject> attributeValues = attribute.getAttributeValues();
                for (XMLObject xmlObject : attributeValues) {
                    if (xmlObject instanceof XSString){
                        value = ((XSString)xmlObject).getValue();
                        
                        if ("mail".equals(identificator)) {
                            if (valideMail(value))
                                break;
                            else
                                value = null;
                        } else {
                            break;
                        }
                    }
                }
                break;
            }
        }
        
        log.debug(">>> " + identificator + " : " + value);
        return value;
    }
    
    protected String getIdentificatorUserField(UserManager userManager) {
        String value = null;
        
        try {
            Method method = userManager.getClass().getMethod(getUserManagerField());
            Object invoke = method.invoke(userManager);
            log.debug(">>> getIdentificatorUserField "  + getUserManagerField() +" : " + invoke);
                value = (String)invoke;
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException | SecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
    //    return userManager.getUserEmailField();
        return value;
    }
    
    @Override
    public String findNuxeoUser(SAMLCredential credential) {
        
        String value = getValueFromCredential(credential);

        try {
            UserManager userManager = Framework.getLocalService(UserManager.class);
            Map<String, Serializable> query = new HashMap<>();
            query.put(getIdentificatorUserField(userManager), value);
            
            DocumentModelList users = userManager.searchUsers(query, null);
            
            if (users.isEmpty()) {
                return null;
            }
            
            DocumentModel user = users.get(0);
            log.debug("userManager.getUserIdField() : " + userManager.getUserIdField());
            return (String) user.getPropertyValue(userManager.getUserIdField());
            
        } catch (ClientException e) {
            log.error("Error while search user in UserManager using email "
                            + value, e);
            return null;
        }
    }
    
    @Override
    public DocumentModel updateUserInfo(DocumentModel user, SAMLCredential credential) {
        
        String value = getValueFromCredential(credential);
        String identificatorUserField = null;
        
        try {
            UserManager userManager = Framework.getLocalService( UserManager.class);
            identificatorUserField = getIdentificatorUserField(userManager);
            user.setPropertyValue(identificatorUserField, value);
        } catch (ClientException e) {
            log.error("Error while search user in UserManager using " + identificatorUserField + value, e);
            return null;
        }
        return user;
    }
    
}
