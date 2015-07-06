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

    private static final Log LOG = LogFactory.getLog(AttributeUserResolver.class);

    public static final String MAIL_REGEX = "^[_a-zA-Z0-9-]+(\\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)+$";

    public static final String IDENTIFICATOR_ATTRIBUTE = "nuxeo.saml2.identificator.attribute";

    public static final String USER_MANAGER_FIELD = "nuxeo.saml2.userManagerField";
    
    public static String getIdentificatorAttribute() {
        return Framework.getProperty(IDENTIFICATOR_ATTRIBUTE, "mail"); // mail employeeid 
    }
    
    public static String getUserManagerField() {
        return Framework.getProperty(USER_MANAGER_FIELD, "getUserEmailField" ); // getUserEmailField getUserIdField
    }
    
    
    private boolean valideMail(String mail){
        return Pattern.matches(MAIL_REGEX, mail);
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
        return value;
    }
    
    protected String getIdentificatorUserField(UserManager userManager) {
        String value = null;
        
        try {
            Method method = userManager.getClass().getMethod(getUserManagerField());
            Object invoke = method.invoke(userManager);
            value = (String)invoke;
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException e) {
            LOG.error("Error while search user in UserManager using " + getUserManagerField() + " " + value, e);
            return null;
        }
        
        return value;
    }
    
    @Override
    public String findNuxeoUser(SAMLCredential credential) {
        
        String value = getValueFromCredential(credential);
        String identificatorUserField = null;
        
        try {
            UserManager userManager = Framework.getLocalService(UserManager.class);
            Map<String, Serializable> query = new HashMap<>();
            identificatorUserField = getIdentificatorUserField(userManager);
            query.put(identificatorUserField, value);
            
            DocumentModelList users = userManager.searchUsers(query, null);
            
            if (users.isEmpty()) {
                return null;
            }
            
            DocumentModel user = users.get(0);
            return (String) user.getPropertyValue(userManager.getUserIdField());
            
        } catch (ClientException e) {
            LOG.error("Error while search user in UserManager using " + identificatorUserField + value, e);
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
            LOG.error("Error while search user in UserManager using " + identificatorUserField + value, e);
            return null;
        }
        return user;
    }
    
}
