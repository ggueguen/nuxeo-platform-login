/*
 * (C) Copyright 2006-2013 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Nelson Silva <nelson.silva@inevo.pt> - initial API and implementation
 *     Nuxeo
 */

package org.nuxeo.ecm.platform.oauth2.openid.auth;

import java.util.Date;
import com.google.api.client.json.GenericJson;
import com.google.api.client.util.DateTime;
import com.google.api.client.util.Key;

public class DefaultOpenIDUserInfo extends GenericJson implements OpenIDUserInfo {

    @Key("sub")
    protected String subject;

    @Key("name")
    protected String name;

    @Key("given_name")
    protected String givenName;

    @Key("family_name")
    protected String familyName;

    @Key("middle_name")
    protected String middleName;

    @Key("nickname")
    protected String nickname;

    @Key("preferred_username")
    protected String preferredUsername;

    @Key("profile")
    protected String profile;

    @Key("picture")
    protected String picture;

    @Key("website")
    protected String website;

    @Key("email")
    protected String email;

    @Key("email_verified")
    protected boolean emailVerified;

    @Key("gender")
    protected String gender;

    @Key("birthdate")
    protected Date birthdate;

    @Key("zoneinfo")
    protected String zoneInfo;

    @Key("locale")
    protected String locale;

    @Key("phone_number")
    protected String phoneNumber;

    @Key("address")
    protected String address;

    @Key("updated_time")
    protected String updatedTime;

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getGivenName() {
        return givenName;
    }

    @Override
    public String getFamilyName() {
        return familyName;
    }

    @Override
    public String getMiddleName() {
        return middleName;
    }

    @Override
    public String getNickname() {
        return nickname;
    }

    @Override
    public String getPreferredUsername() {
        return preferredUsername;
    }

    @Override
    public String getProfile() {
        return profile;
    }

    @Override
    public String getPicture() {
        return picture;
    }

    @Override
    public String getWebsite() {
        return website;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public boolean isEmailVerified() {
        return emailVerified;
    }

    @Override
    public String getGender() {
        return gender;
    }

    @Override
    public Date getBirthdate() {
        return birthdate;
    }

    @Override
    public String getZoneInfo() {
        return zoneInfo;
    }

    @Override
    public String getLocale() {
        return locale;
    }

    @Override
    public String getPhoneNumber() {
        return phoneNumber;
    }

    @Override
    public String getAddress() {
        return address;
    }

    @Override
    public Date getUpdatedTime() {
        Date date;
        try {
            DateTime dateTime = DateTime.parseRfc3339(updatedTime);
            date = new Date(dateTime.getValue());
        } catch (NumberFormatException e) {
            return null;
        }
        return date;
    }

}
