/**
* Copyright 2011 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/
package securesocial.provider.providers;

import com.google.gson.JsonObject;
import org.apache.commons.lang.ArrayUtils;
import play.Logger;
import play.libs.WS;
import securesocial.provider.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A Facebook Provider
 */
public class FacebookProvider extends OAuth2Provider
{
    private static final String ME_API = "https://graph.facebook.com/me?fields=name,picture%s,email&access_token=%s";
    private static final String ERROR = "error";
    private static final String MESSAGE = "message";
    private static final String TYPE = "type";
    private static final String ID = "id";
    private static final String NAME = "name";
    private static final String PICTURE = "picture";
    private static final String EMAIL = "email";

    private static final String BIRTHDAY = "birthday";
    private static final String LOCATION = "location";

    private static final String SCOPE_BIRTHDAY = "user_birthday";
    private static final String SCOPE_LOCATION = "user_location";

    public FacebookProvider() {
        super(ProviderType.facebook);
    }

    /**
     * @return additional fields asked for permission through scope parameters
     */
    private String getAdditionalScopeFields(){
        StringBuilder sb=new StringBuilder();
        if(hasScope(SCOPE_BIRTHDAY)) {
            sb.append(","+BIRTHDAY);
        }
        if(hasScope(SCOPE_LOCATION)){
            sb.append(","+LOCATION);
        }

        return sb.toString();
    }

    @Override
    protected void fillProfile(SocialUser user, Map<String, Object> authContext) {
        JsonObject me = WS.url(ME_API, getAdditionalScopeFields(), user.accessToken).get().getJson().getAsJsonObject();
        JsonObject error = me.getAsJsonObject(ERROR);

        if ( error != null ) {
            final String message = error.get(MESSAGE).getAsString();
            final String type = error.get(TYPE).getAsString();
            Logger.error("Error retrieving profile information from Facebook. Error type: %s, message: %s.", type, message);
            throw new AuthenticationException();
        }

        user.id.id = me.get(ID).getAsString();
        user.displayName = me.get(NAME).getAsString();
        user.avatarUrl = me.get(PICTURE).getAsString();
        user.email = me.get(EMAIL).getAsString();

        //fill provider specific additional fields for additional scope param
        user.scopeValues=new HashMap<String, String>();
        if(hasScope(SCOPE_BIRTHDAY)) {
            user.scopeValues.put(BIRTHDAY, me.get(BIRTHDAY).getAsString());
        }
        if(hasScope(SCOPE_LOCATION)){
            String locName=me.get(LOCATION).getAsJsonObject().get("name").getAsString();
            user.scopeValues.put(LOCATION, locName);
        }
    }
}
