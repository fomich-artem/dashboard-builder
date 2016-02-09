package org.jboss.dashboard.ui.controller.requestChain;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.jboss.dashboard.users.UserStatus;

/**
 * URL-based authentication processor for simple integration
 *
 * @author <a href="mailto:faa@comsoft-corp.ru">Fomichev Artem</a> <br>
 *
 */
@ApplicationScoped
public class URLBasedAuthProcessor extends AbstractChainProcessor {

	protected static final String DEFAULT_PASSWORD = System.getProperty("org.jboss.dashboard.ui.controller.requestChain.URLBasedAuthProcessor.DEFAULT_PASSWORD", "1");

	@Override
	public boolean processRequest() throws Exception {
        HttpServletRequest request = getHttpRequest();
        String username = request.getParameter("username");
        UserStatus us = UserStatus.lookup();
        if (StringUtils.isNotBlank(username)) {
        	if (!us.isAnonymous()) {
        		if (!username.equals(us.getUserLogin()))
        			request.logout();
        		else
        			return true;
        	}
    		request.login(username, DEFAULT_PASSWORD);
    		if (request.isUserInRole("root"))
    			request.logout();
        }
		return true;
	}

}
