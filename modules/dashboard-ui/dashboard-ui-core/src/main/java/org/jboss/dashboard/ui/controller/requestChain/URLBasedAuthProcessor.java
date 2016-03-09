package org.jboss.dashboard.ui.controller.requestChain;

import java.util.HashSet;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.jboss.dashboard.users.Role;
import org.jboss.dashboard.users.UserStatus;

/**
 * URL-based authentication processor for simple integration
 *
 * @author <a href="mailto:faa@comsoft-corp.ru">Fomichev Artem</a> <br>
 *
 */
@ApplicationScoped
public class URLBasedAuthProcessor extends HttpSSOProcessor {

	protected static final String DEFAULT_PASSWORD = System.getProperty("org.jboss.dashboard.ui.controller.requestChain.URLBasedAuthProcessor.DEFAULT_PASSWORD", "1");

	/*@Inject
	HttpSSOProcessor ssoProcessor;*/

	@Override
	public boolean processRequest() throws Exception {
        HttpServletRequest request = getHttpRequest();
        String username = request.getParameter("username");
        UserStatus us = UserStatus.lookup();
        if (StringUtils.isNotBlank(username)) {
        	if (!us.isAnonymous()) {
        		if (!username.equals(us.getUserLogin()))
        			doLogout(request, us);
        		else
        			return true;
        	}
    		//request.login(username, DEFAULT_PASSWORD);
    		//ssoProcessor.processRequest();
        	doLogin(username, request, us);
        }
		return true;
	}

	protected void doLogin(String username, HttpServletRequest request, UserStatus us) throws Exception {
		request.login(username, DEFAULT_PASSWORD);
		if (request.isUserInRole("admin")) {
			//us.initSessionAsRoot();
			doLogout(request, us);
		} else {
			Set<String> roleIds = new HashSet<String>();
			Set<Role> roles = /*ssoProcessor.*/getRolesManager().getAllRoles();
			for (Role role : roles) {
				String roleId = role.getName();
				if (request.isUserInRole(roleId)) roleIds.add(roleId);
			}
			us.initSession(username, roleIds);
		}
	}

	protected void doLogout(HttpServletRequest request, UserStatus us) throws Exception {
		request.logout();
		us.closeSession();
	}

}
