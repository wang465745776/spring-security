/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.context;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 使用在请求之前，从配置的{@link SecurityContextRepository}获取的信息填充{@link SecurityContextHolder}，
 * 并在请求完成并清除上下文持有者后，将其存储回存储库。默认情况下，它使用{@link HttpSessionSecurityContextRepository}。
 * 也就是说默认情况下，使用HttpSession保存SecurityContext信息。
 * 有关HttpSession相关配置选项的信息，请参阅此类。
 * <p>
 * 此过滤器每个请求只执行一次，以解决servlet容器（特别是Weblogic）不兼容问题。
 * <p>
 * 必须在任何身份验证处理机制之前执行此过滤器。
 * 身份验证处理机制（例如BASIC，CAS处理过滤器等）期望在执行时SecurityContextHolder包含有效的SecurityContext。
 * <p>
 * 这本质上是对旧HttpSessionContextIntegrationFilter的重构，以将存储问题委托给单独的策略，
 * 允许在请求之间维护安全上下文的方式进行更多自定义。
 * forceEagerSessionCreation属性可用于确保在执行过滤器链之前会话始终可用（默认值为false，因为这是资源密集型而不建议使用）。
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityContextPersistenceFilter extends GenericFilterBean {

	/** 请求中标示是否已经过滤的属性键，目的是确保每个请求仅应用过滤器一次 */
	static final String FILTER_APPLIED = "__spring_security_scpf_applied";

	/** 安全上下文仓库 */
	private SecurityContextRepository repo;

	/** 用于确保在执行过滤器链之前会话始终可用 */
	private boolean forceEagerSessionCreation = false;

	public SecurityContextPersistenceFilter() {
		// 默认使用HttpSessionSecurityContextRepository，使用httpSession保存安全上下文信息
		this(new HttpSessionSecurityContextRepository());
	}

	public SecurityContextPersistenceFilter(SecurityContextRepository repo) {
		this.repo = repo;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (request.getAttribute(FILTER_APPLIED) != null) {
			// 确保每个请求仅应用过滤器一次
			chain.doFilter(request, response);
			return;
		}

		final boolean debug = logger.isDebugEnabled();

		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

		if (forceEagerSessionCreation) {
			HttpSession session = request.getSession();

			if (debug && session.isNew()) {
				logger.debug("Eagerly created session: " + session.getId());
			}
		}

		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request,
				response);
		SecurityContext contextBeforeChainExecution = repo.loadContext(holder);

		try {
			SecurityContextHolder.setContext(contextBeforeChainExecution);

			chain.doFilter(holder.getRequest(), holder.getResponse());

		} finally {
			SecurityContext contextAfterChainExecution = SecurityContextHolder
					.getContext();
			// 至关重要的删除SecurityContextHolder内容 - 在任何事情之前执行此操作
			// else.
			SecurityContextHolder.clearContext();
			repo.saveContext(contextAfterChainExecution, holder.getRequest(),
					holder.getResponse());
			request.removeAttribute(FILTER_APPLIED);

			if (debug) {
				logger.debug("SecurityContextHolder now cleared, as request processing completed");
			}
		}
	}

	public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
		this.forceEagerSessionCreation = forceEagerSessionCreation;
	}
}
