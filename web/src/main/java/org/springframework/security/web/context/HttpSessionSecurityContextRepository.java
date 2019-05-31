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

import javax.servlet.AsyncContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.Transient;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.util.WebUtils;

/**
 * 一个{@code SecurityContextRepository}实现，用于将安全上下文存储在请求之间的{@code HttpSession}中。
 * <p>
 * 在loadContext方法中将查询{@code HttpSession}以查询{@code SecurityContext}
 * （默认情况下使用key{@link #SPRING_SECURITY_CONTEXT_KEY}）。
 * 如果由于某种原因无法从{@code HttpSession}获取有效的{@code SecurityContext}，
 * 则会通过调用{@link SecurityContextHolder#createEmptyContext()}创建一个新的SecurityContext，返回此实例。
 * <p>
 * 调用saveContext时，上下文将存储在相同key下，提供
 * 1.值已经改变
 * 2.配置的AuthenticationTrustResolver不会报告内容代表匿名用户
 * <p>
 * 使用标准配置，如果{@code HttpSession}不存在，则在loadContext期间不会创建{@code HttpSession}。
 * 当在Web请求结束时调用saveContext并且不存在会话时，只有在提供的{@code SecurityContext}不等于空的{@code SecurityContext}
 * 实例时才会创建新的{@code HttpSession}。这避免了不必要的HttpSession创建，但在请求期间自动存储对上下文所做的更改。
 * 请注意，如果将{@link SecurityContextPersistenceFilter}配置为急切地创建会话，则此处应用的会话最小化逻辑不会产生任何差异。
 * 如果您正在使用eager会话创建，那么您应该确保此类的allowSessionCreation属性设置为true（默认值）。
 * <p>
 * 如果由于某种原因，不应该创建{@code HttpSession}
 * （例如，如果正在使用基本身份验证或者永远不会呈现相同{@code jsessionid})的类似客户端），
 * 则{@link #setAllowSessionCreation(boolean) allowSessionCreation}应设置为false。
 * 只有在您确实需要节省服务器内存并确保使用{@code SecurityContextHolder}的所有类都设计为
 * Web请求之间没有{@code SecurityContext}持久性时才执行此操作。
 * @author Luke Taylor
 * @since 3.0
 */
public class HttpSessionSecurityContextRepository implements SecurityContextRepository {
	/** 在session中存储安全上下文的默认key。 */
	public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

	protected final Log logger = LogFactory.getLog(this.getClass());

	/** SecurityContext实例，用于检查与默认（未认证的）内容的相等性 */
	private final Object contextObject = SecurityContextHolder.createEmptyContext();
	private boolean allowSessionCreation = true;

	/** 禁止URL重写 */
	private boolean disableUrlRewriting = false;

	/** 在session中保存security context的键 */
	private String springSecurityContextKey = SPRING_SECURITY_CONTEXT_KEY;

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * 获取当前请求的security context（如果可用）并返回它。
	 * <p>
	 * 如果session为null，或者context对象为null或者session中存储的context对象不是{@code SecurityContext}的实例，
	 * 则将生成并返回新的上下文对象。
	 */
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
		HttpServletRequest request = requestResponseHolder.getRequest();
		HttpServletResponse response = requestResponseHolder.getResponse();
		HttpSession httpSession = request.getSession(false);

		// 1.从session获取SecurityContext,如果不存在就创建一个
		SecurityContext context = readSecurityContextFromSession(httpSession);

		if (context == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("No SecurityContext was available from the HttpSession: "
						+ httpSession + ". " + "A new one will be created.");
			}
			context = generateNewContext();

		}

		SaveToSessionResponseWrapper wrappedResponse = new SaveToSessionResponseWrapper(
				response, request, httpSession != null, context);
		requestResponseHolder.setResponse(wrappedResponse);

		requestResponseHolder.setRequest(new SaveToSessionRequestWrapper(
				request, wrappedResponse));

		return context;
	}

	public void saveContext(SecurityContext context, HttpServletRequest request,
							HttpServletResponse response) {
		SaveContextOnUpdateOrErrorResponseWrapper responseWrapper = WebUtils
				.getNativeResponse(response,
						SaveContextOnUpdateOrErrorResponseWrapper.class);
		if (responseWrapper == null) {
			throw new IllegalStateException(
					"Cannot invoke saveContext on response "
							+ response
							+ ". You must use the HttpRequestResponseHolder.response after invoking loadContext");
		}
		// saveContext() might already be called by the response wrapper
		// if something in the chain called sendError() or sendRedirect(). This ensures we
		// only call it
		// once per request.
		if (!responseWrapper.isContextSaved()) {
			responseWrapper.saveContext(context);
		}
	}

	/**
	 * 判断session中是否存在context
	 * TODO 如果手动设置了context的值，可能会被校验为存在context，这算是一个小小的bug
	 * @author freedom wang
	 * @date 2019-05-30 22:04:30
	 */
	public boolean containsContext(HttpServletRequest request) {
		HttpSession session = request.getSession(false);

		if (session == null) {
			return false;
		}

		return session.getAttribute(springSecurityContextKey) != null;
	}

	/**
	 * 从Session中读取SecurityContext
	 * @param httpSession 从请求中获取的session
	 * @return 若从session获取SecurityContext失败，则返回null,否则返回SecurityContext
	 */
	private SecurityContext readSecurityContextFromSession(HttpSession httpSession) {
		final boolean debug = logger.isDebugEnabled();

		// 1.校验session是否存在
		if (httpSession == null) {
			if (debug) {
				logger.debug("No HttpSession currently exists");
			}

			return null;
		}

		// 2.校验对应属性是否存在
		// Session存在，所以尝试从中获取context
		Object contextFromSession = httpSession.getAttribute(springSecurityContextKey);

		if (contextFromSession == null) {
			if (debug) {
				logger.debug("HttpSession returned null object for SPRING_SECURITY_CONTEXT");
			}

			return null;
		}

		// 3.校验从session中获取到的内容是否为SecurityContext
		// 我们现在已经从session获取到了安全上下文对象
		if (!(contextFromSession instanceof SecurityContext)) {
			if (logger.isWarnEnabled()) {
				logger.warn(springSecurityContextKey
						+ " did not contain a SecurityContext but contained: '"
						+ contextFromSession
						+ "'; are you improperly modifying the HttpSession directly "
						+ "(you should always use SecurityContextHolder) or using the HttpSession attribute "
						+ "reserved for this class?");
			}

			return null;
		}

		if (debug) {
			logger.debug("Obtained a valid SecurityContext from "
					+ springSecurityContextKey + ": '" + contextFromSession + "'");
		}

		// Everything OK. The only non-null return from this method.

		// 4.校验完毕，返回SecurityContext
		return (SecurityContext) contextFromSession;
	}

	/**
	 * 默认情况下，调用{@link SecurityContextHolder#createEmptyContext()}以获取新context
	 * （调用此方法时，holder中不应存在context）。
	 * 使用此方法，context创建策略由正在使用的{@link SecurityContextHolderStrategy}决定。
	 * 默认实现将返回一个新的SecurityContextImpl。
	 * @return 一个新的SecurityContext实例. 不会为null.
	 */
	protected SecurityContext generateNewContext() {
		return SecurityContextHolder.createEmptyContext();
	}

	/**
	 * If set to true (the default), a session will be created (if required) to store the
	 * security context if it is determined that its contents are different from the
	 * default empty context value.
	 * <p>
	 * Note that setting this flag to false does not prevent this class from storing the
	 * security context. If your application (or another filter) creates a session, then
	 * the security context will still be stored for an authenticated user.
	 * @param allowSessionCreation
	 */
	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}

	/**
	 * 允许禁用URL中的session标识符的使用。 默认关闭。
	 * @param disableUrlRewriting 设置为true以禁用响应包装器中的URL编码方法，并防止使用jsessionid参数。
	 */
	public void setDisableUrlRewriting(boolean disableUrlRewriting) {
		this.disableUrlRewriting = disableUrlRewriting;
	}

	/**
	 * 允许为这个repository实例自定义session属性名
	 * @param springSecurityContextKey session中保存security context使用的属性名. 默认是 {@link #SPRING_SECURITY_CONTEXT_KEY}.
	 */
	public void setSpringSecurityContextKey(String springSecurityContextKey) {
		Assert.hasText(springSecurityContextKey,
				"springSecurityContextKey cannot be empty");
		this.springSecurityContextKey = springSecurityContextKey;
	}

	// ~ Inner Classes
	// ==================================================================================================

	private static class SaveToSessionRequestWrapper extends
			HttpServletRequestWrapper {
		private final SaveContextOnUpdateOrErrorResponseWrapper response;

		public SaveToSessionRequestWrapper(HttpServletRequest request,
										   SaveContextOnUpdateOrErrorResponseWrapper response) {
			super(request);
			this.response = response;
		}

		@Override
		public AsyncContext startAsync() {
			response.disableSaveOnResponseCommitted();
			return super.startAsync();
		}

		@Override
		public AsyncContext startAsync(ServletRequest servletRequest,
									   ServletResponse servletResponse) throws IllegalStateException {
			response.disableSaveOnResponseCommitted();
			return super.startAsync(servletRequest, servletResponse);
		}
	}

	/**
	 * 当sendError()或sendRedirect发生时，应用于每个请求/响应的包装器使用SecurityContext更新HttpSession。 见SEC-398。
	 * <p>
	 * 存储从请求开始的必要状态，以便在保存之前确定security context是否已更改。
	 */
	final class SaveToSessionResponseWrapper extends
			SaveContextOnUpdateOrErrorResponseWrapper {

		private final HttpServletRequest request;
		private final boolean httpSessionExistedAtStartOfRequest;
		private final SecurityContext contextBeforeExecution;
		private final Authentication authBeforeExecution;

		/**
		 * 除了我们要包装的请求和响应对象之外，还需要成功调用saveContext()所需的参数。
		 * @param request                            请求对象 (用来获取session, 如果存在的化).
		 * @param httpSessionExistedAtStartOfRequest 指示在执行过滤器链之前是否存在会话。
		 *                                           如果是true，并且session被发现为null，则表示它在请求期间失效，现在将创建新session。
		 * @param context                            执行过滤器链之前的context。 只有在请求期间更改了context或其内容时，才会存储上下文。
		 */
		SaveToSessionResponseWrapper(HttpServletResponse response,
									 HttpServletRequest request, boolean httpSessionExistedAtStartOfRequest,
									 SecurityContext context) {
			super(response, disableUrlRewriting);
			this.request = request;
			this.httpSessionExistedAtStartOfRequest = httpSessionExistedAtStartOfRequest;
			this.contextBeforeExecution = context;
			this.authBeforeExecution = context.getAuthentication();
		}

		/**
		 * 在session中存储提供的security context（如果可用），并且自请求开始时设置了之后它发生了改变。
		 * 如果AuthenticationTrustResolver将当前用户标识为匿名，则不会存储context。
		 * @param context 过滤器链处理请求后从SecurityContextHolder获取的context对象。
		 *                SecurityContextHolder.getContext()不能用于获取context，因为在调用此方法时它已被清除。
		 */
		@Override
		protected void saveContext(SecurityContext context) {
			final Authentication authentication = context.getAuthentication();
			HttpSession httpSession = request.getSession(false);

			// See SEC-776
			if (authentication == null || trustResolver.isAnonymous(authentication)) {
				if (logger.isDebugEnabled()) {
					logger.debug("SecurityContext is empty or contents are anonymous - context will not be stored in HttpSession.");
				}

				if (httpSession != null && authBeforeExecution != null) {
					// SEC-1587 A non-anonymous context may still be in the session
					// SEC-1735 remove if the contextBeforeExecution was not anonymous
					httpSession.removeAttribute(springSecurityContextKey);
				}
				return;
			}

			if (httpSession == null) {
				httpSession = createNewSessionIfAllowed(context);
			}

			// If HttpSession exists, store current SecurityContext but only if it has
			// actually changed in this thread (see SEC-37, SEC-1307, SEC-1528)
			if (httpSession != null) {
				// We may have a new session, so check also whether the context attribute
				// is set SEC-1561
				if (contextChanged(context)
						|| httpSession.getAttribute(springSecurityContextKey) == null) {
					httpSession.setAttribute(springSecurityContextKey, context);

					if (logger.isDebugEnabled()) {
						logger.debug("SecurityContext '" + context
								+ "' stored to HttpSession: '" + httpSession);
					}
				}
			}
		}

		private boolean contextChanged(SecurityContext context) {
			return context != contextBeforeExecution
					|| context.getAuthentication() != authBeforeExecution;
		}

		private HttpSession createNewSessionIfAllowed(SecurityContext context) {
			if (isTransientAuthentication(context.getAuthentication())) {
				return null;
			}

			if (httpSessionExistedAtStartOfRequest) {
				if (logger.isDebugEnabled()) {
					logger.debug("HttpSession is now null, but was not null at start of request; "
							+ "session was invalidated, so do not create a new session");
				}

				return null;
			}

			if (!allowSessionCreation) {
				if (logger.isDebugEnabled()) {
					logger.debug("The HttpSession is currently null, and the "
							+ HttpSessionSecurityContextRepository.class.getSimpleName()
							+ " is prohibited from creating an HttpSession "
							+ "(because the allowSessionCreation property is false) - SecurityContext thus not "
							+ "stored for next request");
				}

				return null;
			}
			// Generate a HttpSession only if we need to

			if (contextObject.equals(context)) {
				if (logger.isDebugEnabled()) {
					logger.debug("HttpSession is null, but SecurityContext has not changed from default empty context: ' "
							+ context
							+ "'; not creating HttpSession or storing SecurityContext");
				}

				return null;
			}

			if (logger.isDebugEnabled()) {
				logger.debug("HttpSession being created as SecurityContext is non-default");
			}

			try {
				return request.getSession(true);
			} catch (IllegalStateException e) {
				// Response must already be committed, therefore can't create a new
				// session
				logger.warn("Failed to create a session, as response has been committed. Unable to store"
						+ " SecurityContext.");
			}

			return null;
		}
	}

	private boolean isTransientAuthentication(Authentication authentication) {
		return AnnotationUtils.getAnnotation(authentication.getClass(), Transient.class) != null;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 *                      null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
	}
}
