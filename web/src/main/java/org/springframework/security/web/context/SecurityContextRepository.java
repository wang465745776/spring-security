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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;

/**
 * 用于在请求之间保持{@link SecurityContext}的策略。
 * <p>
 * 被{@link SecurityContextPersistenceFilter}用于获取应该用于当前执行线程的上下文，
 * 并在请求已完成后，从线程本地存储中删除之后存储上下文。
 * <p>
 * 使用的持久性机制将取决于实现，但最常见的是HttpSession将用于存储上下文。
 * @author Luke Taylor
 * @see SecurityContextPersistenceFilter
 * @see HttpSessionSecurityContextRepository
 * @see SaveContextOnUpdateOrErrorResponseWrapper
 * @since 3.0
 */
public interface SecurityContextRepository {

	/**
	 * 获取所提供请求的安全上下文。 对于未经身份验证的用户，应返回空的上下文实现。 此方法不应返回null。
	 * <p>
	 * HttpRequestResponseHolder参数的使用允许实现返回请求或响应（或两者）的包装版本，允许它们访问请求的特定于实现的状态。
	 * 从holder中获取的值将被传递到过滤器链，并在最终被调用时传递给saveContext方法。
	 * 实现可能希望返回{@link SaveContextOnUpdateOrErrorResponseWrapper}的子类作为响应对象，
	 * 这可以保证在发生错误或重定向时保持上下文。
	 * @param requestResponseHolder 当前加载上下文的请求和响应的holder。
	 * @return 用于当前请求的安全上下文应该永远不会为null
	 */
	SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder);

	/**
	 * 在完成请求时存储安全性上下文。
	 * @param context  从holder处获得的非空的上下文。
	 * @param request
	 * @param response
	 */
	void saveContext(SecurityContext context, HttpServletRequest request,
					 HttpServletResponse response);

	/**
	 * 允许查询存储库，以确定它是否包含当前请求的安全上下文。
	 * @param request 当前的请求
	 * @return 如果请求的安全上下文被找到则返回true，否则返回false
	 */
	boolean containsContext(HttpServletRequest request);
}
