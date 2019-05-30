/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.context;

import org.springframework.security.core.Authentication;

import java.io.Serializable;

/**
 *
 * 与当前执行线程关联的最小安全信息的接口定义。
 *
 * 安全上下文存储在 {@link SecurityContextHolder}中。
 *
 * @author Ben Alex
 */
public interface SecurityContext extends Serializable {
	// ~ Methods
	// ========================================================================================================

	/**
	 * 获取当前经过身份验证的principal或认证请求令牌。
	 *
	 * @return <code>Authentication</code>，如果没有可用的身份验证信息，则为null
	 */
	Authentication getAuthentication();

	/**
	 * 更改当前已验证的principal，或删除认证信息。
	 *
	 * @param authentication  新的<code>Authentication</code>令牌，如果不存储其他身份验证信息，则为null
	 */
	void setAuthentication(Authentication authentication);
}
