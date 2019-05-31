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

import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

import java.lang.reflect.Constructor;

/**
 * 此类使用了策略模式。
 *
 * 将给定的{@link SecurityContext}与当前执行线程相关联。
 * <p>
 * 此类提供了一系列委托给{@link org.springframework.security.core.context.SecurityContextHolderStrategy}实例的静态方法。
 * 该类的目的是提供一种方便的方法来指定应该用于给定JVM的策略。
 * 这是一个JVM范围的设置，因为此类中的所有内容都是静态的，以便于在调用代码时使用。
 * <p>
 * 要指定应使用的策略，您必须提供模式设置。模式设置是定义为<code>static final</code>的字段的三个有效MODE_设置之一，
 * 或者是提供公共无参数构造函数的{@link org.springframework.security.core.context.SecurityContextHolderStrategy}
 * 的具体实现的完全限定类名。
 * <p>
 * 有两种方法可以指定所需的策略模式<code>String</code>。
 * 第一种是通过以{@link #SYSTEM_PROPERTY}为键的系统属性来指定它。
 * 第二种是在使用该类之前调用{@link #setStrategyName(String)}。
 * <p>
 * 如果没有使用这两种方法，该类将默认使用{@link #MODE_THREADLOCAL}，它是向后兼容的，
 * 具有较少的JVM不兼容性并且适用于服务器（而MODE_GLOBAL绝对不适合服务器使用）。
 * @author Ben Alex
 */
public class SecurityContextHolder {
	// ~ Static fields/initializers
	// =====================================================================================

	public static final String MODE_THREADLOCAL = "MODE_THREADLOCAL";
	public static final String MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL";
	public static final String MODE_GLOBAL = "MODE_GLOBAL";
	public static final String SYSTEM_PROPERTY = "spring.security.strategy";

	/** 策略名称，默认拿取系统属性spring.security.strategy的值，将会根据不同的策略名称，调用不同的策略类 */
	private static String strategyName = System.getProperty(SYSTEM_PROPERTY);

	/** 当前使用的策略 */
	private static SecurityContextHolderStrategy strategy;
	private static int initializeCount = 0;

	static {
		initialize();
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * 显式清除当前线程的上下文值。
	 */
	public static void clearContext() {
		strategy.clearContext();
	}

	/**
	 * 获取当前的<code>SecurityContext</code>.
	 * @return 安全上下文 (不为<code>null</code>)
	 */
	public static SecurityContext getContext() {
		return strategy.getContext();
	}

	/**
	 * 主要用于故障排除，此方法显示该类重新初始化其SecurityContextHolderStrategy的次数。
	 * @return 次数（除非您调用{@link #setStrategyName(String)} 切换到备用策略，否则应为1）。
	 */
	public static int getInitializeCount() {
		return initializeCount;
	}

	/**
	 * 安全上下文Holder类的初试化
	 * @author freedom wang
	 * @date 2019-05-30 15:48:02
	 */
	private static void initialize() {
		// 1.校验策略名称，如果为空，则设置为默认的策略名称
		if (!StringUtils.hasText(strategyName)) {
			// Set default
			strategyName = MODE_THREADLOCAL;
		}

		// 2.
		if (strategyName.equals(MODE_THREADLOCAL)) {
			strategy = new ThreadLocalSecurityContextHolderStrategy();
		} else if (strategyName.equals(MODE_INHERITABLETHREADLOCAL)) {
			strategy = new InheritableThreadLocalSecurityContextHolderStrategy();
		} else if (strategyName.equals(MODE_GLOBAL)) {
			strategy = new GlobalSecurityContextHolderStrategy();
		} else {
			// 尝试加载一个自定义的策略类
			try {
				Class<?> clazz = Class.forName(strategyName);
				Constructor<?> customStrategy = clazz.getConstructor();
				strategy = (SecurityContextHolderStrategy) customStrategy.newInstance();
			} catch (Exception ex) {
				ReflectionUtils.handleReflectionException(ex);
			}
		}

		initializeCount++;
	}

	/**
	 * 将新的SecurityContext与当前执行线程相关联
	 * @param context 新的<code>SecurityContext</code> (不应该为<code>null</code>)
	 */
	public static void setContext(SecurityContext context) {
		strategy.setContext(context);
	}

	/**
	 * 更改首选策略。 不要为给定的JVM多次调用此方法，因为它将重新初始化策略并对使用旧策略的任何现有线程产生负面影响。
	 * @param strategyName 应使用的策略的完全限定类名。
	 */
	public static void setStrategyName(String strategyName) {
		// 1.设置策略名称
		SecurityContextHolder.strategyName = strategyName;

		// 2.初始化
		initialize();
	}

	/**
	 * 取回上下文策略
	 * @return 用于存储安全上下文的已配置策略。
	 */
	public static SecurityContextHolderStrategy getContextHolderStrategy() {
		return strategy;
	}

	/**
	 * 将创建新的空context委派给配置的策略。
	 */
	public static SecurityContext createEmptyContext() {
		return strategy.createEmptyContext();
	}

	@Override
	public String toString() {
		return "SecurityContextHolder[strategy='" + strategyName + "'; initializeCount="
				+ initializeCount + "]";
	}
}
